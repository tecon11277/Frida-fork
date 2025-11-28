#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <signal.h>
#include <time.h>

#include "fork_handler.h"

#define LOG_TAG "ForkHandler"
// In Android, map these to __android_log_print if needed
#define LOGE(fmt, ...) fprintf(stderr, "[" LOG_TAG "] E: " fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stdout, "[" LOG_TAG "] I: " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stdout, "[" LOG_TAG "] W: " fmt "\n", ##__VA_ARGS__)

// --- I/O Helper Functions ---

static int write_all(int fd, const void* buf, size_t count) {
    size_t bytes_written = 0;
    const uint8_t* ptr = (const uint8_t*)buf;
    while (bytes_written < count) {
        ssize_t res = write(fd, ptr + bytes_written, count - bytes_written);
        if (res < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        bytes_written += res;
    }
    return 0;
}

static int read_all(int fd, void* buf, size_t count) {
    size_t bytes_read = 0;
    uint8_t* ptr = (uint8_t*)buf;
    while (bytes_read < count) {
        ssize_t res = read(fd, ptr + bytes_read, count - bytes_read);
        if (res <= 0) {
            if (res < 0 && errno == EINTR) continue;
            return -1; // Error or Unexpected EOF
        }
        bytes_read += res;
    }
    return 0;
}

static void safe_usleep(long usec) {
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

// --- SELinux Security Logic ---

static int check_fd_access(const char* target_con, int fd) {
    if (is_selinux_enabled() <= 0) return 0; // Bypass if SELinux disabled
    
    char *parent_con = NULL, *pipe_con = NULL;
    int ret = -1;

    // Get current context and pipe file context
    if (getcon(&parent_con) < 0) goto cleanup;
    if (fgetfilecon(fd, &pipe_con) < 0) goto cleanup;

    // Check 1: Can target_con use FDs owned by parent_con?
    if (selinux_check_access(target_con, parent_con, "fd", "use", NULL) < 0) {
        LOGE("SELinux Denial: Context '%s' cannot use FDs of '%s'", target_con, parent_con);
        goto cleanup;
    }

    // Check 2: Can target_con write to the specific pipe?
    if (selinux_check_access(target_con, pipe_con, "fifo_file", "write", NULL) < 0) {
        LOGE("SELinux Denial: Context '%s' cannot write to pipe '%s'", target_con, pipe_con);
        goto cleanup;
    }

    ret = 0; // Allowed
cleanup:
    freecon(parent_con); 
    freecon(pipe_con);
    return ret;
}

static int verify_current_context(const char* expected_con) {
    if (is_selinux_enabled() <= 0) return 0;
    
    char *curr = NULL;
    if (getcon(&curr) < 0) return -1;
    
    int match = (strcmp(curr, expected_con) == 0);
    if (!match) LOGE("Context Mismatch! Expected: %s, Actual: %s", expected_con, curr);
    
    freecon(curr);
    return match ? 0 : -1;
}

// --- Child Process Logic ---

static void run_child_logic(const handler_def_t* handler, int write_fd) {
    // 1. Security Pre-flight
    if (check_fd_access(handler->selinux_context, write_fd) < 0) {
        _exit(101); // Permission Denied
    }
    
    // 2. SELinux Transition
    if (is_selinux_enabled() > 0) {
        if (setcon(handler->selinux_context) < 0) {
            LOGE("Child setcon to '%s' failed: %s", handler->selinux_context, strerror(errno));
            _exit(102); // Transition Error
        }
    }
    
    // 3. Verify we are effectively in the new context
    if (verify_current_context(handler->selinux_context) < 0) {
        _exit(103); // Verification Error
    }

    // 4. Run Payload
    handler_result_t result = { .str = NULL };
    int ret = handler->func(&result);

    // 5. Serialize
    ipc_header_t header;
    header.status_code = ret;
    header.length = (result.str != NULL) ? (uint32_t)strlen(result.str) : 0;

    // 6. Safety Check
    if (header.length > MAX_IPC_PAYLOAD) {
        LOGE("Child payload too large (%u). Aborting.", header.length);
        if (result.str) free(result.str);
        _exit(105); // Payload too large
    }

    // 7. Write Data
    if (write_all(write_fd, &header, sizeof(header)) < 0) {
        if (result.str) free(result.str);
        _exit(104); // IO Error
    }
    
    if (header.length > 0) {
        if (write_all(write_fd, result.str, header.length) < 0) {
             if (result.str) free(result.str);
            _exit(104); // IO Error
        }
    }

    if (result.str) free(result.str);
    close(write_fd);
    _exit(0); // Success
}

// --- Parent Process Logic ---

/**
 * Attempts to kill a child process gracefully (SIGTERM), waits a bit, then forces it (SIGKILL).
 * Ensures the zombie is reaped via waitpid.
 */
static void terminate_child(pid_t pid, const char* name) {
    LOGW("Timing out handler '%s'. Sending SIGTERM...", name);
    kill(pid, SIGTERM);

    // Poll for exit for TERM_GRACE_PERIOD_MS
    int status;
    int loop_cnt = TERM_GRACE_PERIOD_MS / 10; 
    
    for (int i = 0; i < loop_cnt; i++) {
        safe_usleep(10000); // 10ms
        // WNOHANG returns 0 if running, >0 if exited, -1 on error
        if (waitpid(pid, &status, WNOHANG) > 0) {
            LOGI("Handler '%s' exited gracefully.", name);
            return;
        }
    }

    LOGE("Handler '%s' stuck. Sending SIGKILL.", name);
    kill(pid, SIGKILL);
    // Blocking wait to ensure zombie cleanup
    waitpid(pid, &status, 0); 
}

static void process_parent_logic(const handler_def_t* handler, pid_t child_pid, int read_fd, handler_report_t* report) {
    ipc_header_t header = {0};
    report->handler_name = handler->name;
    report->success = false;
    report->timed_out = false;
    report->output_str = NULL;
    report->status_code = -1; // Default to "unknown/running"

    struct pollfd pfd = { .fd = read_fd, .events = POLLIN };
    int poll_ret;
    
    // 1. Wait for Data (with retry on EINTR)
    while (1) {
        poll_ret = poll(&pfd, 1, HANDLER_TIMEOUT_MS);
        if (poll_ret < 0 && errno == EINTR) {
            continue; // Signal interrupted poll, retry
        }
        break;
    }

    if (poll_ret == 0) {
        // --- TIMEOUT ---
        report->timed_out = true;
        terminate_child(child_pid, handler->name);
        close(read_fd);
        return; 
    } 
    else if (poll_ret < 0) {
        // --- POLL ERROR ---
        LOGE("Poll failed for '%s': %s", handler->name, strerror(errno));
        terminate_child(child_pid, handler->name); // Ensure child is dead
        close(read_fd);
        return;
    }

    // 2. Data Ready - Read Header
    if (read_all(read_fd, &header, sizeof(header)) == 0) {
        if (header.length > MAX_IPC_PAYLOAD) {
            LOGE("Payload too large from '%s'", handler->name);
            // We read valid header but invalid size. 
            // Child might still be running or exiting. We let waitpid handle the rest.
        } else {
            report->status_code = header.status_code;
            
            // 3. Read Body
            if (header.length > 0) {
                // +1 for null terminator
                char* buf = malloc(header.length + 1);
                if (buf) {
                    if (read_all(read_fd, buf, header.length) == 0) {
                        buf[header.length] = '\0';
                        report->output_str = buf;
                        report->success = true;
                    } else {
                        free(buf);
                        LOGE("Failed to read body from '%s'", handler->name);
                    }
                } else {
                    LOGE("OOM allocating buffer for '%s'", handler->name);
                }
            } else {
                // Empty string is a valid success
                report->success = true;
            }
        }
    } else {
        LOGE("Failed to read header from '%s' (Pipe closed?)", handler->name);
    }
    
    close(read_fd);

    // 4. Reap Child
    int status;
    if (waitpid(child_pid, &status, 0) < 0) {
        LOGE("waitpid failed for '%s'", handler->name);
    } else {
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            report->success = false;
            // If we didn't get a status code from pipe (e.g. crash), take it from exit status
            if (report->status_code == -1 && WIFEXITED(status)) {
                report->status_code = WEXITSTATUS(status);
            }
        }
    }
}

// --- Main Execution Loop ---

void execute_handler_sequence(const handler_def_t* handlers, size_t count) {
    handler_report_t* reports = calloc(count, sizeof(handler_report_t));
    if (!reports) {
        LOGE("FATAL: OOM allocating reports.");
        return;
    }

    size_t executed_count = 0;
    bool critical_failure = false;

    for (size_t i = 0; i < count; i++) {
        const handler_def_t* h = &handlers[i];
        
        // Initialize status code to -1 to indicate "not run" or "crash" until proven otherwise
        reports[i].status_code = -1;
        executed_count++;

        LOGI(">>> Executing: %s [Critical: %s]", h->name, h->is_critical ? "YES" : "NO");

        int pipefd[2];
        if (pipe(pipefd) < 0) {
            LOGE("Pipe creation failed: %s", strerror(errno));
            if (h->is_critical) { critical_failure = true; break; }
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            LOGE("Fork failed: %s", strerror(errno));
            close(pipefd[0]); close(pipefd[1]);
            if (h->is_critical) { critical_failure = true; break; }
            continue;
        }

        if (pid == 0) {
            // Child: Writes to pipefd[1]
            close(pipefd[0]);
            run_child_logic(h, pipefd[1]);
            // run_child_logic calls _exit, never returns
        } else {
            // Parent: Reads from pipefd[0]
            close(pipefd[1]);
            process_parent_logic(h, pid, pipefd[0], &reports[i]);
            
            // Check Results
            if (!reports[i].success) {
                if (reports[i].timed_out) LOGE("Handler '%s' TIMED OUT.", h->name);
                else LOGE("Handler '%s' FAILED.", h->name);

                if (h->is_critical) {
                    LOGE("!!! CRITICAL FAILURE. Aborting sequence. !!!");
                    critical_failure = true;
                    break;
                }
            }
        }
    }

    // --- Final Reporting ---
    LOGI("================ REPORT ================");
    for (size_t i = 0; i < executed_count; i++) {
        const handler_report_t* r = &reports[i];
        if (r->timed_out) {
             LOGI("[%s]: TIMEOUT", r->handler_name);
        } else if (r->success) {
             LOGI("[%s]: SUCCESS | Data: \"%s\"", r->handler_name, r->output_str ? r->output_str : "");
        } else {
             LOGI("[%s]: FAILED (Exit/Status: %d)", r->handler_name, r->status_code);
        }
    }
    
    if (critical_failure) LOGE("Sequence ABORTED due to Critical Failure.");
    else LOGI("Sequence COMPLETED.");
    LOGI("========================================");

    // Cleanup
    for (size_t i = 0; i < executed_count; i++) {
        if (reports[i].output_str) free(reports[i].output_str);
    }
    free(reports);
}
