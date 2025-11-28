#ifndef FORK_HANDLER_H
#define FORK_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// --- Configuration ---

// Max payload size (1MB). 
// Prevents a compromised child from causing OOM in the parent.
#define MAX_IPC_PAYLOAD (1024 * 1024)

// Timeout for each handler in milliseconds.
#define HANDLER_TIMEOUT_MS 2000 

// Grace period after SIGTERM before sending SIGKILL (ms).
#define TERM_GRACE_PERIOD_MS 200

// --- Data Structures ---

// Result container for the child logic.
// The child MUST allocate 'str'. The framework will free it.
typedef struct {
    char* str;
} handler_result_t;

// Function pointer prototype.
// Returns 0 on success, non-zero on failure.
typedef int (*handler_func_t)(handler_result_t* result);

// The definition of a single component/handler.
typedef struct {
    const char* name;
    const char* selinux_context; 
    bool is_critical;           // If true, failure stops the entire sequence immediately.
    handler_func_t func;
} handler_def_t;

// Structure for the final report log.
typedef struct {
    const char* handler_name;
    bool success;               // True if exited 0 AND sent valid data
    bool timed_out;             // True if execution exceeded HANDLER_TIMEOUT_MS
    int status_code;            // Exit code (WEXITSTATUS) or internal error code (-1 if did not run)
    char* output_str;           // The response string (caller must free)
} handler_report_t;

// Internal Structure for serialization (Packed for architecture safety).
typedef struct {
    uint32_t length;
    int32_t status_code;
} __attribute__((packed)) ipc_header_t;

/**
 * Executes a sequence of handlers in isolated processes.
 * Handles forking, SELinux transitions, timeouts, and result aggregation.
 * @param handlers Array of handler definitions.
 * @param count Number of handlers.
 */
void execute_handler_sequence(const handler_def_t* handlers, size_t count);

#endif // FORK_HANDLER_H
