#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "fork_handler.h"

// --- Handlers ---

int handle_calculator(handler_result_t* res) {
    res->str = strdup("42");
    return 0;
}

// Simulates a stuck process (infinite loop/sleep)
int handle_stuck_process(handler_result_t* res) {
    // Sleep longer than HANDLER_TIMEOUT_MS (2000ms)
    // In a real bug, this might be while(1);
    sleep(5); 
    res->str = strdup("I should not be seen");
    return 0;
}

// Simulates a crash
int handle_crash(handler_result_t* res) {
    // Dereferencing NULL to cause SIGSEGV
    volatile int* p = NULL;
    *p = 1; 
    return 0;
}

int handle_network(handler_result_t* res) {
    res->str = strdup("Connected");
    return 0;
}

// --- Handler Definitions ---

/* Scenario A:
   1. Calc (OK)
   2. Stuck (Timeout) -> Non-Critical, so we continue to next
   3. Network (OK)
*/
const handler_def_t SCENARIO_A[] = {
    { "Calc", "u:r:untrusted_app:s0", true, handle_calculator },
    { "StuckWorker", "u:r:shell:s0", false, handle_stuck_process }, // Non-critical timeout
    { "Network", "u:r:shell:s0", true, handle_network }
};

/* Scenario B:
   1. Calc (OK)
   2. CriticalStuck (Timeout) -> Critical, should abort entire flow
   3. Network (Should NOT run)
*/
const handler_def_t SCENARIO_B[] = {
    { "Calc", "u:r:untrusted_app:s0", true, handle_calculator },
    { "CriticalStuck", "u:r:shell:s0", true, handle_stuck_process }, // Critical timeout
    { "Network", "u:r:shell:s0", true, handle_network }
};

int main(int argc, char** argv) {
    // Unbuffer stdout/stderr for immediate logging in IDE/Terminal
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("\n--- TEST CASE A: Non-Critical Timeout ---\n");
    execute_handler_sequence(SCENARIO_A, sizeof(SCENARIO_A) / sizeof(handler_def_t));

    printf("\n--- TEST CASE B: Critical Timeout ---\n");
    execute_handler_sequence(SCENARIO_B, sizeof(SCENARIO_B) / sizeof(handler_def_t));

    return 0;
}
