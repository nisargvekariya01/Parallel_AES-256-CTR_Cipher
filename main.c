#include "project_defs.h"
#include "tui.h"
#include "encryption_decryption.h"

int main(int argc, char *argv[]) { // main()
    TUIState state = {0}; // User Input
    strncpy(state.mode, "encrypt", 9); // Default Mode
    state.threads = 4; // Default Threads
    state.current_field = 0;

    if(run_tui(&state) != 0) { // UI for selecting Mode, Input File,...
        printf("\nOperation cancelled by user.\n\n");
        return 0;
    }

    if(access(state.input_file, R_OK) != 0) { // Is  input file readable?
        fprintf(stderr, "ERROR: Cannot read input file: %s\n", state.input_file);
        return 1;
    }
    if(strlen(state.output_file) == 0) { // Is output path provided?
        fprintf(stderr, "ERROR: Output file path is required.\n");
        return 1;
    }
    if(strlen(state.key) == 0) { // Is key provided?
        fprintf(stderr, "ERROR: Encryption key is required.\n");
        return 1;
    }

    int result;
    if(strcmp(state.mode, "encrypt") == 0) { // Encryption
        result = parallel_encrypt(state.input_file, state.output_file, state.key, state.threads);
    } else if(strcmp(state.mode, "decrypt") == 0) { // Decryption
        result = parallel_decrypt(state.input_file, state.output_file, state.key, state.threads);
    } else {
        fprintf(stderr, "ERROR: Invalid mode '%s'.\n", state.mode);
        return 1;
    }

    if(result == 0) {
        printf("Operation completed successfully!\n\n");
    } else {
        printf("\nOperation failed! Please check the error messages above.\n\n");
    }

    return result;
}
