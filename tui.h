#ifndef TUI_H
#define TUI_H

#include "project_defs.h"
#include "utility.h"

// TUI State structure
typedef struct {
    char mode[10];
    char input_file[PATH_MAX];
    char output_file[PATH_MAX];
    char key[MAX_INPUT_LEN];
    int threads;
    int current_field;
} TUIState;

// File Selector State
typedef struct {
    char current_path[PATH_MAX];
    char file_list[MAX_FILES][MAX_INPUT_LEN];
    int file_count;
    int cursor_pos;
    int scroll_offset;
} FileSelectorState;


void init_tui() {
    initscr(); // Takes control of the terminal and prepares it for drawing windows, text, colors,...
    cbreak(); // Every key is sent immediately, so getch() gets keys instantly
    noecho();
    keypad(stdscr, TRUE); // Enables special keys (arrows, function keys, backspace, delete,...)
    curs_set(1); // Makes the cursor visible
    start_color(); // Activates color functionality in ncurses
    init_pair(1, COLOR_YELLOW, COLOR_BLACK);
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
    init_pair(3, COLOR_CYAN, COLOR_BLACK);
    init_pair(4, COLOR_WHITE, COLOR_BLACK);
}

void draw_main_screen(const TUIState *state) {
    clear(); // Clears the entire ncurses screen

    attron(A_BOLD); // Enable bold text
    mvprintw(1, 2, "AES-256-CTR Parallel Cipher Setup (TUI)"); // move cursor to row 1, column 2, print the title
    attroff(A_BOLD); // Turn bold off

    // At row 3, column 2, print a guide for how to use the TUI
    mvprintw(3, 2, "Use UP/DOWN. ENTER to edit/select file. Backspace/CTRL+D to submit.");

    // Stores the labels of the 5 fields
    const char *fields[] = {"Mode (encrypt/decrypt)", "Input File Path", "Output File Path", "Encryption Key", "Threads (1-16)"};
    char output_buffer[PATH_MAX + 30]; // Hold the textual value of each field before printing

    for(int i = 0; i < 5; i++) {
        attrset(COLOR_PAIR(1));
        if(i == state->current_field) {
            attron(A_REVERSE); // Set highlight
        }

        mvprintw(5 + i * 2, 2, "%s:", fields[i]);

        attroff(A_REVERSE); // Removes highlight
        attrset(COLOR_PAIR(2));

        switch(i) {
            case 0:
                snprintf(output_buffer, sizeof(output_buffer), "%s", state->mode); // Copy state->mode into output_buffer
                break;
            case 1:
                snprintf(output_buffer, sizeof(output_buffer), "%.*s", MAX_INPUT_LEN - 1, state->input_file);
                break;
            case 2:
                snprintf(output_buffer, sizeof(output_buffer), "%.*s", MAX_INPUT_LEN - 1, state->output_file);
                break;
            case 3:
                if(strlen(state->key) > 0) { 
                    memset(output_buffer, '*', sizeof(output_buffer));
                    output_buffer[strlen(state->key)] = '\0';
                } else {
                    output_buffer[0] = '\0';
                }
                break;
            case 4:
                snprintf(output_buffer, sizeof(output_buffer), "%d", state->threads);
                break;
        }
        mvprintw(5 + i * 2, 35, "%s", output_buffer);
    }
    attrset(A_NORMAL); // Reset to normal text attributes
    refresh(); // Push all changes to the terminal display
}

int read_directory(FileSelectorState *fstate) {
    DIR *d; // Directory stream pointer
    struct dirent *dir; // Holds each entry read from directory
    struct stat st;
    char full_path[PATH_MAX];

    d = opendir(fstate->current_path);
    if(!d) {
        return 0;
    }

    fstate->file_count = 0;
    if(strcmp(fstate->current_path, "/") != 0) {
        strncpy(fstate->file_list[fstate->file_count++], "..", MAX_INPUT_LEN);
    }

    while((dir = readdir(d)) != NULL) { // Loop over directory entries
        if(strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
            continue;
        }

        // Use safe_path_join to build full_path
        safe_path_join(full_path, PATH_MAX, fstate->current_path, dir->d_name);

        if(lstat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // store directories with leading '/' for UI identification (like your original)
            snprintf(fstate->file_list[fstate->file_count], MAX_INPUT_LEN, "/%.*s", MAX_INPUT_LEN - 2, dir->d_name);
            fstate->file_count++;
        } else if(lstat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            // Regular File
            strncpy(fstate->file_list[fstate->file_count], dir->d_name, MAX_INPUT_LEN - 1);
            fstate->file_list[fstate->file_count][MAX_INPUT_LEN - 1] = '\0';
            fstate->file_count++;
        }
        if(fstate->file_count >= MAX_FILES) {
            break;
        }
    }

    closedir(d);
    fstate->cursor_pos = 0;
    fstate->scroll_offset = 0;
    return fstate->file_count;
}

void draw_file_list(const FileSelectorState *fstate, const char *prompt) {
    clear();
    mvprintw(1, 2, "Path: %s", fstate->current_path);
    mvprintw(3, 2, "%s", prompt);

    int y = 5;
    for(int i = 0; i < DISPLAY_HEIGHT && (i + fstate->scroll_offset) < fstate->file_count; i++) {
        int list_index = i + fstate->scroll_offset;
        const char *filename = fstate->file_list[list_index];

        if(list_index == fstate->cursor_pos) {
            attron(A_REVERSE | A_BOLD);
        }

        if(filename[0] == '/') {
            attron(COLOR_PAIR(3));
        } else {
            attron(COLOR_PAIR(4));
        }

        mvprintw(y + i, 2, " %-*s ", 40, filename[0] == '/' ? filename + 1 : filename);

        attroff(A_REVERSE | A_BOLD);
        attrset(A_NORMAL);
    }
    mvprintw(LINES - 2, 2, "UP/DOWN/ENTER to navigate. ESC to return to main menu."); refresh();
}

int run_file_selector(char *selected_path, const char *prompt) {
    FileSelectorState fstate; // Holds current directory, file list, cursor position, scroll offset file count
    int ch; // Stores keyboard input

    if(getcwd(fstate.current_path, PATH_MAX) == NULL) {
        strncpy(fstate.current_path, "/", PATH_MAX);
    }
    if(!read_directory(&fstate)) { // Reads folder entries
        return 1;
    }

    while(1) { // Selects a file or cancels
        draw_file_list(&fstate, prompt);
        ch = getch();

        switch(ch) {
            case KEY_UP:
                fstate.cursor_pos = (fstate.cursor_pos > 0) ? fstate.cursor_pos - 1 : 0;
                if(fstate.cursor_pos < fstate.scroll_offset) {
                    fstate.scroll_offset--;
                }
                break;

            case KEY_DOWN:
                fstate.cursor_pos = (fstate.cursor_pos < fstate.file_count - 1) ? fstate.cursor_pos + 1 : fstate.file_count - 1;
                if(fstate.cursor_pos >= fstate.scroll_offset + DISPLAY_HEIGHT) {
                    fstate.scroll_offset++;
                }
                break;

            case 10: case 13: // ENTER
            {
                if(fstate.file_count == 0) {
                    break;
                }

                char *filename = fstate.file_list[fstate.cursor_pos];

                if(strcmp(filename, "..") == 0) {
                    char *last_slash = strrchr(fstate.current_path, '/');
                    if(last_slash && last_slash != fstate.current_path) {
                        *last_slash = '\0';
                    } else if(last_slash) {
                        fstate.current_path[1] = '\0';
                    }
                    read_directory(&fstate);
                } else if(filename[0] == '/') {
                    char new_path[PATH_MAX];

                    safe_path_join(new_path, PATH_MAX, fstate.current_path, filename);

                    if(chdir(new_path) == 0) {
                        strncpy(fstate.current_path, new_path, PATH_MAX);
                        fstate.current_path[PATH_MAX - 1] = '\0';
                        read_directory(&fstate);
                    }
                } else {
                    // File selected
                    safe_path_join(selected_path, PATH_MAX, fstate.current_path, filename);
                    selected_path[PATH_MAX - 1] = '\0';
                    return 0; // Selection successful
                }
                break;
            }

            case 27: // ESC
            return 1;
        }
    }
}

int run_tui(TUIState *state) { // UI for selecting Mode, Input File,...
    int ch;
    init_tui(); // Prepares the terminal for the UI

    while(1) { // UI redraws and reacts to keys until it returns
        draw_main_screen(state); // Redraw the whole TUI screen from current state
        ch = getch(); // Read one keypress from the user

        switch(ch) {
            case KEY_UP: // Up arrow
                state->current_field = (state->current_field - 1 + 5) % 5; 
                break;

            case KEY_DOWN: // Down arrow
                state->current_field = (state->current_field + 1) % 5; 
                break;

            case 10: case 13: // ENTER
            {
                if(state->current_field == 1) {
                    curs_set(0); // Hide the cursor
                    if(run_file_selector(state->input_file, "SELECT INPUT FILE:") == 0) { // Shows a directory listing UI and lets the user pick a file
                        char *base_name = strrchr(state->input_file, '/'); // Extract the basename (file name only)
                        if(base_name) {
                            base_name++;
                        } else {
                            base_name = state->input_file;
                        }

                        size_t max_out = sizeof(state->output_file);
                        state->output_file[0] = '\0';
                        strncat(state->output_file, base_name, max_out - strlen(state->output_file) - 1);
                        strncat(state->output_file, ".enc", max_out - strlen(state->output_file) - 1);
                        state->output_file[max_out - 1] = '\0';
                    }
                    curs_set(1); // Show the cursor
                    break;
                }

                char buffer[MAX_INPUT_LEN]; // Used to read user input
                char *target_field = NULL; // Pointer to the actual field in state
                int max_len = MAX_INPUT_LEN - 1; // Maximum characters to accept by default

                switch(state->current_field) {
                    case 0:
                        target_field = state->mode;
                        break;

                    case 2:
                        target_field = state->output_file;
                        break;
                    
                    case 3:
                        target_field = state->key;
                        break;
                    
                    case 4:
                        target_field = buffer;
                        max_len = 2;
                        break;
                }

                if(target_field) { // If there is a target to edit
                    mvhline(5 + state->current_field * 2, 35, ' ', MAX_INPUT_LEN); // Overwrite the visible input area with spaces
                    move(5 + state->current_field * 2, 35); // Move the cursor to the start column for input

                    echo(); // Enable input
                    getnstr(buffer, max_len); // Read up to max_len characters into buffer
                    noecho(); // Turn echoing off

                    if(state->current_field == 4) {
                        state->threads = atoi(buffer); // Convert numeric string to integer
                        if(state->threads < 1 || state->threads > MAX_THREADS) {
                            state->threads = 4;
                        }
                    } else if(state->current_field == 0) {
                        if(strcmp(buffer, "decrypt") == 0 || strcmp(buffer, "encrypt") == 0) {
                            strncpy(target_field, buffer, max_len);
                        }
                    } else {
                        strncpy(target_field, buffer, max_len);
                        target_field[max_len] = '\0';
                    }
                }

                state->current_field = (state->current_field + 1) % 5; 
                break;
            }

            case 4:  // CTRL + D → SUBMIT
            {
                if(strlen(state->input_file) > 0 && strlen(state->output_file) > 0 && strlen(state->key) > 0) {
                    endwin(); // Restore terminal
                    return 0;  // tell main to start encryption/decryption
                }
                break;
            }

            case 127: // Backspace (used as submit)
            {
                if(strlen(state->input_file) > 0 && strlen(state->output_file) > 0 && strlen(state->key) > 0) {
                    endwin(); // Restore terminal
                    return 0;  // tell main to start encryption/decryption
                }
                break;
            }

            case KEY_F(1): // Cancels the operation
                endwin(); 
                return 1;
        }
    }
}

#endif
