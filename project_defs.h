#ifndef PROJECT_DEFS_H
#define PROJECT_DEFS_H

/* Standard system headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <ncurses.h>
#include <dirent.h>
#include <limits.h>

/* OpenSSL headers */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/types.h>

/* --- CONSTANTS AND GLOBAL STRUCTURES --- */

#define MAX_THREADS 16
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define HMAC_SIZE 32
#define IV_FILE_NAME ".iv_data"
#define HMAC_FILE_NAME ".hmac_data"
#define MAX_INPUT_LEN 256
#define MAX_FILES 500
#define DISPLAY_HEIGHT 20

#endif /* PROJECT_DEFS_H */
