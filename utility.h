#ifndef UTILITY_H
#define UTILITY_H

#include "project_defs.h"

/* Header-only implementations: marked static inline so they can live in a header
   without causing multiple-definition linker errors when included from multiple
   translation units. Because you are compiling only main.c, static would also
   work; static inline is a good portable choice. */

static inline off_t get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) < 0) {
        return -1;
    }
    return st.st_size;
}

static inline long long get_time_microseconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
}

static inline void safe_path_join(char *dest, size_t dest_size, const char *base, const char *name) {
    if (dest_size == 0) return;
    dest[0] = '\0';

    if (!base || !name) {
        dest[0] = '\0';
        return;
    }

    /* Special-case root base "/" */
    if (base[0] == '/' && base[1] == '\0') {
        strncat(dest, "/", dest_size - strlen(dest) - 1);
        if (name[0] == '/') {
            strncat(dest, name + 1, dest_size - strlen(dest) - 1);
        } else {
            strncat(dest, name, dest_size - strlen(dest) - 1);
        }
        dest[dest_size - 1] = '\0';
        return;
    }

    /* copy base (truncated if needed) */
    size_t base_len = strnlen(base, dest_size - 1);
    if (base_len > 0) {
        memcpy(dest, base, base_len);
        dest[base_len] = '\0';
    } else {
        dest[0] = '\0';
    }

    /* if base has trailing slash, remove it */
    if (base_len > 0 && dest[base_len - 1] == '/') {
        dest[base_len - 1] = '\0';
    }

    /* add single slash if there's room */
    if (strlen(dest) < dest_size - 1) {
        strncat(dest, "/", dest_size - strlen(dest) - 1);
    }

    /* append name (skip leading slash if present) */
    if (name[0] == '/') {
        strncat(dest, name + 1, dest_size - strlen(dest) - 1);
    } else {
        strncat(dest, name, dest_size - strlen(dest) - 1);
    }

    dest[dest_size - 1] = '\0';
}

#endif /* UTILITY_H */
