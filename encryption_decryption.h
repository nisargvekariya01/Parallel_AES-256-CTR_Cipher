#ifndef ENCRYPTION_DECRYPTION_H
#define ENCRYPTION_DECRYPTION_H

#include "project_defs.h"
#include "utility.h"

// ThreadData and Statistics
typedef struct {
    int thread_id;
    const char *input_file;
    const char *output_file;
    off_t start_offset;
    off_t chunk_size;
    unsigned char *encryption_key;
    unsigned char *iv_base;
    int input_fd;   // NEW: shared input fd
    int output_fd;  // NEW: shared output fd
    int is_decrypt;
} ThreadData;

typedef struct {
    long long total_bytes_processed;
    int threads_completed;
    pthread_mutex_t stats_lock;
} Statistics;

Statistics global_stats = {0, 0, PTHREAD_MUTEX_INITIALIZER};

int aes_cipher(unsigned char *data, int in_len, unsigned char *out_data, int *out_len, const unsigned char *key, const unsigned char *iv_base, off_t offset) {
    EVP_CIPHER_CTX *ctx; // Declare OpenSSL cipher context pointer
    int len;

    unsigned char local_iv[AES_IV_SIZE];
    memcpy(local_iv, iv_base, AES_IV_SIZE);

    off_t block_index = offset / AES_IV_SIZE; // Convert the byte offset to a block number

    for(int i = 0; i < 8 && i < AES_IV_SIZE; i++) {
        local_iv[AES_IV_SIZE - 1 - i] ^= (unsigned char)((block_index) >> (i*8));
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) { // Allocate a new OpenSSL cipher context
        return -1;
    }

    if(EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, local_iv, 1) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0); // Disable padding

    if(EVP_CipherUpdate(ctx, out_data, &len, data, in_len) != 1) { // Process the input data
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *out_len = len;
    
    if(EVP_CipherFinal_ex(ctx, out_data + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int calculate_hmac(const char *filepath, const unsigned char *key, unsigned char *hmac_result) {
    int input_fd = -1;
    struct stat st;
    size_t buf_size;
    unsigned char *buffer = NULL;
    size_t bytes_read;
    size_t hmac_len = HMAC_SIZE; // Expected HMAC output length

    EVP_MAC *mac = NULL; // Representing the MAC algorithm provider object (HMAC algorithm handle)
    EVP_MAC_CTX *ctx = NULL; // OpenSSL MAC context used to perform the HMAC operations (init/update/final)

    /* determine file size so we can pick a good buffer size */
    input_fd = open(filepath, O_RDONLY);
    if(input_fd < 0) {
        fprintf(stderr, "ERROR: Cannot open file for HMAC calculation: %s\n", filepath);
        return 1;
    }
    if(fstat(input_fd, &st) < 0) {
        fprintf(stderr, "ERROR: fstat failed on %s\n", filepath);
        close(input_fd);
        return 1;
    }

    /* choose buffer size:
       - at least 64 KB,
       - prefer 4 MB (or file size if smaller),
       - cap at 16 MB to avoid huge per-process allocations */
    const size_t MIN_BUF = 64 * 1024;
    const size_t PREFERRED = 4 * 1024 * 1024;
    const size_t MAX_BUF = 16 * 1024 * 1024;
    
    if((off_t)PREFERRED > st.st_size) buf_size = (size_t)st.st_size;
    else buf_size = PREFERRED;

    if(buf_size < MIN_BUF) buf_size = MIN_BUF;
    if(buf_size > MAX_BUF) buf_size = MAX_BUF;
    if(buf_size == 0) buf_size = MIN_BUF; // safety

    buffer = malloc(buf_size);
    if(!buffer) {
        fprintf(stderr, "ERROR: malloc failed for HMAC buffer\n");
        close(input_fd);
        return 1;
    }

    /* Optional: tell kernel we will read sequentially (helps readahead) */
    #if defined(POSIX_FADV_SEQUENTIAL)
    posix_fadvise(input_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    #endif

    /* init HMAC (OpenSSL 3 EVP_MAC style, same as your original) */
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL); // HMAC implementation
    if(!mac) {
        fprintf(stderr, "ERROR: EVP_MAC_fetch failed to get HMAC algorithm.\n");
        free(buffer);
        close(input_fd);
        return 1;
    }
    ctx = EVP_MAC_CTX_new(mac); // Allocates a MAC context bound to mac
    if(!ctx) {
        fprintf(stderr, "ERROR: EVP_MAC_CTX_new failed.\n");
        EVP_MAC_free(mac);
        free(buffer);
        close(input_fd);
        return 1;
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), // We want HMAC using SHA-256 as the underlying digest
        OSSL_PARAM_construct_end()
    };
    if(EVP_MAC_init(ctx, key, AES_KEY_SIZE, params) != 1) {
        fprintf(stderr, "ERROR: EVP_MAC_init failed (key or param issue).\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(buffer);
        close(input_fd);
        return 1;
    }
    
    /* read loop with larger buffer */
    while((bytes_read = read(input_fd, buffer, buf_size)) > 0) {
        if(EVP_MAC_update(ctx, buffer, bytes_read) != 1) {
            fprintf(stderr, "ERROR: EVP_MAC_update failed.\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            free(buffer);
            close(input_fd);
            return 1;
        }
    }
    if(bytes_read == (size_t)-1 || bytes_read == (size_t) -1) {
        // read returned -1 as ssize_t; convert check
        if(errno) {
            fprintf(stderr, "ERROR: Read error during HMAC calculation: %s\n", strerror(errno));
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            free(buffer);
            close(input_fd);
            return 1;
        }
    }
    
    /* finalize */
    if(EVP_MAC_final(ctx, hmac_result, &hmac_len, HMAC_SIZE) != 1) {
        fprintf(stderr, "ERROR: EVP_MAC_final failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(buffer);
        close(input_fd);
        return 1;
    }

    if(hmac_len != HMAC_SIZE) {
        fprintf(stderr, "ERROR: Final HMAC length mismatch. Expected %d, got %zu.\n", HMAC_SIZE, hmac_len);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(buffer);
        close(input_fd);
        return 1;
    }

    /* cleanup */
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    free(buffer);
    close(input_fd);
    return 0;
}

int write_iv_to_file(const unsigned char *iv_base) {
    int iv_fd = open(IV_FILE_NAME, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(iv_fd < 0) {
        return 1;
    }
    if(write(iv_fd, iv_base, AES_IV_SIZE) != AES_IV_SIZE) {
        close(iv_fd);
        return 1;
    }
    close(iv_fd);
    return 0;
}

int read_iv_from_file(unsigned char *iv_base) {
    int iv_fd = open(IV_FILE_NAME, O_RDONLY);
    if(iv_fd < 0) {
        fprintf(stderr, "ERROR: Cannot open IV file (%s)! Error: %s\n", IV_FILE_NAME, strerror(errno));
        return 1;
    }
    if(read(iv_fd, iv_base, AES_IV_SIZE) != AES_IV_SIZE) {
        fprintf(stderr, "ERROR: Failed to read IV from file!\n");
        close(iv_fd);
        return 1;
    }
    close(iv_fd);
    return 0;
}

int read_hmac_from_file(unsigned char *hmac_tag) {
    int hmac_fd = open(HMAC_FILE_NAME, O_RDONLY);
    if(hmac_fd < 0) {
        fprintf(stderr, "ERROR: Cannot open HMAC file (%s)! Error: %s\n", HMAC_FILE_NAME, strerror(errno));
        return 1;
    }
    if(read(hmac_fd, hmac_tag, HMAC_SIZE) != HMAC_SIZE) {
        fprintf(stderr, "ERROR: Failed to read HMAC tag from file!\n");
        close(hmac_fd);
        return 1;
    }
    close(hmac_fd);
    return 0;
}

int write_hmac_to_file(const unsigned char *hmac_tag) {
    int hmac_fd = open(HMAC_FILE_NAME, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(hmac_fd < 0) {
        return 1;
    }
    if(write(hmac_fd, hmac_tag, HMAC_SIZE) != HMAC_SIZE) {
        close(hmac_fd);
        return 1;
    }
    close(hmac_fd);
    return 0;
}

void *cipher_chunk(void *param) {
    ThreadData *td = (ThreadData *)param;
    unsigned char *buffer = NULL;
    unsigned char *output_buffer = NULL;
    ssize_t bytes_read = 0;
    int output_len = 0;

    // allocate per-thread buffers to chunk_size
    buffer = (unsigned char *)malloc((size_t)td->chunk_size);
    output_buffer = (unsigned char *)malloc((size_t)td->chunk_size);
    if (!buffer || !output_buffer) {
        free(buffer); free(output_buffer);
        pthread_exit(NULL);
    }

    // read using pread so we don't need lseek or per-thread fd state
    off_t remaining = td->chunk_size;
    off_t offset = td->start_offset;
    unsigned char *bufptr = buffer;
    while (remaining > 0) {
        ssize_t r = pread(td->input_fd, bufptr, (size_t)remaining, offset);
        if (r < 0) {
            // read error
            free(buffer); free(output_buffer);
            pthread_exit(NULL);
        } else if (r == 0) {
            // EOF
            break;
          }
        remaining -= r;
        offset += r;
        bufptr += r;
    }
    bytes_read = (ssize_t)(td->chunk_size - remaining);
    if (bytes_read <= 0) { free(buffer); free(output_buffer); pthread_exit(NULL); }

    // encrypt/decrypt the chunk
    if (aes_cipher(buffer, (int)bytes_read, output_buffer, &output_len, td->encryption_key, td->iv_base, td->start_offset) != 0) {
        free(buffer); free(output_buffer); pthread_exit(NULL);
    }

    // write using pwrite in a loop to ensure entire buffer is written
    off_t write_offset = td->start_offset;
    unsigned char *wptr = output_buffer;
    ssize_t to_write = output_len;
            
            while (to_write > 0) {
        ssize_t w = pwrite(td->output_fd, wptr, (size_t)to_write, write_offset);
        if (w < 0) {
            // write error
            free(buffer); free(output_buffer);
            pthread_exit(NULL);
        }
        to_write -= w;
        write_offset += w;
        wptr += w;
    }

    // update stats atomically
    pthread_mutex_lock(&global_stats.stats_lock);
    global_stats.total_bytes_processed += output_len;
    global_stats.threads_completed++;
    pthread_mutex_unlock(&global_stats.stats_lock);

    free(buffer); free(output_buffer);
    pthread_exit(NULL);
}

int parallel_cipher(const char *input_file, const char *output_file, const char *key, int num_threads, int is_decrypt) {
    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv_base[AES_IV_SIZE];
    unsigned char stored_hmac[HMAC_SIZE];
    unsigned char calculated_hmac[HMAC_SIZE];
    off_t file_size;
    off_t chunk_size, remainder;
    long long start_time;
    double time_taken;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    pthread_mutex_init(&global_stats.stats_lock, NULL);
    global_stats.total_bytes_processed = 0;
    global_stats.threads_completed = 0;

    if (PKCS5_PBKDF2_HMAC(key, (int)strlen(key), NULL, 0, 10000, EVP_sha256(), AES_KEY_SIZE, aes_key) != 1) {
        fprintf(stderr, "ERROR: Failed to derive encryption key.\n");
        return 1;
    }
    
    if (is_decrypt) {
        if (read_iv_from_file(iv_base) != 0) return 1;
        if (read_hmac_from_file(stored_hmac) != 0) return 1;
    } else {
        if (RAND_bytes(iv_base, AES_IV_SIZE) != 1) { fprintf(stderr, "ERROR: Failed to generate random IV!\n"); return 1;}
        if (write_iv_to_file(iv_base) != 0) return 1;
    }

    file_size = get_file_size(input_file);
    if (file_size < 0) { fprintf(stderr, "ERROR: Cannot access input file: %s\n", input_file); return 1; }

    printf("\n========================================\nPARALLEL AES-256-CTR CIPHER\n========================================\n");
    printf("Mode: %s | File Size: %.2f MB | Threads: %d\n\n", is_decrypt ? "DECRYPT" : "ENCRYPT", file_size / (1024.0 * 1024.0), num_threads);

    // Open input and output once
    int input_fd = open(input_file, O_RDONLY);
    if (input_fd < 0) { fprintf(stderr, "ERROR: Cannot open input file: %s\n", strerror(errno)); return 1; }

    int out_fd = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) { close(input_fd); fprintf(stderr, "ERROR: Cannot create output file! Error: %s\n", strerror(errno)); return 1; }

    // Allocate output file size up front to avoid growth races
    if (ftruncate(out_fd, file_size) != 0) {
        // not fatal but warn
        fprintf(stderr, "WARNING: ftruncate failed: %s\n", strerror(errno));
    }

    chunk_size = file_size / num_threads;
    remainder = file_size % num_threads;

    start_time = get_time_microseconds();

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].input_file = input_file;
        thread_data[i].output_file = output_file;
        thread_data[i].start_offset = (off_t)i * chunk_size;
        thread_data[i].encryption_key = aes_key;
        thread_data[i].iv_base = iv_base;
        thread_data[i].input_fd = input_fd;   // shared fd
        thread_data[i].output_fd = out_fd;    // shared fd
        thread_data[i].is_decrypt = is_decrypt;
        thread_data[i].chunk_size = (i == num_threads - 1) ? (chunk_size + remainder) : chunk_size;

        if (pthread_create(&threads[i], NULL, cipher_chunk, &thread_data[i]) != 0) {
            fprintf(stderr, "ERROR: Failed to create thread %d\n", i);
            close(input_fd); close(out_fd);
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    time_taken = (get_time_microseconds() - start_time) / 1000000.0;
    
    // close fds after threads done
    close(input_fd);
    close(out_fd);

    // HMAC handling unchanged
    if (is_decrypt) {
        if (calculate_hmac(input_file, aes_key, calculated_hmac) != 0) { fprintf(stderr, "CRITICAL ERROR: Failed to calculate HMAC for verification.\n"); return 1; }
        if (memcmp(calculated_hmac, stored_hmac, HMAC_SIZE) != 0) {
            fprintf(stderr, "\n██ CRITICAL FAILURE: KEY MISMATCH OR DATA TAMPERING! ██\n");
            unlink(output_file);
            fprintf(stderr, "Decryption halted. Corrupted output file '%s' deleted.\n", output_file);
            return 1;
        }
    } else {
        if (calculate_hmac(output_file, aes_key, calculated_hmac) != 0) { fprintf(stderr, "CRITICAL ERROR: Failed to generate HMAC for ciphertext.\n"); return 1; }
        if (write_hmac_to_file(calculated_hmac) != 0) return 1;
    }

    printf("\nCIPHER OPERATION COMPLETE! Time: %.4f s | Throughput: %.2f MB/s\n", time_taken, (file_size / (1024.0 * 1024.0)) / time_taken);

    pthread_mutex_destroy(&global_stats.stats_lock);
    return 0;
}
    
    
// --- MODE WRAPPER FUNCTIONS (DEFINITIONS) ---
int parallel_encrypt(const char *input_file, const char *output_file, const char *key, int num_threads) {
    // Calls parallel_cipher with is_decrypt = 0 (Encrypt)
    return parallel_cipher(input_file, output_file, key, num_threads, 0);
}

int parallel_decrypt(const char *input_file, const char *output_file, const char *key, int num_threads) {
    // Calls parallel_cipher with is_decrypt = 1 (Decrypt)
    return parallel_cipher(input_file, output_file, key, num_threads, 1);
}

#endif
