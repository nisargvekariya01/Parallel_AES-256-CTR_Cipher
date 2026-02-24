# 🔐 Parallel AES-256-CTR Cipher

**A modern, multithreaded file cipher that combines fast parallel AES-256-CTR with built-in integrity verification for safer encryption workflows.**

![Banner](images/banner.png)

![Language: C](https://img.shields.io/badge/Language-C-00599C)
![License: MIT](https://img.shields.io/badge/License-MIT-success)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-FCC624)
![Security: AES-256-CTR](https://img.shields.io/badge/Security-AES--256--CTR-red)

---

## ✨ Key Features

- ⚡ **Parallelized encryption/decryption** with `pthread` to utilize multi-core CPUs efficiently.
- 🛡️ **AES-256-CTR mode** for secure and high-throughput block processing.
- 🔍 **HMAC-SHA256 integrity protection** to detect key mismatch or ciphertext tampering.
- 🔐 **PBKDF2 key stretching** (`PKCS5_PBKDF2_HMAC`) to derive a 256-bit key from user passwords.
- 🖥️ **Interactive ncurses TUI** with file browser for simple, keyboard-driven operation.
- 📈 **Runtime metrics** including total processing time and MB/s throughput.

---

## 🧠 Technical Deep-Dive

### Why AES-CTR for parallelism?

AES-CTR converts a block cipher into a stream-like construction where each block is generated from an independent counter value. Because blocks do not depend on prior ciphertext blocks (unlike CBC), file chunks can be encrypted/decrypted concurrently across multiple threads with minimal synchronization.

### HMAC-SHA256 integrity check

After encryption, the project computes an HMAC-SHA256 tag over the ciphertext and stores it in `.hmac_data`. During decryption, the tag is recalculated and compared with the stored value. If verification fails, output is treated as untrusted and removed.

### PBKDF2 for key stretching

User-provided passwords are expanded into a fixed 32-byte AES key using PBKDF2-HMAC-SHA256 with 10,000 iterations (`PKCS5_PBKDF2_HMAC`). This raises the cost of brute-force attacks compared with directly using raw password bytes.

---

## 📁 Project Structure

| Path                      | Purpose                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------- |
| `main.c`                  | Entry point, input validation, and encrypt/decrypt dispatch logic.                    |
| `encryption_decryption.h` | Parallel AES-CTR engine, worker-thread routine, IV/HMAC read/write, and verification. |
| `tui.h`                   | ncurses-based TUI and interactive file browser implementation.                        |
| `project_defs.h`          | Shared constants (`MAX_THREADS`, AES/HMAC sizes, filenames) and common headers.       |
| `utility.h`               | Helpers for file sizing, microsecond timing, and safe path construction.              |
| `images/`                 | Documentation media (banner and screenshot assets).                                   |

---

## 🛠️ Installation & Usage

### 1) Install dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y libssl-dev libncurses-dev
```

### 2) Build

Use the exact compilation command from the project:

```bash
gcc main.c -o parallel_cipher -lpthread -lssl -lcrypto -lncurses
```

### 3) Run

```bash
./parallel_cipher
```

### Quick Start (TUI navigation)

1. Launch the app with `./parallel_cipher`.
2. Use **UP/DOWN** arrows to move between fields.
3. On **Input File Path**, press **ENTER** to open the file browser.
4. In file browser: use **UP/DOWN** to navigate, **ENTER** to open/select, **ESC** to return.
5. Set mode to `encrypt` or `decrypt`.
6. Review/edit **Output File Path**.
7. Enter your **Encryption Key**.
8. Set **Threads** (valid range: `1-16`).
9. Press **CTRL+D** (or **Backspace**) to submit and execute.
10. Press **F1** anytime to cancel.

---

## 📸 Screenshots

### Main TUI

![Main TUI](images/tui_main.png)

### File Browser

![File Browser](images/file_browser.png)

### Completion Summary

![Completion](images/completion.png)

---

## ⚠️ Important Notes

> **Do not lose `.iv_data` and `.hmac_data`.**
> These hidden files are generated during encryption and are required for successful and verified decryption.

> If HMAC validation fails during decryption, the program treats output as unsafe and deletes the generated output file.
