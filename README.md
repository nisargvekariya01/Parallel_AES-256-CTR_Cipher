# 🔐 Parallel AES-256-CTR Cipher

A high-performance, multi-threaded file encryption and decryption tool. It leverages **AES-256-CTR** for secure data transformation and **HMAC-SHA256** to ensure that files have not been tampered with. The project includes a sleek **ncurses TUI** for easy file selection and configuration.

## 🚀 Key Features

* **⚡ Parallel Processing**: Splits files into chunks and processes them simultaneously using `pthread`, significantly reducing processing time on multi-core systems.
* **🛡️ Strong Cryptography**:
* **Cipher**: AES-256-CTR (Counter Mode) for fast, seekable encryption.
* **Integrity**: HMAC-SHA256 to detect any unauthorized modifications to ciphertext.
* **Key Derivation**: PKCS5_PBKDF2_HMAC used to derive 32-byte keys from user passwords.


* **🖥️ Interactive TUI**: Built with `ncurses`, featuring a built-in file browser and field-based configuration.
* **📊 Performance Metrics**: Real-time throughput (MB/s) and time-taken reports upon completion.

## 📁 Project Structure

| File | Description |
| --- | --- |
| `main.c` | Entry point; manages the TUI flow and execution logic. |
| `encryption_decryption.h` | Core logic for parallel AES processing and HMAC calculation. |
| `tui.h` | Ncurses implementation for the main menu and file selector. |
| `project_defs.h` | Global constants, structure definitions, and standard headers. |
| `utility.h` | Helper functions for file size, timing, and path joining. |

## 🛠️ Installation & Compilation

### Prerequisites

You must have the **OpenSSL** and **ncurses** development libraries installed on your Linux/Unix system.

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev libncurses5-dev libncursesw5-dev

```

### Compilation

Use `gcc` to compile the project, linking the necessary libraries:

```bash
gcc main.c -o parallel_cipher -lpthread -lssl -lcrypto -lncurses

```

## 📖 Usage

1. **Launch**: Run `./parallel_cipher`.
2. **Navigation**: Use **UP/DOWN** arrows to move between fields.
3. **File Selection**: Highlight the "Input File Path" and press **ENTER** to open the built-in file browser.
4. **Configuration**: Enter your password, output name, and the number of threads (1-16).
5. **Execution**: Press **CTRL+D** or **Backspace** to submit and start the operation.
6. **Cancel**: Press **F1** at any time to exit.

## 📸 Screenshots

### 1. Configuration Menu

The TUI allows you to set the mode, choose files, and specify thread counts in a clean interface.

### 2. Built-in File Browser

Easily navigate your local directories to select input files.

### 3. Execution Summary

Once the process finishes, the tool provides a summary of the time taken and the processing speed.

## ⚠️ Important Notes

* **Hidden Files**: The tool generates `.iv_data` and `.hmac_data` files during encryption. These are **required** for decryption.
* **Integrity Check**: If the HMAC verification fails during decryption, the tool will delete the corrupted output file to protect you from tampered data.
