# 🐚 shelby: ELF to Shellcode Converter
A small, efficient utility to extract bytecode from ELF executables and transform it into ready-to-use shellcode for x64 binaries.



## ✨ Features

*   🔍 **ELF Parsing:** Reliably parses ELF (Executable and Linkable Format) files to locate relevant sections.
*   🔄 **Bytecode Extraction:** Extracts raw machine code (bytecode) from specified sections of an ELF.
*   🛠️ **Shellcode Generation:** Converts the extracted bytecode into a format suitable for shellcode injection.
*   🚀 **Lightweight & Fast:** Developed in C for minimal overhead and maximum performance.
*   🧩 **Simple Integration:** Generates shellcode that can be easily integrated into exploits or custom loaders.

  (x32 bit support in progress)

---


## 🚀 Installation Guide

### Prerequisites

You will need a C compiler (like GCC) and `make` installed on your system.

*   **Linux/macOS (using GCC):**
    ```bash
    sudo apt update && sudo apt install build-essential # For Debian/Ubuntu
    # Or for macOS with Homebrew:
    # brew install gcc
    ```

### Manual Compilation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/shelby/shelby.git
    cd shelby
    ```

2.  **Compile the source code:**
    ```bash
    cc shelby.c -o shelby
    ```
    This will compile `shelby.c` and create an executable named `shelby` in the current directory.

---


## 💡 Usage Examples

The `shelby` program takes an ELF file as input and outputs the extracted shellcode.

### Basic Usage

To extract shellcode from an ELF file named `hellcode` and print it to standard output:

```bash
./shelby hellcode
```

**Example Output:**

```
"\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
WARNING: Null byte in shellcode
```
