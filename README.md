# 🐚 shelby: ELF to Shellcode Converter
A small, efficient utility to extract bytecode from ELF executables and transform it into ready-to-use shellcode.



## ✨ Features

*   🛠️ **Shellcode Generation:** Converts the extracted bytecode into a format suitable for shellcode injection.
*   ⚙️ **x32 Bit Files Support:** Working with x32 and x64 bit files
---


## 🚀 Installation Guide

### Prerequisites

You will need a C compiler (like GCC) and `make` installed on your system.

*   **Linux/macOS (using GCC):**
    ```bash
    sudo apt update && sudo apt install build-essential # For Debian/Ubuntu
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


## Basic Usage

To extract shellcode from an ELF file named `hellcode` and print it to standard output:

```bash
./shelby hellcode
./shelby -x hellcode_32
```

**Example Output:**

```
"\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
WARNING: Null byte in shellcode
```
