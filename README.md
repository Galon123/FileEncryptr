```text

  █████╗  ███████╗  ██████╗  ██╗ ███████╗
 ██╔══██╗ ██╔════╝ ██╔════╝  ██║ ██╔════╝
 ███████║ █████╗   ██║  ███╗ ██║ ███████╗
 ██╔══██║ ██╔══╝   ██║   ██║ ██║ ╚════██║
 ██║  ██║ ███████╗ ╚██████╔╝ ██║ ███████║
 ╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝ ╚══════╝
                                                                                                         
                                    
```                             

A fast, secure, and standalone command-line utility written in Go that encrypts and decrypts local files/folders using authenticated AES-256-GCM encryption.

## **Features**

* **AES-256-GCM Encryption:** Uses authenticated cryptography to ensure data is not only hidden but mathematically verified against tampering.  
* **PBKDF2 Key Derivation:** Uses a randomized **16-byte salt** and **4096 SHA-256 iterations** to securely derive cryptographic keys from user passwords.  
* **Secure Prompting:** Masks password input in the terminal and requires confirmation to prevent accidental typos when locking files.  
* **Zero Dependencies:** Compiles down to a single, static binary. No external libraries or runtimes are required to use the compiled tool.

## **Prerequisites**
- [Go (Golang)](https://go.dev/dl/) installed and added to your system `PATH`.

## **Installation**
The easiest way to install Aegis is via the provided shell script. It will compile the binary, move it to your local bin, and configure your shell.

```bash
# 1. Clone the repository
git clone [https://github.com/your-username/Aegis-CLI.git](https://github.com/your-username/Aegis-CLI.git)
cd aegis

# 2. Make the installer executable
chmod +x install.sh

# 3. Run the installer
./install.sh

# 4. Reload your shell
source ~/.bashrc  # (or ~/.zshrc if using Zsh)
```

## **Usage**

### **Encrypting a File**

Use the encrypt subcommand and provide the target file. You will be prompted to enter and confirm a password.  
```
$ aegis encrypt -file my_secret_data.txt
```

*Output: my\_secret\_data.txt.enc*

**\* In case of directories/folders containing multiple files, `Aegis` automatically zips them into a singular file then encryptes that zip file.**


### **Decrypting a File**

Use the decrypt subcommand and provide the encrypted .enc file.  
```
$ aegis decrypt \-file my\_secret\_data.txt.enc
```

*Output: my\_secret\_data.txt.decrypted*

### **Flags**

**1. \-out**

Use after encrypt or decrypt to specify output file name.  

```out flag
$ aegis encrypt -file test_1.txt -out test1
```


**2. \-rm**

Use after encrypt or decrypt to remove the original File after operation is done.   

```
$ aegis decrypt \-file test1 -rm
```

## **How it Works Under the Hood**

1. **Encryption Phase:** A **16-byte random salt** is generated using the OS's **CSPRNG** (crypto/rand). The user's password and the salt are fed into **PBKDF2** to derive a **32-byte AES key**. A unique **12-byte Nonce** is generated. The file is encrypted using **AES-GCM**, and the resulting payload is packaged as **\[Salt\] \+ \[Nonce\] \+ \[Ciphertext\]**.  
2. **Decryption Phase:** The program reads the .enc file, slices the first 16 bytes to extract the salt, and re-derives the AES key. It extracts the 12-byte Nonce and passes the remaining ciphertext through the AES-GCM engine to authenticate and decrypt the data.