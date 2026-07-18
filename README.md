```text
                                                                                               
                                                                                               
               AAA                                                         iiii                   
              A:::A                                                       i::::i                  
             A:::::A                                                       iiii                   
            A:::::::A                                                                          
           A:::::::::A             eeeeeeeeeeee         ggggggggg   ggggg iiiiiii     ssssssssss   
          A:::::A:::::A          ee::::::::::::ee     g:::::::::ggg::::g  i:::::i   ss::::::::::s  
         A:::::A A:::::A        e::::::eeeee:::::ee  g:::::::::::::::::g  i::::i  ss:::::::::::::s 
        A:::::A   A:::::A      e::::::e     e:::::e g::::::ggggg::::::gg  i::::i  s::::::ssss:::::s
       A:::::A     A:::::A     e:::::::eeeee::::::e g:::::g     g:::::g   i::::i   s:::::s  ssssss 
      A:::::AAAAAAAAA:::::A    e:::::::::::::::::e  g:::::g     g:::::g   i::::i     s::::::s      
     A:::::::::::::::::::::A   e::::::eeeeeeeeeee   g:::::g     g:::::g   i::::i        s::::::s   
    A:::::AAAAAAAAAAAAA:::::A  e:::::::e            g::::::g    g:::::g   i::::i  ssssss   s:::::s 
   A:::::A             A:::::A e::::::::e           g:::::::ggggg:::::g  i::::::i s:::::ssss::::::s
  A:::::A               A:::::A e::::::::eeeeeeee    g::::::::::::::::g  i::::::i s::::::::::::::s 
 A:::::A                 A:::::A ee:::::::::::::e     gg::::::::::::::g  i::::::i  s:::::::::::ss  
AAAAAAA                   AAAAAAA  eeeeeeeeeeeeee       gggggggg::::::g  iiiiiiii   sssssssssss    
                                                               g:::::g                          
                                                   gggggg      g:::::g                          
                                                   g:::::gg   gg:::::g                          
                                                    g::::::ggg:::::::g                          
                                                     gg:::::::::::::g                           
                                                       ggg::::::ggg                             

                                                          gggggg  
```                             

A fast, secure, and standalone command-line utility written in Go that encrypts and decrypts local files using authenticated AES-256-GCM encryption.

## **Features**

* **` `AES-256-GCM Encryption:` `** Uses authenticated cryptography to ensure data is not only hidden but mathematically verified against tampering.  
* **` `PBKDF2 Key Derivation:` `** Uses a randomized **16-byte salt** and **4096 SHA-256 iterations** to securely derive cryptographic keys from user passwords.  
* **` `Secure Prompting:` `** Masks password input in the terminal and requires confirmation to prevent accidental typos when locking files.  
* **` `Zero Dependencies:` `** Compiles down to a single, static binary. No external libraries or runtimes are required to use the compiled tool.

## **Installation**

### **Option 1: Download the Binary**

Available in *Releases*

### **Option 2: Build from Source**

Ensure you have Go installed, clone the repository, and build the binary:  
git clone \[https://github.com/yourusername/FileEncryptr.git\](https://github.com/yourusername/FileEncryptr.git)  
cd File-Encryptr  
go build \-o vault

## **Usage**

### **Encrypting a File**

Use the encrypt subcommand and provide the target file. You will be prompted to enter and confirm a password.  
./vault encrypt \-file my\_secret\_data.txt

*Output: my\_secret\_data.txt.enc*


### **Decrypting a File**

Use the decrypt subcommand and provide the encrypted .enc file.  
./vault decrypt \-file my\_secret\_data.txt.enc

*Output: my\_secret\_data.txt.decrypted*

### **Flags**

**1. \-out <outputFileName>**

Use after encrypt or decrypt to specify output file name.  

*./vault encrypt \-file test\_1.txt \-out test1*


**2. \-rm**

Use after encrypt or decrypt to remove the original File after operation is done.   

*./vault decrypt \-file test1 -rm* 


## **How it Works Under the Hood**

1. **Encryption Phase:** A **16-byte random salt** is generated using the OS's **CSPRNG** (crypto/rand). The user's password and the salt are fed into **PBKDF2** to derive a **32-byte AES key**. A unique **12-byte Nonce** is generated. The file is encrypted using **AES-GCM**, and the resulting payload is packaged as **\[Salt\] \+ \[Nonce\] \+ \[Ciphertext\]**.  
2. **Decryption Phase:** The program reads the .enc file, slices the first 16 bytes to extract the salt, and re-derives the AES key. It extracts the 12-byte Nonce and passes the remaining ciphertext through the AES-GCM engine to authenticate and decrypt the data.