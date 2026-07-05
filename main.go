package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)


func EncryptData(plaintext []byte, passphrase string) ([]byte, error){

	salt := make([]byte, 16)
	if _,err := io.ReadFull(rand.Reader, salt); err != nil{
		return nil, err
	}

	key, err := pbkdf2.Key(sha256.New, passphrase, salt, 4096, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil{
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil{
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _,err := io.ReadFull(rand.Reader, nonce); err != nil{
		return nil,err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	finalPayload := append(salt, append(nonce, ciphertext...)...)
	return finalPayload, nil
}

func DecryptData(encryptedPayload []byte, passphrase string) ([]byte, error){

	saltLen := 16
	nonceLen := 12
	minRequiredLen := saltLen + nonceLen

	if len(encryptedPayload) < minRequiredLen {
		return nil, errors.New("encryptedPayload is too short, or is corrupted")
	}

	salt := encryptedPayload[:saltLen]
	nonce := encryptedPayload[saltLen:minRequiredLen]
	ciphertext := encryptedPayload[minRequiredLen:]

	key, err := pbkdf2.Key(sha256.New, passphrase, salt, 4096, 32)
	if err != nil{
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil{
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil{
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil{
		return nil, errors.New("Authentication Failed: invalid key or tampered data")
	}

	return plaintext, nil
}

func getPassword() (string, error){

	fmt.Print("Enter Vault Password: ")

	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil{
		return "", err
	}

	return string(bytePassword),nil
}

func main(){

	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help"{
		fmt.Println("Secure File Vault CLI")
		fmt.Println("\nUsage:")
		fmt.Println("   ./vault encrypt -file <filename>")
		fmt.Println("   ./vault decrypt -file <encryptedFileName>")
		fmt.Println("\nRun './vault <command> -h' for more information on a specific command")
		os.Exit(0)
	}

	encryptFlag := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encFile := encryptFlag.String("file", "", "Target file to be encrypted")

	decryptFlag := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decFile := decryptFlag.String("file", "", "Target file to be decrypted")


	switch os.Args[1]{
	case "encrypt":
		encryptFlag.Parse(os.Args[2:])
		if *encFile == ""{
			fmt.Println("Expected a file name using -file...")
			os.Exit(1)
		}
		passpharse,err := getPassword()
		if err != nil{
			fmt.Println("Error reading password: ",err)
			os.Exit(1)
		}
		file,err := os.ReadFile(*encFile)
		if err != nil{
			fmt.Println("OS read Error: ",err)
			os.Exit(1)
		}
		encData, err := EncryptData(file, passpharse)
		if err != nil{
			fmt.Println("Encryption Failed: ",err)
			os.Exit(1)
		}
		err = os.WriteFile(*encFile+".enc", encData, 0600)
		if err != nil{
			fmt.Println("Saving Encrypted File failed: ", err)
			os.Exit(1)
		}
		fmt.Println("Success...Encrypted File Saved as", *encFile+".enc")

	case "decrypt":
		decryptFlag.Parse(os.Args[2:])
		if *decFile == ""{
			fmt.Println("Expected a file name using -file...")
			os.Exit(1)
		}
		passphrase,err := getPassword()
		if err != nil{
			fmt.Println("Error reading password:",err)
			os.Exit(1)
		}
		file,err := os.ReadFile(*decFile)
		if err != nil{
			fmt.Println("OS read Error:",err)
			os.Exit(1)
		}
		decData, err := DecryptData(file, passphrase)
		if err != nil{
			fmt.Println("Decryption Failed:",err)
			os.Exit(1)
		}
		*decFile = strings.TrimSuffix(*decFile, ".enc") + ".decrypted"
		err = os.WriteFile(*decFile, decData, 0600)
		if err != nil{
			fmt.Println("Saving Decrypted File failed: ", err)
			os.Exit(1)
		}
		fmt.Println("Success...Decrypted File Saved as", *decFile)
	default:
		fmt.Printf("Expected encrypt or decrypt after program name...")
		os.Exit(1)
	}
}