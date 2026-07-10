package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

func getPassword(confirm bool) (string, error){

	fmt.Print("[VAULT] Enter Vault Password: ")

	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil{
		return "", err
	}

	if confirm{
		fmt.Print("[VAULT] Confirm Password: ")
		confirmPass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil{
			return "", err
		}
		
		if string(bytePassword) != string(confirmPass){
			return "", errors.New("Passwords do not match")
		}
	}

	return string(bytePassword),nil
}

func ZipDirectory(sourceDir string) ([]byte, error){
	
	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)

	baseDir, err := filepath.Abs(sourceDir)
	if err != nil{
		return nil,err
	}

	err = filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {

		if err != nil{
			return err
		}

		relPath,err := filepath.Rel(baseDir, path)
		if err != nil{
			return err
		}

		//Headers Logic
		info, err := d.Info()
		if err != nil{
			return err
		}
		header,err := zip.FileInfoHeader(info)
		if err != nil{
			return err
		}

		//Cleans up slashes (Since its different slashes for paths in Windows and Linux)
		header.Name = filepath.ToSlash(relPath)

		if d.IsDir(){
			header.Name += "/"
		} else {
			header.Method = zip.Deflate 
		}

		w,err := archive.CreateHeader(header)
		if err != nil{
			return err
		}
		if d.IsDir(){
			return nil
		}
		

		file, err := os.Open(path)
		if err != nil{
			return err
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		return err
	})
	if err != nil{
		return nil,err
	}
	if err = archive.Close(); err != nil{
		return nil, err
	}

	return buf.Bytes(),nil

}

func IsZip(data []byte) bool{
	if len(data) < 4{
		return false
	}

	//Magic Number Checking to see if it is a ZIP File or not (ZIP Files start with 50 4B 03 04)
	return data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 
}

// func UnZipIntoDirectory(data []byte, destDir string) error{

// }