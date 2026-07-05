package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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

	fmt.Print("Enter Vault Password: ")

	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil{
		return "", err
	}

	if confirm{
		fmt.Print("Confirm Password: ")
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