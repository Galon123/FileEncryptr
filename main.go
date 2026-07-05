package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)


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
	encOut := encryptFlag.String("out", "", "Customize output File name (optional)")

	decryptFlag := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decFile := decryptFlag.String("file", "", "Target file to be decrypted")
	decOut := decryptFlag.String("out", "", "Customize output File name (optional)")


	switch os.Args[1]{
	case "encrypt":
		encryptFlag.Parse(os.Args[2:])
		if *encFile == ""{
			fmt.Println("Expected a file name using -file...")
			os.Exit(1)
		}

		passphrase,err := getPassword(true)
		if err != nil{
			fmt.Println("Error reading password: ",err)
			os.Exit(1)
		}

		file,err := os.ReadFile(*encFile)
		if err != nil{
			fmt.Println("OS read Error: ",err)
			os.Exit(1)
		}

		encData, err := EncryptData(file, passphrase)
		if err != nil{
			fmt.Println("Encryption Failed: ",err)
			os.Exit(1)
		}

		finalFileName := *encFile+".enc"
		if *encOut != ""{
			finalFileName = *encOut
		}
		err = os.WriteFile(finalFileName, encData, 0600)
		if err != nil{
			fmt.Println("Saving Encrypted File failed: ", err)
			os.Exit(1)
		}

		fmt.Println("Success...Encrypted File Saved as", finalFileName)

	case "decrypt":
		decryptFlag.Parse(os.Args[2:])
		if *decFile == ""{
			fmt.Println("Expected a file name using -file...")
			os.Exit(1)
		}

		passphrase,err := getPassword(false)
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
		finalFileName := *decFile
		if *decOut != ""{
			finalFileName = *decOut
		}
		err = os.WriteFile(finalFileName, decData, 0600)
		if err != nil{
			fmt.Println("Saving Decrypted File failed: ", err)
			os.Exit(1)
		}

		fmt.Println("Success...Decrypted File Saved as", finalFileName)
	default:
		fmt.Printf("Expected encrypt or decrypt after program name...")
		os.Exit(1)
	}
}