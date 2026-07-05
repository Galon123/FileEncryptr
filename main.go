package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)


func main(){

	const Reset  = "\033[0m"
	const Red    = "\033[31m"
	const Green  = "\033[32m"
	const Yellow = "\033[33m"

	const asciiBanner = 
	`
	#    ____                             _____ _ _       __     __          _ _      ____ _     ___  
	#   / ___|  ___  ___ _   _ _ __ ___  |  ___(_) | ___  \ \   / /_ _ _   _| | |_   / ___| |   |_ _| 
	#   \___ \ / _ \/ __| | | | '__/ _ \ | |_  | | |/ _ \  \ \ / / _| | | | | | __| | |   | |    | |  
	#    ___) |  __/ (__| |_| | | |  __/ |  _| | | |  __/   \ V / (_| | |_| | | |_  | |___| |___ | |  
	#   |____/ \___|\___|\__,_|_|  \___| |_|   |_|_|\___|    \_/ \__,_|\__,_|_|\__|  \____|_____|___| 
    	#                                                                                            
	`

	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help"{
		fmt.Print(Green + asciiBanner + Reset)
		fmt.Println("\nUsage:")
		fmt.Println("   ./vault encrypt -file <filename>")
		fmt.Println("   ./vault decrypt -file <encryptedFileName>")
		fmt.Println("\nRun './vault <command> -h' for more information on a specific command")
		os.Exit(0)
	}

	encryptFlag := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encFile := encryptFlag.String("file", "", "Target file to be encrypted")

	//Aditional Flags
	encOut := encryptFlag.String("out", "", "Customize output File name (optional)")
	encRm := encryptFlag.Bool("rm", false, "Deletes Original File after Encrypting (optional)")

	decryptFlag := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decFile := decryptFlag.String("file", "", "Target file to be decrypted")

	//Additional Flags
	decOut := decryptFlag.String("out", "", "Customize output File name (optional)")
	decRm := decryptFlag.Bool("rm", false, "Deletes Encrypted File after Decrypting (optional)")

	switch os.Args[1]{
	case "encrypt":
		encryptFlag.Parse(os.Args[2:])
		if *encFile == ""{
			fmt.Println(Yellow + "[WARN] Expected a file name using -file..." + Reset)
			os.Exit(1)
		}

		passphrase,err := getPassword(true)
		if err != nil{
			fmt.Println(Red + "[ERROR] Error reading password:" + Reset,err)
			os.Exit(1)
		}

		file,err := os.ReadFile(*encFile)
		if err != nil{
			fmt.Println(Red + "[ERROR] OS read Error:" + Reset,err)
			os.Exit(1)
		}

		encData, err := EncryptData(file, passphrase)
		if err != nil{
			fmt.Println(Red + "[ERROR] Encryption Failed:" + Reset,err)
			os.Exit(1)
		}

		finalFileName := *encFile+".enc"
		if *encOut != ""{
			finalFileName = *encOut
		}
		err = os.WriteFile(finalFileName, encData, 0600)
		if err != nil{
			fmt.Println(Red + "[ERROR] Saving Encrypted File failed:" + Reset, err)
			os.Exit(1)
		}

		if *encRm {
			err = os.Remove(*encFile)
			if err != nil{
				fmt.Println(Yellow + "[WARN] Encryption Succeeded but Deletion Failed:" + Reset,err)
			} else {
				fmt.Println(Green + "[SUCCESS] Original File Deleted Successfully" + Reset)
			}
		}

		fmt.Println(Green + "[SUCCESS] Encrypted File Saved as" + Reset, finalFileName)

	case "decrypt":
		decryptFlag.Parse(os.Args[2:])
		if *decFile == ""{
			fmt.Println(Yellow + "[WARN] Expected a file name using -file" + Reset)
			os.Exit(1)
		}

		passphrase,err := getPassword(false)
		if err != nil{
			fmt.Println(Red + "[ERROR] Error reading password:" + Reset,err)
			os.Exit(1)
		}

		file,err := os.ReadFile(*decFile)
		if err != nil{
			fmt.Println(Red + "OS read Error:" + Reset,err)
			os.Exit(1)
		}

		decData, err := DecryptData(file, passphrase)
		if err != nil{
			fmt.Println(Red + "[ERROR] Decryption Failed:" + Reset,err)
			os.Exit(1)
		}

		finalFileName := strings.TrimSuffix(*decFile, ".enc") + ".decrypted"
		if *decOut != ""{
			finalFileName = *decOut
		}
		err = os.WriteFile(finalFileName, decData, 0600)
		if err != nil{
			fmt.Println(Red + "[ERROR] Saving Decrypted File failed:" + Reset, err)
			os.Exit(1)
		}

		if *decRm {
			err = os.Remove(*decFile)
			if err != nil{
				fmt.Println(Yellow + "[WARN] Encryption Succeeded but Deletion Failed:" + Reset,err)
			} else {
				fmt.Println(Green + "[SUCCESS] Original File Deleted Successfully" + Reset)
			}
		}

		fmt.Println(Green + "[SUCCESS] Decrypted File Saved as" + Reset, finalFileName)
	default:
		fmt.Printf(Yellow + "[WARN] Expected encrypt or decrypt after program name" + Reset)
		os.Exit(1)
	}
}