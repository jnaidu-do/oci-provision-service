package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

func convertPEMToSSHPublicKey(pemKey string) (string, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	var privateKey *rsa.PrivateKey
	var err error

	// Try PKCS1 format first
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse private key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("private key is not RSA")
		}
	}

	// Create SSH public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH public key: %v", err)
	}

	// Return the authorized key format
	return string(ssh.MarshalAuthorizedKey(publicKey)), nil
}

func main() {
	// Define command line flags
	pemFile := flag.String("pem", "", "Path to the PEM private key file")
	outputFile := flag.String("output", "", "Path to save the SSH public key (optional)")
	flag.Parse()

	// Check if PEM file is provided
	if *pemFile == "" {
		fmt.Println("Error: PEM file path is required")
		fmt.Println("Usage: pem2ssh -pem <pem_file> [-output <output_file>]")
		os.Exit(1)
	}

	// Read PEM file
	pemData, err := ioutil.ReadFile(*pemFile)
	if err != nil {
		fmt.Printf("Error reading PEM file: %v\n", err)
		os.Exit(1)
	}

	// Convert PEM to SSH public key
	sshKey, err := convertPEMToSSHPublicKey(string(pemData))
	if err != nil {
		fmt.Printf("Error converting PEM to SSH public key: %v\n", err)
		os.Exit(1)
	}

	// Print the SSH public key
	fmt.Println("Generated SSH Public Key:")
	fmt.Println(sshKey)

	// Save to output file if specified
	if *outputFile != "" {
		err = ioutil.WriteFile(*outputFile, []byte(sshKey), 0644)
		if err != nil {
			fmt.Printf("Error writing SSH public key to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SSH public key saved to: %s\n", *outputFile)
	}

	// Print verification instructions
	fmt.Println("\nTo verify the key:")
	fmt.Println("1. Copy the generated SSH public key above")
	fmt.Println("2. Add it to the ~/.ssh/authorized_keys file on your target VM")
	fmt.Println("3. Try to SSH using the original PEM key:")
	fmt.Printf("   ssh -i %s <username>@<vm-ip>\n", *pemFile)
}
