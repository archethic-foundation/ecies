package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/uniris/ecies/pkg"

	"github.com/urfave/cli"
)

func main() {

	app := cli.NewApp()
	app.Name = "ECIES"
	app.Usage = "Let's encrypt and decrypt messages using ECIES algorithm!"

	app.Commands = []cli.Command{
		{
			Name:  "generate-keys",
			Usage: "Generate private and public keys",
			Action: func(c *cli.Context) (err error) {

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				pv, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					return err
				}
				fmt.Printf("Private key: %s\n\n", hex.EncodeToString(pv))

				pub, err := x509.MarshalPKIXPublicKey(key.Public())
				if err != nil {
					return err
				}

				fmt.Printf("Public key: %s\n", hex.EncodeToString(pub))

				return nil
			},
		},
		{
			Name:  "encrypt",
			Usage: "Encrypt a message using ECIES algorithm",
			Action: func(c *cli.Context) error {

				reader := bufio.NewReader(os.Stdin)

				fmt.Print("Enter your message: ")
				msg, err := reader.ReadBytes('\n')
				if err != nil {
					return err
				}
				msgClean := strings.Trim(string(msg), "\n")

				fmt.Print("Enter your public key: ")
				pbKeyHex, err := reader.ReadString('\n')
				if err != nil {
					return err
				}

				pubBytes, err := hex.DecodeString(strings.Trim(pbKeyHex, "\n"))
				if err != nil {
					return err
				}

				pub, err := x509.ParsePKIXPublicKey(pubBytes)
				if err != nil {
					return err
				}

				ecdsaPublic := pub.(*ecdsa.PublicKey)
				pubKey := ecies.ImportECDSAPublic(ecdsaPublic)

				cipherText, err := ecies.Encrypt(rand.Reader, pubKey, []byte(msgClean), nil, nil)
				if err != nil {
					return err
				}

				fmt.Print("Encrypted message: ")
				fmt.Printf("\n%s\n", hex.EncodeToString(cipherText))
				return nil
			},
		},
		{
			Name:  "decrypt",
			Usage: "Decrypt a message using ECIES algorithm",
			Action: func(c *cli.Context) error {

				reader := bufio.NewReader(os.Stdin)

				fmt.Print("Enter your cipher text: ")
				cipher, err := reader.ReadString('\n')
				if err != nil {
					return err
				}

				cipherHex, err := hex.DecodeString(strings.Trim(cipher, "\n"))
				if err != nil {
					return err
				}

				fmt.Print("Enter your private key: ")
				pvKeyHex, err := reader.ReadString('\n')
				if err != nil {
					return err
				}

				pvBytes, err := hex.DecodeString(strings.Trim(pvKeyHex, "\n"))
				if err != nil {
					return err
				}

				pv, err := x509.ParseECPrivateKey(pvBytes)
				if err != nil {
					return err
				}

				eciesPv := ecies.ImportECDSA(pv)
				message, err := eciesPv.Decrypt(cipherHex, nil, nil)
				if err != nil {
					return err
				}

				fmt.Print("Decrypted message: ")
				fmt.Printf("%s", message)
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
