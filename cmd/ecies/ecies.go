package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
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
	app.Usage = "Let's you encrypt and decrypt message using ECIES algorithm!"

	app.Commands = []cli.Command{
		{
			Name:  "generate-key",
			Usage: "Generate private key",
			Action: func(c *cli.Context) (err error) {

				key, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
				pv, err := ecies.MarshalPrivate(key)
				if err != nil {
					return err
				}
				fmt.Printf("Private key: %s\n", hex.EncodeToString(pv))

				pub, err := ecies.MarshalPublic(&key.PublicKey)
				if err != nil {
					return err
				}

				fmt.Printf("Public key %s\n", hex.EncodeToString(pub))

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

				fmt.Print("Enter your public key: ")
				pbKeyHex, err := reader.ReadString('\n')
				if err != nil {
					return err
				}

				pubBytes, err := hex.DecodeString(strings.Trim(pbKeyHex, "\n"))
				if err != nil {
					return err
				}

				pub, err := ecies.UnmarshalPublic(pubBytes)
				if err != nil {
					return err
				}

				cipherText, err := ecies.Encrypt(rand.Reader, pub, msg, nil, nil)
				if err != nil {
					return err
				}

				fmt.Print("Encrypted message: ")
				fmt.Printf("%s\n", hex.EncodeToString(cipherText))
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

				pv, err := ecies.UnmarshalPrivate(pvBytes)
				if err != nil {
					return err
				}

				message, err := pv.Decrypt(cipherHex, nil, nil)
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
