package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/spf13/pflag"
	"io"
	"io/ioutil"
	"os"
)

const salt = "some-random-salt-LQKyPm^JURst1KvsCPUq"

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Encrypt(data string) string {
	block, _ := aes.NewCipher([]byte(createHash(salt)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func Decrypt(encryptedData string) string {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		panic(err.Error())
	}

	key := []byte(createHash(salt))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return string(plaintext)
}

func main() {
	mode := pflag.StringP("mode", "m", "decrypt", "Mode encrypt/decrypt")
	pflag.Parse()

	fi, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		fmt.Fprint(os.Stderr, "No input")
		os.Exit(1)
	}

	dataBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	data := string(dataBytes)

	if *mode == "encrypt" {
		fmt.Println(Encrypt(data))
	} else {
		fmt.Println(Decrypt(data))
	}
}
