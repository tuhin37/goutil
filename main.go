package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func encryptData(data []byte, salt ...string) ([]byte, error) {
	var key []byte
	if len(salt) > 0 {
		key = []byte(salt[0]) // Use the provided salt as the encryption key
	} else {
		key = generateRandomKey() // Generate a random key if no salt is provided
	}

	plaintext := []byte(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Append the IV to the ciphertext for decryption
	result := append(iv, ciphertext...)

	return result, nil
}

func decryptData(data []byte, salt ...string) ([]byte, error) {
	var key []byte
	if len(salt) > 0 {
		key = []byte(salt[0]) // Use the provided salt as the decryption key
	} else {
		return nil, fmt.Errorf("no salt provided for decryption")
	}

	ciphertext := []byte(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Utility function to generate a random encryption key
func generateRandomKey() []byte {
	key := make([]byte, 32) // 32 bytes for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err) // Handle error appropriately in your application
	}
	return key
}

func main() {
	data := []byte("Hello, World!")

	encryptedData, err := encryptData(data)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	fmt.Println("Encrypted data:", base64.StdEncoding.EncodeToString(encryptedData))

	decryptedData, err := decryptData(encryptedData)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted data:", string(decryptedData))
}
