package binary

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func (b *Binary) Encrypt(salt ...string) ([]byte, error) {
	// Generate a random salt if provided or use an empty salt
	var saltBytes []byte
	if len(salt) > 0 {
		saltBytes = []byte(salt[0])
	}

	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// Create a new AES cipher block based on the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Apply PKCS7 padding to the data
	paddedData := padData(*b)

	// Create a new slice to store the IV and encrypted data
	ciphertext := make([]byte, len(iv)+len(paddedData))

	// Copy the IV to the beginning of the ciphertext
	copy(ciphertext, iv)

	// Create the AES cipher block mode using the IV
	stream := cipher.NewCTR(block, iv)

	// Encrypt the data
	stream.XORKeyStream(ciphertext[len(iv):], paddedData)

	// Concatenate the salt (if provided) with the ciphertext
	if len(saltBytes) > 0 {
		ciphertext = append(saltBytes, ciphertext...)
	}

	return ciphertext, nil
}

// Pad the data using PKCS7 padding scheme
func padData(data []byte) []byte {
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	paddedData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	return paddedData
}

// Decrypt the data
func (b *Binary) Decrypt(salt ...string) ([]byte, error) {
	// Get the salt if provided
	var saltBytes []byte
	if len(salt) > 0 {
		saltBytes = []byte(salt[0])
	}

	// Ensure the ciphertext is not empty
	if len(*b) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	// Extract the salt and ciphertext if salt is provided
	var ciphertext []byte
	if len(saltBytes) > 0 {
		if len(*b) <= len(saltBytes) {
			return nil, errors.New("invalid ciphertext")
		}
		saltBytes, ciphertext = (*b)[:len(saltBytes)], (*b)[len(saltBytes):]
	} else {
		ciphertext = *b
	}

	// Create a new AES cipher block based on the key
	block, err := aes.NewCipher(saltBytes)
	if err != nil {
		return nil, err
	}

	// Check if the ciphertext length is valid
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("invalid ciphertext")
	}

	// Get the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create the AES cipher block mode using the IV
	stream := cipher.NewCTR(block, iv)

	// Decrypt the data
	stream.XORKeyStream(ciphertext, ciphertext)

	// Remove PKCS7 padding from the decrypted data
	plaintext, err := unpadData(ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Remove PKCS7 padding from the data
func unpadData(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding")
	}

	padding := int(data[length-1])
	if length < padding || padding > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}

	for i := length - padding; i < length; i++ {
		if int(data[i]) != padding {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:length-padding], nil
}
