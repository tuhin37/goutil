package binary

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func (b *Binary) EncryptData(salt ...string) Binary {
	var key []byte
	if len(salt) > 0 {
		key = []byte(salt[0]) // Use the provided salt as the encryption key
	} else {
		key = generateRandomKey() // Generate a random key if no salt is provided
	}

	plaintext := []byte(*b)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Append the IV to the ciphertext for decryption
	result := append(iv, ciphertext...)

	return result
}

func (b *Binary) DecryptData(salt ...string) Binary {
	var key []byte
	if len(salt) > 0 {
		key = []byte(salt[0]) // Use the provided salt as the decryption key
	} else {
		return nil
	}

	ciphertext := []byte(*b)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// Extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext
}

// Utility function to generate a random encryption key
func generateRandomKey() []byte {
	key := make([]byte, 32) // 32 bytes for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err) // Handle error appropriately in your application
	}
	return key
}
