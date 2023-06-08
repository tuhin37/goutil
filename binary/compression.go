package binary

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

func (b Binary) Compress() Binary {
	var buf bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil
	}

	_, err = gzWriter.Write(b)
	if err != nil {
		return nil
	}

	err = gzWriter.Close()
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func (b Binary) Decompress() Binary {
	compressedBuf := bytes.NewBuffer(b)
	gzReader, err := gzip.NewReader(compressedBuf)
	if err != nil {
		return nil
	}

	var decompressedBuf bytes.Buffer
	_, err = decompressedBuf.ReadFrom(gzReader)
	if err != nil {
		return nil
	}

	err = gzReader.Close()
	if err != nil {
		return nil
	}

	return decompressedBuf.Bytes()
}

func (b Binary) CompressLZMA() Binary {
	var buf bytes.Buffer
	lzmaWriter, err := lzma.NewWriter(&buf)
	if err != nil {
		return nil
	}

	_, err = lzmaWriter.Write(b)
	if err != nil {
		return nil
	}

	err = lzmaWriter.Close()
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func (b Binary) DecompressLZMA() Binary {
	compressedBuf := bytes.NewBuffer(b)
	lzmaReader, err := lzma.NewReader(compressedBuf)
	if err != nil {
		return nil
	}

	var decompressedBuf bytes.Buffer
	_, err = decompressedBuf.ReadFrom(lzmaReader)
	if err != nil {
		return nil
	}

	return decompressedBuf.Bytes()
}

func (b Binary) Encrypt(key []byte) Binary {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil
	}

	// Pad the data to the nearest multiple of the block size
	paddedData := padData(b, aes.BlockSize)

	// Create a new CBC mode encrypter using the AES block cipher
	mode := cipher.NewCBCEncrypter(block, iv)

	// Create a buffer for the encrypted data
	encrypted := make([]byte, len(paddedData))

	// Encrypt the data
	mode.CryptBlocks(encrypted, paddedData)

	// Prepend the IV to the encrypted data
	encrypted = append(iv, encrypted...)

	// Encode the encrypted data as base64 for readability
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(encoded, encrypted)

	return encoded
}

func (b Binary) Decrypt(key []byte) Binary {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// Decode the base64-encoded encrypted data
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(decoded, b)
	if err != nil {
		return nil
	}
	decoded = decoded[:n]

	// Extract the IV from the encrypted data
	iv := decoded[:aes.BlockSize]
	encryptedData := decoded[aes.BlockSize:]

	// Create a new CBC mode decrypter using the AES block cipher
	mode := cipher.NewCBCDecrypter(block, iv)

	// Create a buffer for the decrypted data
	decrypted := make([]byte, len(encryptedData))

	// Decrypt the data
	mode.CryptBlocks(decrypted, encryptedData)

	// Remove the padding from the decrypted data
	unpadded := unpadData(decrypted)

	return unpadded
}

//------------------------------------------------------------

// Pad the data to the nearest multiple of blockSize using PKCS7 padding
func padData(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	return padded
}

// Remove the PKCS7 padding from the data
func unpadData(data []byte) []byte {
	padding := int(data[len(data)-1])
	unpadded := data[:len(data)-padding]
	return unpadded
}
