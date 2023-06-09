package binary

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash/adler32"
	"hash/crc32"
	"io"

	"github.com/ulikunitz/xz/lzma"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

type Binary []byte

// --------------------------- Hashing ---------------------------

func (b Binary) CalculateMD5() string {
	hasher := md5.New()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b Binary) CalculateSHA1() string {
	hasher := sha1.New()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b Binary) CalculateSHA256() string {
	hasher := sha256.New()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b Binary) CalculateSHA3() string {
	hasher := sha3.New256()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b Binary) CalculateSHA512() string {
	hasher := sha512.New()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b Binary) CalculateBcrypt() string {
	hashedBytes, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hashedBytes)
}

func (b Binary) CalculateCRC32() uint32 {
	hasher := crc32.NewIEEE()
	hasher.Write(b)
	return hasher.Sum32()
}

func (b Binary) CalculateAdler32() uint32 {
	hasher := adler32.New()
	hasher.Write(b)
	return hasher.Sum32()
}

// ------------------------- compression -------------------------

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

//--------------------------- encoding ---------------------------

func (b Binary) EncodeBase64() string {
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeBase64(encodedStr string) Binary {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil
	}
	return decodedBytes
}

//--------------------------- encryption ---------------------------

func (b Binary) Encrypt(key []byte) Binary {

	// the key argument should be the AES key, either 16, 24, or 32 bytes
	// to select AES-128, AES-192, or AES-256.
	// since it is not garanteed that the key is 16, 24 or 32 bytes,
	// do md5 of incoming key to make sure the outputis always 32 bytes
	hasher := md5.New()
	hasher.Write(key)
	keyAES := []byte(hex.EncodeToString(hasher.Sum(nil))) // 32 bytes always, no matter what input

	block, err := aes.NewCipher(keyAES)
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
	padding := aes.BlockSize - (len(b) % aes.BlockSize)
	paddedData := append(b, bytes.Repeat([]byte{byte(padding)}, padding)...)

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
	// the key argument should be the AES key, either 16, 24, or 32 bytes
	// to select AES-128, AES-192, or AES-256.
	// since it is not garanteed that the key is 16, 24 or 32 bytes,
	// do md5 of incoming key to make sure the outputis always 32 bytes
	hasher := md5.New()
	hasher.Write(key)
	keyAES := []byte(hex.EncodeToString(hasher.Sum(nil))) // 32 bytes always, no matter what input

	block, err := aes.NewCipher(keyAES)
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
	padding := int(decrypted[len(decrypted)-1])
	unpadded := decrypted[:len(decrypted)-padding]

	return unpadded
}

/*
--------------------------- examples ---------------------------
func main() {

	file := fileio.FileHandler("./foo.bar")
	fileContentRaw := file.ReadBinary()

	// //------------------------------- compress -------------------------------
	// fmt.Println("-----------------------------------------------------------")
	// compressedLZMA := fileContentRaw.CompressLZMA()
	// compressedGZIP := fileContentRaw.Compress()
	// fmt.Println("original size: ", len(fileContentRaw))
	// fmt.Println("compressedLZMA size: ", len(compressedLZMA))
	// fmt.Println("compressedGZIP size: ", len(compressedGZIP))

	// decompressedLZMA := compressedLZMA.DecompressLZMA()
	// decompressedGZIP := compressedGZIP.Decompress()

	// fmt.Println("decompressedLZMA: ", string(decompressedLZMA))
	// fmt.Println("decompressedLGZIP: ", string(decompressedGZIP))

	// //-------------------------------- encode --------------------------------
	// fmt.Println("-----------------------------------------------------------")
	// encoded64 := fileContentRaw.EncodeBase64()
	// fmt.Println("base64-encoded: ", encoded64)
	// decoded64 := binary.DecodeBase64(encoded64)
	// fmt.Println("base64-decoded: ", string(decoded64))

	//------------------------------- encrypt -------------------------------
	fmt.Println("-----------------------------------------------------------")
	// Encrypt the data
	encrypted := fileContentRaw.Encrypt([]byte("supersecretkey"))
	fmt.Println("Encrypted data:", string(encrypted))
	decrypted := encrypted.Decrypt([]byte("supersecretkey"))
	fmt.Println("Decrypted data:", string(decrypted))

	//------------------------------- hashing -------------------------------
	fmt.Println("-----------------------------------------------------------")
	fmt.Println("md5: ", fileContentRaw.CalculateMD5())
	fmt.Println("sha1: ", fileContentRaw.CalculateSHA1())
	fmt.Println("sha256: ", fileContentRaw.CalculateSHA256())
	fmt.Println("sha512: ", fileContentRaw.CalculateSHA512())
	fmt.Println("sha3: ", fileContentRaw.CalculateSHA3())
	fmt.Println("bcrypt: ", fileContentRaw.CalculateBcrypt())
	fmt.Println("crc32: ", fileContentRaw.CalculateCRC32())
	fmt.Println("Adler32: ", fileContentRaw.CalculateAdler32())
}
*/
