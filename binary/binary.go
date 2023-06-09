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

func (b Binary) CalculateBcrypt() (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hashedBytes), nil
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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// Create a new byte slice to store the ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]

	// Generate a random IV (initialization vector)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}

	// Use cipher.NewCTR to create a stream cipher for encryption
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], b)

	return ciphertext
}

func (b Binary) Decrypt(key []byte) Binary {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	if len(b) < aes.BlockSize {
		return nil
	}

	iv := b[:aes.BlockSize]
	ciphertext := b[aes.BlockSize:]

	// Use cipher.NewCTR to create a stream cipher for decryption
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext
}
