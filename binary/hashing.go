package binary

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash/adler32"
	"hash/crc32"

	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

type Binary []byte

// --------------------------- Hashing ---------------------------
func (b *Binary) CalculateMD5() string {
	hasher := md5.New()
	hasher.Write(*b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b *Binary) CalculateSHA1() string {
	hasher := sha1.New()
	hasher.Write(*b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b *Binary) CalculateSHA256() string {
	hasher := sha256.New()
	hasher.Write(*b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b *Binary) CalculateSHA3() string {
	hasher := sha3.New256()
	hasher.Write(*b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b *Binary) CalculateSHA512() string {
	hasher := sha512.New()
	hasher.Write(*b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (b *Binary) CalculateBcrypt() (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword(*b, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hashedBytes), nil
}

func (b *Binary) CalculateCRC32() uint32 {
	hasher := crc32.NewIEEE()
	hasher.Write(*b)
	return hasher.Sum32()
}

func (b *Binary) CalculateAdler32() uint32 {
	hasher := adler32.New()
	hasher.Write(*b)
	return hasher.Sum32()
}
