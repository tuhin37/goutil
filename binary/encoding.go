package binary

import "encoding/base64"

func (b *Binary) Base64Encode() string {
	return base64.StdEncoding.EncodeToString(*b)
}

func (b *Binary) Base64Decode(encodedStr string) ([]byte, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil, err
	}
	return decodedBytes, nil
}
