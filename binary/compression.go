package binary

import (
	"bytes"
	"compress/gzip"

	"github.com/ulikunitz/xz/lzma"
)

func (b *Binary) Compress() (Binary, error) {
	var buf bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	_, err = gzWriter.Write(*b)
	if err != nil {
		return nil, err
	}

	err = gzWriter.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Decompress(compressedData []byte) ([]byte, error) {
	compressedBuf := bytes.NewBuffer(compressedData)
	gzReader, err := gzip.NewReader(compressedBuf)
	if err != nil {
		return nil, err
	}

	var decompressedBuf bytes.Buffer
	_, err = decompressedBuf.ReadFrom(gzReader)
	if err != nil {
		return nil, err
	}

	err = gzReader.Close()
	if err != nil {
		return nil, err
	}

	return decompressedBuf.Bytes(), nil
}

func (b *Binary) CompressLZMA() ([]byte, error) {
	var buf bytes.Buffer
	lzmaWriter, err := lzma.NewWriter(&buf)
	if err != nil {
		return nil, err
	}

	_, err = lzmaWriter.Write(*b)
	if err != nil {
		return nil, err
	}

	err = lzmaWriter.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func DecompressLZMA(compressedData []byte) ([]byte, error) {
	compressedBuf := bytes.NewBuffer(compressedData)
	lzmaReader, err := lzma.NewReader(compressedBuf)
	if err != nil {
		return nil, err
	}

	var decompressedBuf bytes.Buffer
	_, err = decompressedBuf.ReadFrom(lzmaReader)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return decompressedBuf.Bytes(), nil
}
