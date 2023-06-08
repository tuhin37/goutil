package binary

import (
	"bytes"
	"compress/gzip"

	"github.com/ulikunitz/xz/lzma"
)

func (b *Binary) Compress() Binary {
	var buf bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil
	}

	_, err = gzWriter.Write(*b)
	if err != nil {
		return nil
	}

	err = gzWriter.Close()
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func (b *Binary) Decompress() Binary {
	compressedBuf := bytes.NewBuffer(*b)
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

func (b *Binary) CompressLZMA() Binary {
	var buf bytes.Buffer
	lzmaWriter, err := lzma.NewWriter(&buf)
	if err != nil {
		return nil
	}

	_, err = lzmaWriter.Write(*b)
	if err != nil {
		return nil
	}

	err = lzmaWriter.Close()
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func (b *Binary) DecompressLZMA() Binary {
	compressedBuf := bytes.NewBuffer(*b)
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
