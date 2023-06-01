package fileio

import (
	"io/ioutil"

	"github.com/tuhin37/goutil/binary"
)

type fileHandler struct {
	path string
}

func FileHandler(path string) *fileHandler {
	return &fileHandler{path: path}
}

func (fp *fileHandler) ReadBinary() binary.Binary {
	data, err := ioutil.ReadFile(fp.path)
	if err != nil {
		return nil
	}
	return data
}

func (fp *fileHandler) WriteBinary(data binary.Binary) error {
	err := ioutil.WriteFile(fp.path, data, 0644)
	if err != nil {
		return err
	}
	return nil
}
