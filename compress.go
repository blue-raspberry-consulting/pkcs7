package pkcs7

import (
	"bytes"
	"compress/zlib"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
)

var (
	OIDCompressedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 9}
	OIDCompressionAlgorithmZLIB = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 8}
)

// ErrNotCompressedContent is returned when attempting to Decompress data that is not compressed data
var ErrNotCompressedContent = errors.New("pkcs7: content data is not a compressed data type")

// compressedData is an opaque data structure for creating compressed data payloads
type compressedData struct {
	Version                 int
	CompressionAlgorithm    pkix.AlgorithmIdentifier
	EncapsulatedContentInfo contentInfo
}

type compressedBytes []byte

// Compress creates and returns a compressed data PKCS7 structure,
// The compression algorithm is set to ZLIB.
func Compress(data []byte) ([]byte, error) {
	compressed, err := compressZlib(data)
	if err != nil {
		return nil, err
	}
	compressedContent, err := asn1.Marshal(compressed)
	if err != nil {
		return nil, err
	}
	cd := compressedData{
		Version: 0,
		CompressionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDCompressionAlgorithmZLIB,
		},
		EncapsulatedContentInfo: contentInfo{
			ContentType: OIDData,
			Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: compressedContent, IsCompound: true},
		},
	}
	innerContent, err := asn1.Marshal(cd)
	if err != nil {
		return nil, err
	}
	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDCompressedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}
	return asn1.Marshal(wrapper)
}

func compressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	return buf.Bytes(), err
}

func (p7 *PKCS7) Decompress() ([]byte, error) {
	cd, ok := p7.raw.(compressedBytes)
	if !ok {
		return nil, ErrNotCompressedContent
	}
	return decompressZlib(cd)
}

func decompressZlib(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
