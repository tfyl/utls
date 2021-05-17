package tls

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/andybalholm/brotli"
	"golang.org/x/crypto/cryptobyte"
)

// https://github.com/refraction-networking/utls/blob/33a29038e742910d6ec82636748dfad5dd7f30ae/u_tls_extensions.go#L692

const (
	certCompressionAlgs    uint16 = 27
	typeCertAlgCompression uint8  = 25
)

type CertAlgCompressionExtension struct {
	Methods []CertCompressionAlgo
}

func (e *CertAlgCompressionExtension) writeToUConn(uc *UConn) error {
	uc.extCompressCerts = true
	return nil
}

func (e *CertAlgCompressionExtension) Len() int {
	return 4 + 1 + (2 * len(e.Methods))
}

func (e *CertAlgCompressionExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
	b[0] = byte(certCompressionAlgs >> 8)
	b[1] = byte(certCompressionAlgs & 0xff)

	extLen := 2 * len(e.Methods)
	if extLen > 255 {
		return 0, errors.New("too many certificate compression methods")
	}

	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte((extLen + 1) & 0xff)
	b[4] = byte(extLen)

	i := 5
	for _, compMethod := range e.Methods {
		b[i] = byte(compMethod >> 8)
		b[i+1] = byte(compMethod)
		i += 2
	}
	return e.Len(), io.EOF
}

type certAlgCompressionMessage struct {
	method                       CertCompressionAlgo
	uncompressedLength           uint32
	compressedCertificateMessage []byte
	data                         []byte
}

func (m *certAlgCompressionMessage) marshal() []byte {
	if m.data != nil {
		return m.data
	}

	return []byte{} //TODO: implement it
}

func (m *certAlgCompressionMessage) unmarshal(data []byte) bool {
	m.data = append([]byte{}, data...)

	s := cryptobyte.String(data[4:])

	var algID uint16
	if !s.ReadUint16(&algID) {
		return false
	}
	if !s.ReadUint24(&m.uncompressedLength) {
		return false
	}
	if !readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}

	m.method = CertCompressionAlgo(algID)

	return true
}

func (m *certAlgCompressionMessage) toCertificateMsg() (*CertificateMsgTLS13, error) {
	var (
		decompressed []byte
		r            io.ReadCloser
		err          error
	)

	if m.uncompressedLength > 1<<24 {
		return nil, fmt.Errorf("decompressed certificate is to large")
	}

	compressed := bytes.NewBuffer(m.compressedCertificateMessage)
	decompressed = make([]byte, m.uncompressedLength)

	switch m.method {
	case CertCompressionZlib:
		r, err = zlib.NewReader(compressed)
		if err != nil {
			decompressed, err = ioutil.ReadAll(r)
		}

		if err != nil {
			r.Close()
		}

	case CertCompressionBrotli:
		decompressed, err = ioutil.ReadAll(brotli.NewReader(compressed))

	//TODO:Implement zstd decompression

	default:
		return nil, fmt.Errorf("certificate compression method %v is not supported", m.method)
	}

	if err != nil {
		return nil, err
	}

	length := len(decompressed)
	if length != int(m.uncompressedLength) {
		return nil, fmt.Errorf("length of decompressed certificate is invalid: %v", length)
	}

	decompressed = append([]byte{
		11, //utls.typeCertificate
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}, decompressed...)

	var mm certificateMsgTLS13
	if !mm.Unmarshal(decompressed) {
		return nil, fmt.Errorf("unmarshal decompressed data failed")
	}

	return &mm, nil
}
