package crypto_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/crypto"
)

var data = []byte(`NewBuffer creates and initializes a new Buffer using buf as its initial contents. The new Buffer takes ownership of buf, and the caller should not use buf after this call. NewBuffer is intended to prepare a Buffer to read existing data. It can also be used to size the internal buffer for writing. To do that, buf should have the desired capacity but a length of zero.

In most cases, new(Buffer) (or just declaring a Buffer variable) is sufficient to initialize a Buffer.`)

func TestEncDec(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		buf    *bytes.Buffer
		key    []byte
		errEnc string
		errDec string
	}{
		{&bytes.Buffer{}, []byte("hunter2"), "key was of the wrong length", ""},
		{&bytes.Buffer{}, make([]byte, 32), "", ""},
	}

	for _, test := range tests {
		enc, err := crypto.EncBlobWriter(test.buf, test.key)
		if err != nil {
			assert.EqualError(err, test.errEnc)
			continue
		}

		src := bytes.NewBuffer(data)
		n, err := io.Copy(enc, src)
		if !assert.NoError(err) {
			continue
		}

		err = enc.Close()
		if !assert.NoError(err) {
			continue
		}

		if !assert.Equal(len(data), int(n)) {
			continue
		}

		buf2 := bytes.NewBuffer(test.buf.Bytes())

		dec, err := crypto.DecBlobReader(buf2, test.key)
		if err != nil {
			assert.EqualError(err, test.errDec)
			continue
		}

		var out bytes.Buffer
		n, err = io.Copy(&out, dec)
		if !assert.NoError(err) {
			continue
		}

		if !assert.Equal(len(data), int(n)) {
			continue
		}

		assert.Equal(data, out.Bytes())
	}
}

func TestDec(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		key    []byte
		errDec string
	}{
		{[]byte("hunter2"), "key was of the wrong length"},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(data)
		dec, err := crypto.DecBlobReader(buf, test.key)
		if err != nil {
			assert.EqualError(err, test.errDec)
			continue
		}

		var out bytes.Buffer
		n, err := io.Copy(&out, dec)
		if !assert.NoError(err) {
			continue
		}

		assert.Equal(int(n), len(data))
	}
}
