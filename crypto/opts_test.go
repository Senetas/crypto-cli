package crypto_test

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/crypto"
)

var (
	constPassReader = func() ([]byte, error) {
		return []byte("hunter1"), nil
	}

	errPassReader = func() ([]byte, error) {
		return []byte{}, errors.New("could not read password")
	}
)

func TestPassPhrase(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		passReader    func() ([]byte, error)
		setPassphrase bool
		opts          crypto.Opts
		passphrase    string
	}{
		{constPassReader, true, crypto.Opts{}, "hunter2"},
		{constPassReader, false, crypto.Opts{}, "hunter1"},
		{errPassReader, false, crypto.Opts{}, ""},
	}

	for _, test := range tests {
		if test.setPassphrase {
			test.opts.SetPassphrase(test.passphrase)
		}
		passphrase1, err := test.opts.GetPassphrase(test.passReader)
		if err != nil {
			assert.EqualError(err, "could not read password")
			continue
		}

		if !assert.Equal(test.passphrase, passphrase1) {
			continue
		}

		passphrase2, err := test.opts.GetPassphrase(test.passReader)
		if assert.NoError(err) {
			continue
		}

		if !assert.Equal(test.passphrase, passphrase2) {
			continue
		}
	}
}

func TestStdinPassReader(t *testing.T) {
	assert := assert.New(t)
	passReader := crypto.StdinPassReader
	assert.NotNil(passReader)

	go passReader()
}
