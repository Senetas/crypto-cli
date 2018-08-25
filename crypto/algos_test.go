package crypto_test

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/crypto"
)

func TestValidateAlgos(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		input string
		algo  crypto.Algos
		err   error
	}{
		{"NONE", crypto.None, nil},
		{"PBKDF2-AES256-GCM", crypto.Pbkdf2Aes256Gcm, nil},
		{"", crypto.Algos(""), errors.New("invalid encryption type")},
	}

	for _, test := range tests {
		algo, err := crypto.ValidateAlgos(test.input)
		if err != nil {
			assert.EqualError(err, test.err.Error())
		}
		assert.Equal(test.algo, algo)
	}
}
