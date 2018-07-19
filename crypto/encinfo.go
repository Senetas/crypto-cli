package crypto

import (
	"github.com/pkg/errors"
)

// Algos represents the collection of algorithms used for encryption and authentication
type Algos string

const (
	// None represents an identity encryption function
	None Algos = "NONE"
	// Pbkdf2Aes256Gcm represents aead with AES256-GCM with a key derived
	// from a passphrase using PBKDF2
	Pbkdf2Aes256Gcm Algos = "PBKDF2-AES256-GCM"
)

// ValidateAlgos converts a string to valid Algos if possible
func ValidateAlgos(ctstr string) (Algos, error) {
	if ctstr == string(None) {
		return None, nil
	} else if ctstr == string(Pbkdf2Aes256Gcm) {
		return Pbkdf2Aes256Gcm, nil
	}
	return Algos(""), errors.New("invalid encryption type")
}

// Opts stores data necessary for encryption
type Opts struct {
	Passphrase string
	Salt       string
	EncType    Algos
	// whether the encryption data should be stored in a v2.2 compatible manifest or not
	Compat bool
}
