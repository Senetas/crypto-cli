package distribution_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/utils"
	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/udhos/equalfile"
)

var (
	//passphrase = "196884 = 196883 + 1"
	passphrase = "hunter2"
	opts       = &crypto.Opts{
		Algos:  crypto.Pbkdf2Aes256Gcm,
		Compat: false,
	}
	optsNone = &crypto.Opts{
		Algos:  crypto.None,
		Compat: false,
	}
	optsCompat = &crypto.Opts{
		Algos:  crypto.Pbkdf2Aes256Gcm,
		Compat: true,
	}
	optsMock = &crypto.Opts{
		Algos: crypto.Algos("mock"),
	}

	tests = []struct {
		opts       *crypto.Opts
		passphrase string
		mkFile     func(*testing.T, string) (int64, digest.Digest, string, error)
		newBlob    func(string, digest.Digest, int64, *crypto.DeCrypto) distribution.DecryptedBlob
	}{
		{opts, passphrase, mkRandFile, distribution.NewLayer},
		{optsNone, "", mkRandFile, distribution.NewLayer},
		{optsCompat, passphrase, mkRandFile, distribution.NewLayer},
		{opts, passphrase, mkConfigFile, distribution.NewConfig},
		{optsNone, "", mkConfigFile, distribution.NewConfig},
		{optsCompat, passphrase, mkConfigFile, distribution.NewConfig},
	}
)

func TestCryptoBlobsEncDec(t *testing.T) {
	assert := assert.New(t)

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		c, err := crypto.NewDecrypto(test.opts)
		if !assert.NoError(err) {
			continue
		}

		dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
		defer func() { assert.NoError((utils.CleanUp(dir, nil))) }()
		encpath := filepath.Join(dir, "enc")
		decpath := filepath.Join(dir, "dec")

		size, d, fn, err := test.mkFile(t, dir)
		if !assert.NoError(err) {
			continue
		}

		blob := test.newBlob(fn, d, size, c)

		enc, err := blob.EncryptBlob(test.opts, encpath)
		if !assert.NoError(err) {
			continue
		}

		kdec, err := enc.DecryptKey(test.opts)
		if !assert.NoError(err) {
			continue
		}

		dec, err := kdec.DecryptFile(test.opts, decpath)
		if !assert.NoError(err) {
			continue
		}

		assert.NoError(blobTest(t, dir, fn, encpath, decpath, blob, enc, dec))
	}
}

func TestCryptoBlobsEncDecEncDec(t *testing.T) {
	assert := assert.New(t)

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		c, err := crypto.NewDecrypto(test.opts)
		if !assert.NoError(err) {
			continue
		}

		dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
		defer func() { assert.NoError((utils.CleanUp(dir, nil))) }()
		encpath := filepath.Join(dir, "enc")
		decpath := filepath.Join(dir, "dec")

		size, d, fn, err := test.mkFile(t, dir)
		if !assert.NoError(err) {
			continue
		}

		blob := test.newBlob(fn, d, size, c)

		enc, err := blob.EncryptBlob(test.opts, encpath)
		if !assert.NoError(err) {
			continue
		}

		kdec, err := enc.DecryptKey(test.opts)
		if !assert.NoError(err) {
			continue
		}

		enc2, err := kdec.EncryptKey(test.opts)
		if !assert.NoError(err) {
			continue
		}

		dec, err := enc2.DecryptBlob(test.opts, decpath)
		if !assert.NoError(err) {
			continue
		}

		assert.NoError(blobTest(t, dir, fn, encpath, decpath, blob, enc, dec))
	}
}

func TestCompressBlobs(t *testing.T) {
	assert := assert.New(t)

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	defer func() { assert.NoError((utils.CleanUp(dir, nil))) }()
	size, d, fn, err := mkConstFile(t, dir)
	if !assert.NoError(err) {
		return
	}

	compath := filepath.Join(dir, "enc.gz")
	decpath := filepath.Join(dir, "dec")

	blob := distribution.NewPlainLayer(fn, d, size)

	comp, err := blob.Compress(compath)
	if !assert.NoError(err) {
		return
	}

	dec, err := comp.Decompress(decpath)
	if !assert.NoError(err) {
		return
	}

	assert.NoError(blobTest(t, dir, fn, compath, decpath, blob, comp, dec))
}

func blobTest(
	t *testing.T,
	dir, filename, convpath, deconvpath string,
	blob, conv, deconv distribution.Blob,
) (err error) {
	fi, err := os.Stat(convpath)
	if err != nil {
		return
	} else if fi.Size() != conv.GetSize() {
		t.Error(errors.Errorf("converted file is incorrect size: %d vs %d", fi.Size(), conv.GetSize()))
	}

	fi, err = os.Stat(deconvpath)
	if err != nil {
		return
	} else if fi.Size() != deconv.GetSize() {
		t.Error(errors.Errorf("decompressed file is incorrect size: %d vs %d", fi.Size(), deconv.GetSize()))
	}

	equal, err := equalfile.CompareFile(filename, deconv.GetFilename())
	if err != nil {
		return
	}

	if !equal {
		showContents(t, filename, deconvpath)
		return
	}

	if blob.GetDigest().String() != deconv.GetDigest().String() {
		err = errors.Errorf(
			"digests do not match: orig: %s decrypted: %s",
			blob.GetDigest(),
			deconv.GetDigest(),
		)
	}
	return
}

func mkConstFile(t *testing.T, dir string) (_ int64, _ digest.Digest, _ string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}

	file := filepath.Join(dir, "plain")
	fh, err := os.Create(file)
	if err != nil {
		return
	}
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	z := utils.ConstReader(0)

	n, err := io.CopyN(mw, z, 1024)
	if err != nil {
		return
	}

	return n, digester.Digest(), file, nil
}

func mkRandFile(t *testing.T, dir string) (_ int64, _ digest.Digest, _ string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}

	fn := filepath.Join(dir, "plain")
	fh, err := os.Create(fn)
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()
	if err != nil {
		return
	}

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	r := rand.Reader

	n, err := io.CopyN(mw, r, 1024)
	if err != nil {
		return
	}

	return n, digester.Digest(), fn, nil
}

func mkConfigFile(t *testing.T, dir string) (_ int64, _ digest.Digest, _ string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}

	fn := filepath.Join(dir, "config")
	fh, err := os.Create(fn)
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()
	if err != nil {
		return
	}

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	b := bytes.NewReader(config)

	n, err := io.Copy(mw, b)
	if err != nil {
		return
	}

	return n, digester.Digest(), fn, nil
}

func showContents(t *testing.T, fn, decpath string) error {
	a := readFile(t, fn)
	b := readFile(t, decpath)
	return errors.Errorf("decryption is not inverting encryption:\nPlaintext: %v\nDecrypted: %v", a, b)
}

func readFile(t *testing.T, filename string) []byte {
	fh, err := os.Open(filename)
	if err != nil {
		return []byte(fmt.Sprintf("[could not read %s]", filename))
	}
	contents, err := ioutil.ReadAll(fh)
	if err != nil {
		return []byte(fmt.Sprintf("[could not read %s]", filename))
	}
	return contents
}
