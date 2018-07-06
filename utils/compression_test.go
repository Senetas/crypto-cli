package utils_test

import (
	_ "crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/utils"
)

var (
	dir  = filepath.Join(os.TempDir(), "com.senetas.crypto")
	file = filepath.Join(dir, "temp")
)

func createTempFile(t *testing.T) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}

	buf := [1]byte{125}
	for i := 1; i <= 1024; i++ {
		fh.Write(buf[:])
		//buf[0] = byte(i)
	}
}

func TestCompDecomp(t *testing.T) {
	createTempFile(t)

	_, err := utils.CompressWithDigest(file)
	if err != nil {
		t.Fatal(err)
	}

	_, err = utils.Decompress(file + ".gz")
	if err != nil {
		t.Fatal(err)
	}

	cmp := equalfile.New(nil, equalfile.Options{})
	equal, err := cmp.CompareFile(file, file+".gz.dec")
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	if !equal {
		t.Fatalf("inversion failure")
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}
}

func TestCompDigest(t *testing.T) {
	createTempFile(t)

	d, err := utils.CompressWithDigest(file)
	if err != nil {
		t.Fatal(err)
	}

	v := d.Verifier()
	fh, err := os.Open(file + ".gz")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = io.Copy(v, fh); err != nil {
		t.Fatal(err)
	}

	if !v.Verified() {
		t.Fatal(errors.New("digests failed to match"))
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}
}

func TestDecompDigest(t *testing.T) {
	createTempFile(t)

	_, err := utils.CompressWithDigest(file)
	if err != nil {
		t.Fatal(err)
	}

	d, err := utils.Decompress(file + ".gz")
	if err != nil {
		t.Fatal(err)
	}

	v := d.Verifier()
	fh, err := os.Open(file + ".gz.dec")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(v, fh); err != nil {
		t.Fatal(err)
	}

	if !v.Verified() {
		t.Fatal(errors.New("digests failed to match"))
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}
}
