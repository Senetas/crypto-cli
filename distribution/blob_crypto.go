package distribution

import (
	"compress/gzip"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/minio/sio"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

// EncFile encrypts the file inName to outName with a random 32 byte key. returns the key
// assumes infile and outfile use they system seperator
func encFile(in io.Writer, key []byte) (io.WriteCloser, error) {
	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          key,
	}

	out, err := sio.EncryptWriter(in, cfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return out, nil
}

// DecFile decrypts (and authenticates) infile and writes it to outfile
// only persists if the decrypttion and authentication suceedes
// assumes infile and outfile use they system seperator
func decFile(in io.Reader, datakey []byte) (io.Reader, error) {
	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          datakey,
	}

	out, err := sio.DecryptReader(in, cfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return out, nil
}

func (eb *encryptedBlobNew) DecryptBlob(opts crypto.Opts, outname string) (db DecryptedBlob, err error) {
	dk, err := DecryptKey(*eb.EnCrypto, opts)
	if err != nil {
		return nil, err
	}

	r, err := db.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	dec, err := decFile(r, dk.DecKey)
	if err != nil {
		return nil, err
	}

	zr, err := gzip.NewReader(dec)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err = os.MkdirAll(filepath.Dir(outname), 0700); err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := os.Create(outname)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	n, err := io.Copy(mw, zr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	return &decryptedBlob{
		NoncryptedBlob: &NoncryptedBlob{
			Filename:    outname,
			Size:        n,
			ContentType: eb.ContentType,
			Digest:      &dgst,
		},
		DeCrypto: &dk,
	}, nil
}

func (e *encryptedBlobCompat) DecryptBlob(opts crypto.Opts, outname string) (DecryptedBlob, error) {
	if len(e.URLs) == 0 {
		return nil, errors.New("missing encryption key")
	}

	u, err := url.Parse(e.URLs[0])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	algos, err := crypto.ValidateAlgos(u.Query().Get(AlgosKey))
	if err != nil {
		return nil, err
	}

	ek := &EnCrypto{
		Algos:  algos,
		EncKey: u.Query().Get(KeyKey),
	}

	eb := &encryptedBlobNew{
		NoncryptedBlob: e.NoncryptedBlob,
		EnCrypto:       ek,
	}

	return eb.DecryptBlob(opts, outname)
}

// EncryptBlob encrypts the key for the layer
func (db *decryptedBlob) EncryptBlob(opts crypto.Opts, outname string) (eb EncryptedBlob, err error) {
	if err := os.MkdirAll(filepath.Dir(outname), 0700); err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := os.Create(outname)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	ew, err := encFile(mw, db.DecKey)
	if err != nil {
		return nil, err
	}

	zw := gzip.NewWriter(ew)

	r, err := db.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	n, err := io.Copy(zw, r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	ek, err := EncryptKey(*db.DeCrypto, opts)
	if err != nil {
		return nil, err
	}

	nb := &NoncryptedBlob{
		Filename:    outname,
		Size:        n,
		ContentType: db.ContentType,
		Digest:      &dgst,
	}

	if opts.Compat {
		u, err := url.Parse(BaseCryptoURL)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		v := url.Values{}
		v.Set(AlgosKey, string(ek.Algos))
		v.Set(KeyKey, ek.EncKey)
		u.RawQuery = v.Encode()

		return &encryptedBlobCompat{
			NoncryptedBlob: nb,
			URLs:           []string{u.String()},
		}, nil
	}

	return &encryptedBlobNew{
		NoncryptedBlob: nb,
		EnCrypto:       &ek,
	}, nil
}

func (ub *NoncryptedBlob) Compress(outfile string) (cb CompressedBlob, err error) {
	if err := os.MkdirAll(filepath.Dir(outfile), 0700); err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := os.Create(outfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	r, err := ub.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	size, err := io.Copy(mw, zr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	return &NoncryptedBlob{
		Filename:    outfile,
		Size:        size,
		ContentType: ub.ContentType,
		Digest:      &dgst,
	}, nil
}

func (cb *NoncryptedBlob) Decompress(outfile string) (db DecompressedBlob, err error) {
	if err := os.MkdirAll(filepath.Dir(outfile), 0700); err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := os.Create(outfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)
	zw := gzip.NewWriter(mw)

	r, err := db.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	size, err := io.Copy(zw, r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	return &NoncryptedBlob{
		Filename:    outfile,
		Size:        size,
		ContentType: cb.ContentType,
		Digest:      &dgst,
	}, nil
}
