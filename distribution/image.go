// Copyright © 2018 SENETAS SECURITY PTY LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package distribution

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	pb "gopkg.in/cheggaaa/pb.v1"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry/names"
	"github.com/Senetas/crypto-cli/utils"
)

const (
	saltBase    = "com.senetas.crypto/%s/%s"
	configSalt  = saltBase + "/config"
	layerSalt   = saltBase + "/layer%d"
	labelString = "LABEL com.senetas.crypto.enabled"
)

var createdRE = `#\(nop\)\s+` + labelString + `=(true|false)|(#\(nop\))`

// ImageManifest represents a docker image manifest schema v2.2
type ImageManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        Blob   `json:"config"`
	Layers        []Blob `json:"layers"`
	DirName       string `json:"-"`
}

// NewManifest creates an unencrypted manifest (with the data necessary for encryption)
func NewManifest(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
	tempDir string,
) (
	manifest *ImageManifest,
	err error,
) {
	ctx := context.Background()

	// TODO: fix hardcoded version if necessary
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.37"))
	if err != nil {
		err = utils.StripTrace(errors.Wrap(err, "could not create client for docker daemon"))
		return
	}

	inspt, _, err := cli.ImageInspectWithRaw(ctx, ref.String())
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	imageTar, err := cli.ImageSave(ctx, []string{inspt.ID})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer func() { err = utils.CheckedClose(imageTar, err) }()

	layers, err := layersToEncrypt(ctx, cli, inspt)
	if err != nil {
		return
	}

	log.Debug().Msgf("The following layers are to be encrypted: %v", layers)

	// output manifest
	manifest = &ImageManifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeManifest,
		DirName:       filepath.Join(tempDir, uuid.New().String()),
	}

	// extract image
	if err = extractTarBall(imageTar, inspt.Size, manifest); err != nil {
		return
	}

	configBlob, layerBlobs, err := mkBlobs(ref.Path(), ref.Tag(), manifest.DirName, layers, opts)
	if err != nil {
		return
	}

	manifest.Config = configBlob
	manifest.Layers = layerBlobs

	return manifest, nil
}

func extractTarBall(r io.Reader, size int64, manifest *ImageManifest) (err error) {
	if err = os.MkdirAll(manifest.DirName, 0700); err != nil {
		err = errors.Wrapf(err, "could not create: %s", manifest.DirName)
		return
	}

	log.Info().Msg("Extracting image.")
	bar := pb.New64(0).SetUnits(pb.U_BYTES)
	tr := tar.NewReader(r)
	br := bar.NewProxyReader(tr)

	bar.Start()

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return errors.WithStack(err)
		}

		path := filepath.Join(manifest.DirName, header.Name)
		info := header.FileInfo()

		switch {
		case info.IsDir():
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			fallthrough
		case dontExtract(info.Name()):
			continue
		}

		fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			err = errors.WithStack(utils.CheckedClose(fh, err))
			return err
		}

		bar.SetTotal64(bar.Total + header.Size)

		_, err = io.Copy(fh, br)
		if err = utils.CheckedClose(fh, err); err != nil {
			return err
		}
	}

	bar.Finish()

	return nil
}

func dontExtract(name string) bool {
	return name == "json" || name == "VERSION" || name == "repositories"
}

// TODO: find a way to do this by interfacing with the daemon directly
func mkBlobs(
	repo, tag, path string,
	layers []string,
	opts *crypto.Opts,
) (
	configBlob Blob,
	layerBlobs []Blob,
	err error,
) {
	// assemble layers
	layerSet := make(map[string]bool)
	for _, x := range layers {
		layerSet[x] = true
	}

	// read the archive manifest
	manifestfile := filepath.Join(path, "manifest.json")
	manifestFH, err := os.Open(manifestfile)
	defer func() { err = utils.CheckedClose(manifestFH, err) }()
	if err != nil {
		err = errors.Wrapf(err, "could not open file: %s", manifestfile)
		return
	}

	image, err := mkArchiveStruct(path, manifestFH)
	if err != nil {
		return
	}

	switch opts.EncType {
	case crypto.Pbkdf2Aes256Gcm:
		return pbkdf2Aes256GcmEncrypt(path, layerSet, image, opts)
	case crypto.None:
		return noneEncrypt(path, layerSet, image, opts)
	default:
	}
	return nil, nil, errors.Errorf("%v is not a valid encryption type", opts.EncType)
}

func noneEncrypt(
	path string,
	layerSet map[string]bool,
	image *archiveStruct,
	opts *crypto.Opts,
) (
	Blob,
	[]Blob,
	error,
) {
	layerBlobs := make([]Blob, len(image.Layers))
	configBlob := NewPlainConfig(filepath.Join(path, image.Config), "", 0)
	for i, f := range image.Layers {
		layerBlobs[i] = NewPlainLayer(filepath.Join(path, f), "", 0)
	}
	return configBlob, layerBlobs, nil
}

func pbkdf2Aes256GcmEncrypt(
	path string,
	layerSet map[string]bool,
	image *archiveStruct,
	opts *crypto.Opts,
) (
	_ Blob,
	_ []Blob,
	err error,
) {
	// make the config
	dec, err := NewDecrypto(opts)
	if err != nil {
		return nil, nil, err
	}
	configBlob := NewConfig(filepath.Join(path, image.Config), "", 0, dec)

	layerBlobs := make([]Blob, len(image.Layers))
	for i, f := range image.Layers {
		basename := filepath.Join(path, f)

		dec, err := NewDecrypto(opts)
		if err != nil {
			return nil, nil, err
		}

		d, err := fileDigest(basename)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		log.Debug().Msgf("preparing %s", d)
		if layerSet[d.String()] {
			layerBlobs[i] = NewLayer(filepath.Join(path, f), d, 0, dec)
		} else {
			layerBlobs[i] = NewPlainLayer(filepath.Join(path, f), d, 0)
		}
	}

	return configBlob, layerBlobs, nil
}

func fileDigest(filename string) (d digest.Digest, err error) {
	fh, err := os.Open(filename)
	defer func() { err = utils.CheckedClose(fh, err) }()
	if err != nil {
		return
	}
	return digest.Canonical.FromReader(fh)
}

func layersToEncrypt(ctx context.Context, cli *client.Client, inspt types.ImageInspect) ([]string, error) {
	// get the history
	hist, err := cli.ImageHistory(ctx, inspt.ID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// the positions of the layers to encrypt
	eps, err := encryptPositions(hist)
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("%v", eps)
	log.Debug().Msgf("%v", inspt.RootFS.Layers)

	// the total number of layers
	diffIDsToEncrypt := make([]string, len(eps))
	for i, n := range eps {
		diffIDsToEncrypt[i] = inspt.RootFS.Layers[n]
	}

	log.Debug().Msgf("%v", diffIDsToEncrypt)

	// the last n entries in this array are the diffIDs of the layers to encrypt
	return diffIDsToEncrypt, nil
}

func encryptPositions(hist []image.HistoryResponseItem) (encryptPos []int, err error) {
	n := 0
	toEncrypt := false
	re := regexp.MustCompile(createdRE)

	for i := len(hist) - 1; i >= 0; i-- {
		matches := re.FindSubmatch([]byte(hist[i].CreatedBy))

		if hist[i].Size != 0 || len(matches) == 0 {
			if toEncrypt {
				encryptPos = append(encryptPos, n)
			}
			n++
		} else {
			switch string(matches[1]) {
			case "true":
				toEncrypt = true
			case "false":
				toEncrypt = false
			default:
			}
		}
	}

	if len(encryptPos) == 0 {
		err = utils.NewError("this image was not built with the correct LABEL", false)
		return
	}

	return encryptPos, nil
}

type archiveStruct struct {
	Config string
	Layers []string
}

func mkArchiveStruct(path string, manifestFH io.Reader) (a *archiveStruct, err error) {
	var images []*archiveStruct
	dec := json.NewDecoder(manifestFH)
	if err = dec.Decode(&images); err != nil {
		err = errors.Wrapf(err, "error unmarshalling manifest")
		return
	}

	if len(images) < 1 {
		err = errors.New("no image data was found")
		return
	}

	return images[0], nil
}

func unencryptedConfig(blob *NoncryptedBlob) (_ Blob, err error) {
	digester := digest.Canonical.Digester()
	r, err := blob.ReadCloser()
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	size, err := io.Copy(digester.Hash(), r)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	d := digester.Digest()
	return NewPlainConfig(blob.GetFilename(), d, size), nil
}

func prepareConfig(config Blob, opts *crypto.Opts, ref names.NamedTaggedRepository) (Blob, error) {
	switch blob := config.(type) {
	case DecryptedBlob:
		log.Debug().Msg("encrypting config")
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		return blob.EncryptBlob(opts, blob.GetFilename()+".aes")
	case *NoncryptedBlob:
		log.Debug().Msgf("preparing config")
		return unencryptedConfig(blob)
	}
	return nil, errors.New("config is of wrong type")
}

// Encrypt an image, generating an image manifest suitable for upload to a repo
func (m *ImageManifest) Encrypt(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
) (
	_ *ImageManifest,
	err error,
) {
	configBlob, err := prepareConfig(m.Config, opts, ref)
	if err != nil {
		return nil, err
	}

	layerBlobs := make([]Blob, len(m.Layers))
	for i, l := range m.Layers {
		switch blob := l.(type) {
		case DecryptedBlob:
			log.Debug().Msgf("encrypting layer %d", i)
			opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			layerBlobs[i], err = blob.EncryptBlob(opts, blob.GetFilename()+".aes")
		case *NoncryptedBlob:
			log.Debug().Msgf("compressing layer %d", i)
			layerBlobs[i], err = blob.Compress(blob.GetFilename() + ".gz")
		default:
		}
		if err != nil {
			return nil, err
		}
	}

	return &ImageManifest{
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		DirName:       m.DirName,
		Config:        configBlob,
		Layers:        layerBlobs,
	}, nil
}

// DecryptKeys attempts to decrypt all keys in a manifest
func (m *ImageManifest) DecryptKeys(
	opts *crypto.Opts,
	ref names.NamedTaggedRepository,
) (err error) {
	switch blob := m.Config.(type) {
	case EncryptedBlob:
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		m.Config, err = blob.DecryptKey(opts)
		if err != nil {
			return err
		}
	case *NoncryptedBlob:
	default:
		return errors.New("mainfest blobs are of wrong type")
	}

	for i, l := range m.Layers {
		switch blob := l.(type) {
		case EncryptedBlob:
			opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			m.Layers[i], err = blob.DecryptKey(opts)
			if err != nil {
				return err
			}
		case *NoncryptedBlob:
		default:
			return errors.New("mainfest blobs are of wrong type")
		}
	}
	return nil
}

// Decrypt attempts to decrypt a manifest
func (m *ImageManifest) Decrypt(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
) (out *ImageManifest, err error) {
	out = &ImageManifest{
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		Layers:        make([]Blob, len(m.Layers)),
		DirName:       m.DirName,
	}

	switch blob := m.Config.(type) {
	case EncryptedBlob:
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		out.Config, err = blob.DecryptBlob(opts, blob.GetFilename()+".dec")
	case KeyDecryptedBlob:
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		out.Config, err = blob.DecryptFile(opts, blob.GetFilename()+".dec")
	case *NoncryptedBlob:
		out.Config = blob
	default:
		err = errors.Errorf("manifest is not decryptable: %T", m.Config)
	}
	if err != nil {
		return
	}

	// decrypt keys and files for layers
	for i, l := range m.Layers {
		out.Layers[i], err = decryptLayer(ref, opts, l, i)
		if err != nil {
			return
		}
	}

	return
}

func decryptLayer(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
	l Blob,
	i int,
) (layer Blob, err error) {
	switch blob := l.(type) {
	case EncryptedBlob:
		opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
		layer, err = blob.DecryptBlob(opts, blob.GetFilename()+".dec")
	case KeyDecryptedBlob:
		opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
		layer, err = blob.DecryptFile(opts, blob.GetFilename()+".dec")
	case CompressedBlob:
		layer, err = blob.Decompress(blob.GetFilename() + ".dec")
	case *NoncryptedBlob:
		layer = l
	}
	return
}
