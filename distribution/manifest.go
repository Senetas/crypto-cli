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

const labelString = "LABEL com.senetas.crypto.enabled"

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
		err = errors.Wrap(err, "could not create client for docker daemon")
		return
	}

	// run docker inspect to optain the image ID
	inspt, _, err := cli.ImageInspectWithRaw(ctx, ref.String())
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	// docker save the image (as a ReadCloser)
	imageTar, err := cli.ImageSave(ctx, []string{inspt.ID})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer func() { err = utils.CheckedClose(imageTar, err) }()

	// determine which layers need to be encrypted
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

	// extract image and fill out manifest
	if err = extractTarBall(imageTar, inspt.Size, manifest); err != nil {
		return
	}

	// make the Blob structs for the manifest
	manifest.Config, manifest.Layers, err = mkBlobs(
		ref.Path(),
		ref.Tag(),
		manifest.DirName,
		layers,
		opts,
	)

	return
}

// Encrypt an image, generating an image manifest suitable for upload to a repo
func (m *ImageManifest) Encrypt(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
) (
	out *ImageManifest,
	err error,
) {
	out = &ImageManifest{
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		DirName:       m.DirName,
		Layers:        make([]Blob, len(m.Layers)),
	}

	out.Config, err = prepareConfig(m.Config, opts, ref)
	if err != nil {
		return
	}

	for i, l := range m.Layers {
		switch blob := l.(type) {
		case DecryptedBlob:
			log.Debug().Msgf("encrypting layer %d: %s", i, blob.GetFilename())
			out.Layers[i], err = blob.EncryptBlob(opts, blob.GetFilename()+".aes")
		case *NoncryptedBlob:
			log.Debug().Msgf("compressing layer %d: %s", i, blob.GetFilename())
			out.Layers[i], err = blob.Compress(blob.GetFilename() + ".gz")
		default:
		}
		if err != nil {
			return
		}
	}
	return
}

// DecryptKeys decrypts all keys in a manifest
func (m *ImageManifest) DecryptKeys(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
) (err error) {
	switch blob := m.Config.(type) {
	case EncryptedBlob:
		m.Config, err = blob.DecryptKey(opts)
	case *NoncryptedBlob:
	default:
		err = errors.Errorf("config is of wrong type: %T", blob)
	}
	if err != nil {
		return
	}

	for i := 0; i < len(m.Layers) && err == nil; i++ {
		switch blob := m.Layers[i].(type) {
		case EncryptedBlob:
			m.Layers[i], err = blob.DecryptKey(opts)
		case *NoncryptedBlob:
		default:
			err = errors.Errorf("layer is of wrong type: %T", blob)
		}
	}

	return
}

// Decrypt decrypt a manifest, both the keys and layer data
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
		out.Config, err = blob.DecryptBlob(opts, blob.GetFilename()+".dec")
	case KeyDecryptedBlob:
		out.Config, err = blob.DecryptFile(opts, blob.GetFilename()+".dec")
	case *NoncryptedBlob:
		out.Config = blob
	default:
		err = errors.Errorf("config is of wrong type: %T", blob)
	}
	if err != nil {
		return
	}

	// decrypt keys and files for layers
	out.Layers = make([]Blob, len(m.Layers))
	for i := 0; i < len(m.Layers) && err == nil; i++ {
		out.Layers[i], err = decryptLayer(ref, opts, m.Layers[i])
	}

	return
}

// extractTarBall extracts the tarball from a docker save and fills out the
// provided image manifest that with details about the layers
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
	defer bar.Finish()

	for {
		var header *tar.Header
		header, err = tr.Next()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return errors.WithStack(err)
		}

		path := filepath.Join(manifest.DirName, header.Name)
		info := header.FileInfo()

		switch {
		case info.IsDir():
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return errors.WithStack(err)
			}
			fallthrough
		case dontExtract(info.Name()):
			continue
		}

		bar.SetTotal64(bar.Total + header.Size)

		if err = mkFile(path, info, br); err != nil {
			return err
		}
	}
}

// dontExtract holds the names of the file int the image archive to not extract
func dontExtract(name string) bool {
	return name == "json" || name == "VERSION" || name == "repositories"
}

// mkFile makes the file in extractTarBall
func mkFile(path string, info os.FileInfo, r io.Reader) (err error) {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
	defer func() { err = utils.CheckedClose(fh, err) }()
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	if _, err = io.Copy(fh, r); err != nil {
		err = errors.WithStack(err)
		return
	}
	return
}

// mkBlobs assembles the list of filenames that contains the layers of the image
// into a struct that contain additional information such as their digest
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
	// manifestfile consists of information that is local to the os, or supplied by the user or the
	// docker daemon. Thus, assuming they are not comprimised, it is safe to open
	manifestfile := filepath.Join(path, "manifest.json")
	manifestFH, err := os.Open(manifestfile) // #nosec
	defer func() { err = utils.CheckedClose(manifestFH, err) }()
	if err != nil {
		err = errors.Wrapf(err, "could not open file: %s", manifestfile)
		return
	}

	image, err := NewImageArchiveManifest(manifestFH)
	if err != nil {
		return
	}

	switch opts.Algos {
	case crypto.Pbkdf2Aes256Gcm:
		return pbkdf2Aes256GcmEncrypt(path, layerSet, image, opts)
	case crypto.None:
		return noneEncrypt(path, layerSet, image, opts)
	default:
	}
	return nil, nil, errors.Errorf("%v is not a valid encryption type", opts.Algos)
}

// noneEncrypt encrypts the images's Blob structs when the enctype is NONE
// (i.e. no encryption)
func noneEncrypt(
	path string,
	layerSet map[string]bool,
	image *ImageArchiveManifest,
	opts *crypto.Opts,
) (
	configBlob Blob,
	layerBlobs []Blob,
	_ error,
) {
	layerBlobs = make([]Blob, len(image.Layers))
	configBlob = NewPlainConfig(filepath.Join(path, image.Config), "", 0)
	for i, f := range image.Layers {
		layerBlobs[i] = NewPlainLayer(filepath.Join(path, f), "", 0)
	}
	return
}

// pbkdf2Aes256GcmEncrypt encrypts the images's Blob structs when the enctype
// is Pbkdf2Aes256Gcm
func pbkdf2Aes256GcmEncrypt(
	path string,
	layerSet map[string]bool,
	image *ImageArchiveManifest,
	opts *crypto.Opts,
) (
	configBlob Blob,
	layerBlobs []Blob,
	err error,
) {
	// make the config
	var dec *crypto.DeCrypto
	dec, err = crypto.NewDecrypto(opts)
	if err != nil {
		return
	}
	configBlob = NewConfig(filepath.Join(path, image.Config), "", 0, dec)

	layerBlobs = make([]Blob, len(image.Layers))
	for i, f := range image.Layers {
		basename := filepath.Join(path, f)

		dec, err = crypto.NewDecrypto(opts)
		if err != nil {
			return
		}

		var d digest.Digest
		d, err = fileDigest(basename)
		if err != nil {
			err = errors.WithStack(err)
			return
		}

		log.Debug().Msgf("preparing %s", d)
		if layerSet[d.String()] {
			layerBlobs[i] = NewLayer(filepath.Join(path, f), d, 0, dec)
		} else {
			layerBlobs[i] = NewPlainLayer(filepath.Join(path, f), d, 0)
		}
	}

	return
}

// fileDigest calculates the digest of the file at location filename
// note its error are not wraped
func fileDigest(filename string) (d digest.Digest, err error) {
	// filename consists of information that is local to the os or the docker
	// daemon. Thus assuming they are not comprimised, it is safe to open
	fh, err := os.Open(filename) // #nosec
	defer func() { err = utils.CheckedClose(fh, err) }()
	if err != nil {
		return
	}
	return digest.Canonical.FromReader(fh)
}

// layersToEncrypt returns the diffIDs of the layers that have been marked for encryption
func layersToEncrypt(
	ctx context.Context,
	cli *client.Client,
	inspt types.ImageInspect,
) (_ []string, err error) {
	// get the history
	hist, err := cli.ImageHistory(ctx, inspt.ID)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	// the positions of the layers to encrypt
	eps, err := encryptPositions(hist)
	if err != nil {
		return
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

// encryptPositions gives the positions in the image history that correspond to encrypted layers
// the length of the output array is the number of layers that are to be encrypted
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
		err = errors.New("this image was not built with the correct LABEL")
		return
	}

	return
}

// ImageArchiveManifest collects the filenames of the config and layers in the image
// archive obtained from a docker save command
type ImageArchiveManifest struct {
	Config string
	Layers []string
}

// NewImageArchiveManifest reads a image archive manifest file
func NewImageArchiveManifest(manifestFH io.Reader) (a *ImageArchiveManifest, err error) {
	var images []*ImageArchiveManifest
	if err = json.NewDecoder(manifestFH).Decode(&images); err != nil {
		err = errors.Wrapf(err, "error unmarshalling manifest")
		return
	}

	if len(images) < 1 {
		err = errors.New("no image data was found")
		return
	}

	return images[0], nil
}

// creates a blob a blob that contains a config
func prepareConfig(
	config Blob,
	opts *crypto.Opts,
	ref names.NamedTaggedRepository,
) (
	_ Blob,
	err error,
) {
	switch blob := config.(type) {
	case DecryptedBlob:
		log.Debug().Msg("encrypting config")
		return blob.EncryptBlob(opts, blob.GetFilename()+".aes")
	case *NoncryptedBlob:
		log.Debug().Msgf("preparing config")
		return unencryptedConfig(blob)
	}
	err = errors.Errorf("config is of wrong type: %T", config)
	return
}

// unencryptedConfig creates a blob that contains an unencrypted config
func unencryptedConfig(blob *NoncryptedBlob) (_ Blob, err error) {
	r, err := blob.ReadCloser()
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	digester := digest.Canonical.Digester()
	size, err := io.Copy(digester.Hash(), r)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	return NewPlainConfig(blob.GetFilename(), digester.Digest(), size), nil
}

// decryptLayer decides whether to decrypt or decompress the layer
func decryptLayer(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
	l Blob,
) (layer Blob, err error) {
	switch blob := l.(type) {
	case EncryptedBlob:
		layer, err = blob.DecryptBlob(opts, blob.GetFilename()+".dec")
	case KeyDecryptedBlob:
		layer, err = blob.DecryptFile(opts, blob.GetFilename()+".dec")
	case CompressedBlob:
		layer, err = blob.Decompress(blob.GetFilename() + ".dec")
	default:
		err = errors.Errorf("layer is of wrong type: %T", blob)
	}
	return
}
