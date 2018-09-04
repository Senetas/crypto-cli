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

package images

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/utils"
)

// constructImageArchive takes a manifest and creates a tarball that may be loaded with docker load.
// It downloads and decrypts the config and layers if necessary. In fact, only a reader of a tarball
// is return, with an error changed containing errors from writing the tar
func constructImageArchive(
	manifest *distribution.ImageManifest,
	ref auth.Scope,
	opts *crypto.Opts,
) (err error) {
	contents := make([]string, len(manifest.Layers)+2)
	contents[0] = "manifest.json"

	manifestfile := filepath.Join(manifest.DirName, contents[0])

	archiveManifest := &distribution.ArchiveManifest{
		RepoTags: []string{ref.String()},
		Config:   filepath.Base(manifest.Config.GetFilename()),
		Layers:   make([]string, len(manifest.Layers)),
	}

	contents[1] = archiveManifest.Config

	for i, l := range manifest.Layers {
		archiveManifest.Layers[i] = filepath.Base(l.GetFilename())
	}

	copy(contents[2:], archiveManifest.Layers)

	if err = writeArchiveManifestFile(manifestfile, archiveManifest); err != nil {
		return
	}

	pr, pw := io.Pipe()
	errCh := make(chan error, 3)
	defer close(errCh)

	go mkTar(manifest.DirName, contents, pw, errCh)

	if err = loadArchive(pr); err != nil {
		return
	}

	return utils.ConcatErrChan(errCh, 3)
}

func writeArchiveManifestFile(manifestfile string, archiveManifest *distribution.ArchiveManifest) (err error) {
	amFH, err := os.Create(manifestfile)
	if err != nil {
		err = utils.CheckedClose(amFH, errors.Wrapf(err, "filename = %s", manifestfile))
		return
	}
	defer func() { err = utils.CheckedClose(amFH, err) }()

	enc := json.NewEncoder(amFH)
	if err = enc.Encode(&[]*distribution.ArchiveManifest{archiveManifest}); err != nil {
		err = errors.Wrapf(err, "%#v", archiveManifest)
		return
	}

	return
}

func loadArchive(pr io.Reader) (err error) {
	// TODO: stop hardcoding version
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.37"))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	resp, err := cli.ImageLoad(context.Background(), pr, false)
	defer func() { err = utils.CheckedClose(resp.Body, err) }()
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	if resp.Body != nil && resp.JSON {
		dec := json.NewDecoder(resp.Body)

		message := make(map[string]interface{})
		for dec.More() {
			err = dec.Decode(&message)
			if err != nil {
				err = errors.WithStack(err)
				return
			}
		}

		msg, ok := message["stream"]
		if ok {
			msgStr, ok := msg.(string)
			if ok {
				log.Info().Msg(strings.TrimSpace(msgStr))
				return
			}
		}

		return errors.New("image load failed for unknown reasons")
	}

	_, err = io.Copy(os.Stderr, resp.Body)
	return utils.Errors{errors.New("filed to import image"), err}
}

func mkTar(dir string, contents []string, w io.WriteCloser, errCh chan<- error) {
	defer func() { errCh <- w.Close() }()
	tarball := tar.NewWriter(w)
	defer func() { errCh <- tarball.Close() }()

	var err error // err2 is needed below to prevent shadowing
	for _, src := range contents {
		fullpath := filepath.Join(dir, src)

		info, err2 := os.Stat(fullpath)
		if err2 != nil {
			err = errors.WithStack(err2)
			break
		}

		header, err2 := tar.FileInfoHeader(info, info.Name())
		if err2 != nil {
			err = errors.WithStack(err2)
			break
		}

		if err = tarball.WriteHeader(header); err != nil {
			err = errors.WithStack(err)
			break
		}

		// the only part of fullpath that may be varied by anadvesary is the digest
		// but we have explicitly validated that the digest is a digest previously.
		// of course the advsaery could replace both the file and the digest, but then
		// decryption will fail
		file, err2 := os.Open(fullpath) // #nosec
		defer func() { err = utils.CheckedClose(file, err) }()
		if err2 != nil {
			err = errors.WithStack(err2)
			break
		}

		_, err = io.Copy(tarball, file)
		if err != nil {
			err = errors.WithStack(err)
			break
		}
	}

	errCh <- err
}
