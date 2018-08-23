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
	"bytes"
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
) (
	pr io.ReadCloser,
	err error,
) {
	newDir := filepath.Join(manifest.DirName, "new")
	if err = os.MkdirAll(newDir, 0700); err != nil {
		err = errors.Wrapf(err, "dir name = %s", newDir)
		return
	}

	newConfig := utils.FilePathSansExt(filepath.Base(manifest.Config.GetFilename())) + ".json"
	archiveManifest := &distribution.ArchiveManifest{
		RepoTags: []string{ref.String()},
		Config:   newConfig,
		Layers:   make([]string, len(manifest.Layers)),
	}

	if err = os.Rename(manifest.Config.GetFilename(), filepath.Join(newDir, newConfig)); err != nil {
		err = errors.WithStack(err)
		return
	}

	for i, l := range manifest.Layers {
		base := utils.FilePathSansExt(filepath.Base(l.GetFilename()))
		layerDir := filepath.Join(newDir, base)
		archiveManifest.Layers[i] = filepath.Join(base, "layer.tar")

		if err = os.MkdirAll(layerDir, 0700); err != nil {
			err = errors.WithStack(err)
			return
		}

		if err = os.Rename(
			l.GetFilename(),
			filepath.Join(newDir, archiveManifest.Layers[i]),
		); err != nil {
			err = errors.WithStack(err)
			return
		}
	}

	manifestfile := filepath.Join(newDir, "manifest.json")

	amFH, err := os.Create(manifestfile)
	defer func() { err = utils.CheckedClose(amFH, err) }()
	if err != nil {
		err = errors.Wrapf(err, "filename = %s", manifestfile)
		return
	}

	enc := json.NewEncoder(amFH)
	if err = enc.Encode(&[]*distribution.ArchiveManifest{archiveManifest}); err != nil {
		err = errors.Wrapf(err, "%#v", archiveManifest)
		return
	}

	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	defer close(errCh)

	go tarit(newDir, pw, errCh)

	fh, err := os.Create(filepath.Join(manifest.DirName, "new.tar"))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	go func() {
		_, _ = io.Copy(fh, pr)
		//errCh <- err
	}()

	for i := 0; i < 2; i++ {
		err = <-errCh
		if err != nil {
			return
		}
	}

	fh2, err := os.Open(filepath.Join(manifest.DirName, "new.tar"))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	// TODO: stop hardcoding version
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.37"))
	if err != nil {
		err = errors.Wrapf(err, "could not load client: %v", client.FromEnv)
		return
	}

	resp, err := cli.ImageLoad(context.Background(), fh2, false)
	defer func() { err = utils.CheckedClose(resp.Body, err) }()
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	var b bytes.Buffer
	if _, err = io.Copy(&b, resp.Body); err != nil {
		return
	}

	log.Debug().Msg(b.String())

	return
}

func tarit(source string, w io.Writer, errCh chan<- error) {
	tarball := tar.NewWriter(w)
	defer func() { errCh <- tarball.Close() }()

	errCh <- filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			header.Name = strings.TrimPrefix(path, source)

			if err = tarball.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { err = utils.CheckedClose(file, err) }()

			_, err = io.Copy(tarball, file)

			return err
		},
	)
}
