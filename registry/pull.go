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

package registry

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	"github.com/docker/docker/registry"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// PullImage pulls an image from a remote repository
func PullImage(token string, ref reference.Named, endpoint *registry.APIEndpoint) (*types.ImageManifestJSON, error) {
	bldr := v2.NewURLBuilder(endpoint.URL, false)

	manifest, err := PullManifest(token, ref, bldr)
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("Obtaining config: %s\n", manifest.Config.Digest)
	manifest.Config.Filename, err = PullFromDigest(token, ref, manifest.Config.Digest, bldr)
	if err != nil {
		return nil, err
	}

	log.Info().Msg("Obtaining layers:")
	for _, l := range manifest.Layers {
		log.Info().Msgf("Obtaining layer: %s", l.Digest)
		l.Filename, err = PullFromDigest(token, ref, l.Digest, bldr)
		if err != nil {
			return nil, err
		}
	}

	return manifest, nil
}

// PullManifest pulls a manifest from the registry and parses it
func PullManifest(token string, ref reference.Named, bldr *v2.URLBuilder) (manifest *types.ImageManifestJSON, err error) {
	urlStr, err := bldr.BuildManifestURL(ref)
	if err != nil {
		return nil, errors.Wrapf(err, "ref = %v", ref)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	// TODO: Handle list manifests
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := doRequest(client, req, true, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body, err)
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("manifest download failed with status: " + resp.Status)
	}

	body := json.NewDecoder(resp.Body)
	manifest = &types.ImageManifestJSON{}
	if err = body.Decode(manifest); err != nil {
		return nil, err
	}

	return manifest, nil
}

// PullFromDigest downloads a blob (refereced by its digest) from the registry to a temporay file.
// It verifies that the downloaded matches its digest, deleting if if it does not
func PullFromDigest(token string, ref reference.Named, d *digest.Digest, bldr *v2.URLBuilder) (fn string, err error) {
	sep := SeperateRepository(ref)
	can := digestedReference{sep, *d}

	urlStr, err := bldr.BuildBlobURL(can)
	if err != nil {
		return "", errors.Wrapf(err, "%#v", ref)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.docker.image.rootfs.diff.tar.gzip")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := doRequest(client, req, true, false)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Failed to download blob " + d.String())
	}

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto")
	if err = os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	fn = filepath.Join(dir, d.Encoded())
	fh, err := os.Create(fn)
	if err != nil {
		return "", err
	}
	defer func() {
		err = utils.CheckedClose(fh, err)
	}()

	vw := d.Verifier()
	mw := io.MultiWriter(vw, fh)

	if _, err = io.Copy(mw, resp.Body); err != nil {
		return "", err
	}

	if err = resp.Body.Close(); err != nil {
		return "", err
	}

	if !vw.Verified() {
		return quitUnVerified(fn, fh, err)
	}

	return fn, nil
}

func quitUnVerified(fn string, fh *os.File, err error) (string, error) {
	if err2 := os.Remove(fn); err != nil {
		return "", errors.Wrapf(utils.CombineErr([]error{err, err2}), "digest verification failed, and unverified was NOT delete. To clean manaually delete: %s", fn)
	}
	if err2 := fh.Close(); err2 != nil {
		return "", errors.Wrap(utils.CombineErr([]error{err, err2}), "digest verification failed, failed to close, but unverified data was deleted")
	}
	return "", errors.Wrapf(err, "digest verification failed, unverified data deleted")
}
