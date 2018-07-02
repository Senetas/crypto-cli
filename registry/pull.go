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
	"errors"
	"io"
	"net/http"
	"os"
	//"net/http/httputil"
	"net/url"

	digest "github.com/opencontainers/go-digest"

	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// PullManifest pulls a manifest from the registry and parses it
func PullManifest(user, repo, tag, token string) (manifest *types.ImageManifestJSON, err error) {
	regAddr := "registry-1.docker.io"
	regPath := "v2"

	u := url.URL{
		Scheme: "https",
		Host:   regAddr,
		Path:   regPath + "/" + repo + "/manifests/" + tag}

	client := &http.Client{}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	// TODO: Handle list manifests
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Authorization", "Bearer "+token)

	//dump, err := httputil.DumpRequest(req, true)
	//if err != nil {
	//return nil, err
	//}
	//fmt.Println(string(dump))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
	}()

	//dump, err = httputil.DumpResponse(resp, true)
	//if err != nil {
	//return nil, err
	//}
	//fmt.Println(string(dump))

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("manifest upload failed with status: " + resp.Status)
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
func PullFromDigest(user, repo, token string, d *digest.Digest) (fn string, err error) {
	regAddr := "registry-1.docker.io"
	regPath := "v2"

	u := url.URL{
		Scheme: "https",
		Host:   regAddr,
		Path:   regPath + "/" + repo + "/blobs/" + d.String()}

	client := &http.Client{}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.docker.image.rootfs.diff.tar.gzip")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Authorization", "Bearer "+token)

	//dump, err := httputil.DumpRequest(req, true)
	//if err != nil {
	//return "", err
	//}
	//fmt.Println(string(dump))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		err = resp.Body.Close()
	}()

	//dump, err := httputil.DumpResponse(resp, false)
	//if err != nil {
	//return "", err
	//}
	//fmt.Println(string(dump))

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Failed to download blob" + d.String())
	}

	dir := os.TempDir() + "/com.senetas.crypto"

	fn = dir + "/" + d.Encoded()
	fh, err := os.Create(fn)
	if err != nil {
		return "", err
	}
	defer func() {
		err = utils.CheckedClose(fh, err)
	}()

	pr, pw := io.Pipe()
	tr := io.TeeReader(resp.Body, pw)
	vw := d.Verifier()

	done := make(chan int64)
	errChan := make(chan error)
	defer close(done)
	defer close(errChan)

	go func() {
		var err2 error
		defer func() {
			err2 = pw.Close()
		}()

		n, err2 := io.Copy(fh, tr)

		errChan <- err2
		done <- n
	}()

	go func() {
		n, err2 := io.Copy(vw, pr)

		errChan <- err2
		done <- n
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			return "", err
		}
		<-done
	}

	if !vw.Verified() {
		return quitUnVerified(fn, fh, err)
	}

	return fn, nil
}

func quitUnVerified(fn string, fh *os.File, err error) (string, error) {
	_ = fh.Close()
	err2 := errors.New("could not verify digest")
	if err3 := os.Remove(fn); err3 != nil {
		return "", utils.CombineErr([]error{err, err2, err3})
	}
	return "", err
}
