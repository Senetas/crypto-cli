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
	"net/url"
	"os"
	"strconv"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	dauth "github.com/docker/distribution/registry/client/auth"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry/auth"
	"github.com/Senetas/crypto-cli/registry/httpclient"
	"github.com/Senetas/crypto-cli/registry/names"
	"github.com/Senetas/crypto-cli/utils"
)

// PushImage pushes the config, layers and mainifest to the nominated registry, in that order
func PushImage(
	token dauth.Scope,
	ref reference.Named,
	manifest *distribution.ImageManifest,
	endpoint *registry.APIEndpoint,
) error {
	trimed := names.TrimNamed(ref)

	if err := PushLayer(token, trimed, manifest.Config, endpoint); err != nil {
		return err
	}
	for _, l := range manifest.Layers {
		if err := PushLayer(token, trimed, l, endpoint); err != nil {
			return err
		}
	}
	log.Info().Msg("Layers and config uploaded successfully")

	mdigest, err := PushManifest(token, ref, manifest, endpoint)
	if err != nil {
		return err
	}
	log.Info().Msgf("Successfully uploaded manifest with digest: %s", mdigest)

	return nil
}

// PushManifest puts a manifest on the registry
func PushManifest(
	token dauth.Scope,
	ref reference.Named,
	manifest *distribution.ImageManifest,
	endpoint *registry.APIEndpoint,
) (string, error) {
	builder := v2.NewURLBuilder(endpoint.URL, false)
	urlStr, err := builder.BuildManifestURL(ref)
	if err != nil {
		return "", errors.Wrapf(err, "ref = %v", ref)
	}

	// a pipe allows using the struct directly as the http body
	// w/o copying to a buffer
	pr, pw := io.Pipe()
	errChan := make(chan error, 1)
	defer close(errChan)
	go func() {
		defer func() { errChan <- pw.Close() }()
		enc := json.NewEncoder(pw)
		enc.SetIndent("", "\t")
		errChan <- enc.Encode(manifest)
	}()

	req, err := http.NewRequest("PUT", urlStr, pr)
	if err != nil {
		return "", errors.Wrapf(err, "url = %v", urlStr)
	}

	req.Header.Set("Accept", "application/json, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Content-Type", distribution.MediaTypeManifest)
	auth.AddToReqest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	if err != nil {
		return "", err
	}
	defer func() { err = utils.CheckedClose(resp.Body, err) }()

	// close the channel after request is done
	if err = utils.ConcatErrChan(errChan, 2); err != nil {
		return "", errors.WithStack(err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("manifest upload failed with status: " + resp.Status)
	}

	return resp.Header.Get("Docker-Content-Digest"), nil
}

// PushLayer pushes a layer to the registry, checking if it exists
func PushLayer(
	token dauth.Scope,
	ref reference.Named,
	layerData *distribution.Layer,
	endpoint *registry.APIEndpoint,
) (err error) {
	sep := names.SeperateRepository(ref)
	dig := names.AppendDigest(sep, *layerData.Digest)
	bldr := v2.NewURLBuilder(endpoint.URL, false)

	layerExists, err := checkLayer(token, dig, bldr)
	if err != nil {
		return err
	} else if layerExists {
		log.Info().Msgf("Blob %s exists.", layerData.Digest)
		return nil
	}

	log.Info().Msgf("Blob %s is new, proceed to upload", layerData.Digest)

	// query the server for which location to upload to
	loc, err := getUploadLoc(token, dig, bldr, layerData)
	if err != nil {
		return err
	}

	// now actually upload the blob
	log.Info().Msgf("Uploading to: %v", loc)
	return uploadBlob(loc, token, dig, bldr, layerData)
}

func checkLayer(token dauth.Scope, ref reference.Canonical, bldr *v2.URLBuilder) (b bool, err error) {
	layerURLStr, err := bldr.BuildBlobURL(ref)
	if err != nil {
		return false, errors.Wrapf(err, "%#v", ref)
	}

	req, err := http.NewRequest("HEAD", layerURLStr, nil)
	if err != nil {
		return false, errors.Wrapf(err, "%v", layerURLStr)
	}

	auth.AddToReqest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	if err != nil {
		return false, errors.Wrapf(err, "%v", req)
	}
	defer func() { err = utils.CheckedClose(resp.Body, err) }()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	return false, errors.New("error testing exsistance of layer")
}

func getUploadLoc(
	token dauth.Scope,
	dig reference.Named,
	bldr *v2.URLBuilder,
	layerData *distribution.Layer,
) (loc string, err error) {
	// get the location to upload the blob
	uploadURLStr, err := bldr.BuildBlobUploadURL(dig, nil)
	if err != nil {
		return "", errors.Wrapf(err, "%#v", dig)
	}

	req, err := http.NewRequest("POST", uploadURLStr, nil)
	if err != nil {
		return "", errors.Wrapf(err, "could not make req = %v", req)
	}

	auth.AddToReqest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	if err != nil {
		return "", err
	}
	defer func() { err = utils.CheckedClose(resp.Body, err) }()

	if resp.StatusCode != http.StatusAccepted {
		return "", errors.New("upload of layer " + layerData.Digest.String() + " was not accepted")
	}

	loc = resp.Header.Get("Location")
	if loc == "" {
		return "", errors.New("server did not return location to upload to")
	}

	return loc, nil
}

func uploadBlob(
	loc string,
	token dauth.Scope,
	dig reference.Canonical,
	bldr *v2.URLBuilder,
	layerData *distribution.Layer,
) error {
	u, err := url.Parse(loc)
	if err != nil {
		return errors.Wrapf(err, "loc = %v", loc)
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.Wrapf(err, "rawquery = %v", u.RawQuery)
	}
	q.Add("digest", layerData.Digest.String())
	rawq, err := url.QueryUnescape(q.Encode())
	if err != nil {
		return errors.Wrapf(err, "could not extract uescape url query: %s", q.Encode())
	}
	u.RawQuery = rawq

	// open the layer file to get size and upload
	layerFH, err := os.Open(layerData.Filename)
	if err != nil {
		return errors.Wrapf(err, "could not open: %s", layerData.Filename)
	}
	// file will be closed by the http client

	req, err := http.NewRequest("PUT", u.String(), layerFH)
	if err != nil {
		return errors.Wrapf(err, "could not make req = %v", req)
	}

	req.Header.Add("Content-Length", strconv.FormatInt(layerData.Size, 10))
	req.Header.Add("Content-Type", "application/octect-stream")
	auth.AddToReqest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, false, true)
	if err != nil {
		return err
	}
	defer func() { err = utils.CheckedClose(resp.Body, err) }()

	if resp.StatusCode != http.StatusCreated {
		return errors.New("upload of layer " + layerData.Digest.String() + " failed")
	}
	return nil
}
