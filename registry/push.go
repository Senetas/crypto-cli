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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	dauth "github.com/docker/distribution/registry/client/auth"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	pb "gopkg.in/cheggaaa/pb.v1"

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
	log.Info().Msg("Layers and config uploaded successfully.")

	mdigest, err := PushManifest(token, ref, manifest, endpoint)
	if err != nil {
		return err
	}
	log.Info().Msgf("Successfully uploaded manifest: %s.", mdigest)

	return nil
}

// PushManifest puts a manifest on the registry
func PushManifest(
	token dauth.Scope,
	ref reference.Named,
	manifest *distribution.ImageManifest,
	endpoint *registry.APIEndpoint,
) (_ string, err error) {
	builder := v2.NewURLBuilder(endpoint.URL, false)
	urlStr, err := builder.BuildManifestURL(ref)
	if err != nil {
		err = errors.Wrapf(err, "ref = %v", ref)
		return
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
		err = errors.Wrapf(err, "url = %v", urlStr)
		return
	}

	req.Header.Set("Accept", "application/json, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Content-Type", distribution.MediaTypeManifest)
	auth.AddToRequest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	if resp != nil {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}
	if err != nil {
		return
	}

	// close the channel after request is done
	if err = utils.ConcatErrChan(errChan, 2); err != nil {
		err = errors.WithStack(err)
		return
	}

	if resp.StatusCode != http.StatusCreated {
		err = errors.New("manifest upload failed with status: " + resp.Status)
		return
	}

	return resp.Header.Get("Docker-Content-Digest"), nil
}

// PushLayer pushes a layer to the registry, checking if it exists
func PushLayer(
	token dauth.Scope,
	ref reference.Named,
	layer distribution.Blob,
	endpoint *registry.APIEndpoint,
) (err error) {
	sep := names.SeperateRepository(ref)
	dig := names.AppendDigest(sep, layer.GetDigest())
	bldr := v2.NewURLBuilder(endpoint.URL, false)

	exists, err := layerExists(token, dig, bldr)
	if err != nil {
		return
	} else if exists {
		log.Info().Msgf("Blob %s exists.", layer.GetDigest())
		return
	}

	log.Info().Msgf("Blob %s is new, proceed to upload.", layer.GetDigest())

	// query the server for which location to upload to
	loc, err := getUploadLoc(token, dig, bldr, layer)
	if err != nil {
		return
	}

	// now actually upload the blob
	return uploadBlob(loc, token, dig, bldr, layer)
}

// layerExists checks if the layer already exists on the repository
func layerExists(token dauth.Scope, ref reference.Canonical, bldr *v2.URLBuilder) (b bool, err error) {
	layerURLStr, err := bldr.BuildBlobURL(ref)
	if err != nil {
		err = errors.Wrapf(err, "%#v", ref)
		return
	}

	req, err := http.NewRequest("HEAD", layerURLStr, nil)
	if err != nil {
		err = errors.Wrapf(err, "%v", layerURLStr)
		return
	}

	auth.AddToRequest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	if resp != nil {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}
	if err != nil {
		err = errors.Wrapf(err, "%v", req)
		return
	}

	log.Debug().Msg(resp.Status)

	switch resp.StatusCode {
	case http.StatusOK:
		b = true
	case http.StatusNotFound:
		b = false
	case http.StatusUnauthorized:
		err = errors.Errorf("this account is not authorised to access the repository: %s", ref.Name())
	default:
		err = errors.New("error testing exsistence of layer")
	}

	return
}

// getUploadLoc optains the urlString to upload the blob to by querying the API
func getUploadLoc(
	token dauth.Scope,
	dig reference.Named,
	bldr *v2.URLBuilder,
	layerData distribution.Blob,
) (loc string, err error) {
	// get the location to upload the blob
	uploadURLStr, err := bldr.BuildBlobUploadURL(dig, nil)
	if err != nil {
		err = errors.Wrapf(err, "%#v", dig)
		return
	}

	req, err := http.NewRequest("POST", uploadURLStr, nil)
	if err != nil {
		err = errors.Wrapf(err, "could not make req = %v", req)
		return
	}

	auth.AddToRequest(token, req)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	if resp != nil {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}
	if err != nil {
		return
	}

	switch resp.StatusCode {
	case http.StatusAccepted:
		loc = resp.Header.Get("Location")
		if loc == "" {
			err = errors.New("server did not return location to upload to")
		}
	case http.StatusUnauthorized:
		err = errors.Errorf("this account is not authorised to access the repository: %s", dig.Name())
	default:
		err = errors.Errorf("upload of layer %v was not accepted", layerData.GetDigest())
	}

	return
}

// uploadBlob uploads the blob to the given urlString
func uploadBlob(
	loc string,
	token dauth.Scope,
	dig reference.Canonical,
	bldr *v2.URLBuilder,
	blob distribution.Blob,
) error {
	u, err := url.Parse(loc)
	if err != nil {
		return errors.Wrapf(err, "loc = %v", loc)
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.Wrapf(err, "rawquery = %v", u.RawQuery)
	}

	q.Add("digest", blob.GetDigest().String())
	u.RawQuery, err = url.QueryUnescape(q.Encode())
	if err != nil {
		return errors.WithStack(err)
	}

	// open the layer file to get size and upload
	blobFH, err := os.Open(blob.GetFilename())
	if err != nil {
		return errors.Wrapf(err, "could not open: %s", blob.GetFilename())
	}
	defer func() { err = utils.CheckedClose(blobFH, err) }()

	// timeout
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(10*time.Second, cancel)
	bar := pb.New64(blob.GetSize()).SetUnits(pb.U_BYTES)
	pr := bar.NewProxyReader(blobFH)
	trr := utils.NewResetReader(pr, func() { timer.Reset(20 * time.Second) })

	errCh := make(chan error)
	defer close(errCh)

	req, err := http.NewRequest("PUT", u.String(), trr)
	if err != nil {
		return errors.Wrapf(err, "could not make req = %v", req)
	}

	req = req.WithContext(ctx)
	req.ContentLength = blob.GetSize()
	req.Header.Set("Content-Type", "application/octect-stream")
	auth.AddToRequest(token, req)

	go upload(req, bar, blob, errCh)

	select {
	case <-ctx.Done():
		return errors.New("request timed out")
	default:
	}

	return <-errCh
}

// upload executes the upload request in uploadBlob
func upload(
	req *http.Request,
	bar *pb.ProgressBar,
	blob distribution.Blob,
	errCh chan<- error,
) {
	var err error
	defer func() { errCh <- err }()

	bar.Start()

	resp, err := httpclient.DoRequest(http.DefaultClient, req, false, true)
	if resp != nil {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}

	bar.Finish()

	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusCreated {
		err = errors.Errorf("upload of blob %s failed with status %s", blob.GetFilename(), resp.Status)
	}
}
