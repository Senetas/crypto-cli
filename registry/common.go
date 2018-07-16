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
	"net/http"
	"net/http/httputil"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func doRequest(client *http.Client, req *http.Request, dumpReqBody, dumpRespBody bool) (*http.Response, error) {
	//dump, err := httputil.DumpRequestOut(req, dumpReqBody)
	//if err != nil {
	//return nil, errors.Wrapf(err, "%#v", req)
	//}
	//log.Debug().Msgf("\n%s", dump)

	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "%#v", req)
	}

	//dump, err = httputil.DumpResponse(resp, dumpRespBody)
	//if err != nil {
	//return nil, errors.Wrapf(err, "%#v", resp)
	//}
	//log.Debug().Msgf("\n%s", dump)

	return resp, err
}

func doRequestCtx(client *http.Client, req *http.Request, dumpReqBody, dumpRespBody bool) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, dumpReqBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", req)
	}
	log.Debug().Msgf("\n%s", dump)

	errChan := make(chan error)
	respChan := make(chan *http.Response)

	defer close(errChan)
	defer close(respChan)

	go func() {
		var err error
		var resp *http.Response
		select {
		case <-req.Context().Done():
			err = req.Context().Err()
		default:
			resp, err = client.Do(req)
			select {
			case <-req.Context().Done():
				log.Error().Msg("cancelled")
				err = req.Context().Err()
			default:
			}
		}
		if err != nil {
			err = errors.Wrapf(err, "%#v", req)
		}
		errChan <- err
		respChan <- resp
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, err
		}
	case <-req.Context().Done():
		log.Error().Msg("cancelled")
		return nil, req.Context().Err()
	}

	resp := <-respChan

	dump, err = httputil.DumpResponse(resp, dumpRespBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", resp)
	}
	log.Debug().Msgf("\n%s", dump)

	return resp, nil
}
