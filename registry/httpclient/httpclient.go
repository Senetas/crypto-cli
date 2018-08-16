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

package httpclient

import (
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	// DefaultClient is a http client with timeouts set
	DefaultClient = &http.Client{
		Timeout:   100 * time.Second,
		Transport: defaultTransport,
	}
	defaultTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
)

// DoRequest wraps http.Client.Do but dumps the request and response with optional bodies
func DoRequest(client *http.Client, req *http.Request, dumpReqBody, dumpRespBody bool) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, dumpReqBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", req)
	}
	log.Debug().Msg(req.URL.String())
	log.Debug().Msgf("%s", dump)

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if dump, err = httputil.DumpResponse(resp, dumpRespBody); err != nil {
		return nil, errors.Wrapf(err, "%#v", resp)
	}
	log.Debug().Msgf("%s", dump)

	return resp, err
}
