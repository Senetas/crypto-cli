package registry

import (
	"net/http"
	"net/http/httputil"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	regAddr = "registry-1.docker.io"
	regPath = "v2"
)

func doRequest(client *http.Client, req *http.Request, reqBody, respBody bool) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, reqBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", req)
	}
	log.Debug().Msgf("\n%s", dump)

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", req)
	}

	dump, err = httputil.DumpResponse(resp, respBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", resp)
	}
	log.Debug().Msgf("\n%s", dump)

	return resp, nil
}
