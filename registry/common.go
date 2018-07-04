package registry

import (
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog/log"
)

func doRequest(client *http.Client, req *http.Request, reqBody, respBody bool) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, reqBody)
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("\n%s", dump)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	dump, err = httputil.DumpResponse(resp, respBody)
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("\n%s", dump)

	return resp, nil
}
