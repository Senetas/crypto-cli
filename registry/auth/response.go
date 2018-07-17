package auth

import (
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

type responseToken struct {
	Token string `json:"token"`
}

func decodeRespose(respBody io.Reader) (rt responseToken, err error) {
	dec := json.NewDecoder(respBody)
	if err = dec.Decode(&rt); err != nil {
		return responseToken{}, errors.Wrapf(err, "could not decode response from auth server")
	}
	if rt.Token == "" {
		return responseToken{}, errors.New("malformed response from auth server")
	}
	return rt, nil
}
