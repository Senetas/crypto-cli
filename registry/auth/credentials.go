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

package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/docker/docker/cli/config"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/utils"
)

// Credentials represents a username password pair
type Credentials interface {
	SetAuth(r *http.Request) (*http.Request, error)
}

type fromCliCredentials struct {
	username string
	password string
}

// NewCredsFromCli creates a struct that satisfies Credentials from
// a username and password (typically entered at the command like)
func NewCredsFromCli(username, password string) Credentials {
	return &fromCliCredentials{username: username, password: password}
}

func (c *fromCliCredentials) SetAuth(req *http.Request) (*http.Request, error) {
	req.SetBasicAuth(c.username, c.password)
	return req, nil
}

type fromConfCredentials struct {
	conffile string
	mutex    sync.Mutex
	token    string
}

// NewDefaultCreds create a credentials struct from the credentials in
// the default conf file, typically ~/.docker/config.json. the struct is lazy,
// i.e. the file is only read if the username or password is accessed
func NewDefaultCreds() Credentials {
	return NewCredsFromConf(filepath.Join(config.Dir(), "config.json"))
}

// NewCredsFromConf create a credentials struct from the credentials in
// a conf file. the struct is lazy, i.e. the file is only read if the
// username or password is accessed
func NewCredsFromConf(conffile string) Credentials {
	return &fromConfCredentials{conffile: conffile, mutex: sync.Mutex{}}
}

func (c *fromConfCredentials) SetAuth(req *http.Request) (r *http.Request, err error) {
	c.mutex.Lock()
	if c.token == "" {
		c.token, err = extractToken(c.conffile)
		if err != nil {
			return nil, err
		}
	}
	c.mutex.Unlock()
	req.Header.Set("Authorization", "Basic "+c.token)
	return req, nil
}

// the username and password are encoded in base64 in the conffile
func extractToken(conffile string) (token string, err error) {
	confH, err := os.Open(conffile)
	if err != nil {
		return "", errors.Wrapf(err, "could not open file: %s", conffile)
	}
	defer func() { err = utils.CheckedClose(confH, err) }()

	var config map[string]interface{}
	dec := json.NewDecoder(confH)
	if err = dec.Decode(&config); err != nil {
		return "", errors.Wrapf(err, "could not decode: %s", conffile)
	}

	// return the first entry if any
	for _, v := range config["auths"].(map[string]interface{}) {
		return (v.(map[string]interface{})["auth"]).(string), nil
	}

	return "", errors.New("No Authentication Token was found. Try running \"docker login\" to generate one")
}
