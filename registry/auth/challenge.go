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
	"net/url"
	"regexp"

	"github.com/pkg/errors"
)

var challengeRE = regexp.MustCompile(`^\s*Bearer\s+realm="([^"]+)",service="([^"]+)"(,scope="([^"]+)")?\s*$`)

// Challenge from a auth server
type Challenge struct {
	realm   *url.URL
	service string
	scope   string
}

// ParseChallengeHeader parses the challenge header and extract the relevant parts
func ParseChallengeHeader(header string) (*Challenge, error) {
	match := challengeRE.FindAllStringSubmatch(header, -1)

	if len(match) != 1 {
		return nil, errors.Errorf("malformed challenge header: %s", header)
	}

	realmURL, err := url.Parse(match[0][1])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &Challenge{
		realm:   realmURL,
		service: match[0][2],
		scope:   match[0][4],
	}, nil
}

func (c *Challenge) buildURL() *url.URL {
	authURL := *c.realm
	authParams := make(url.Values)
	authParams.Set("service", c.service)
	if c.scope != "" {
		authParams.Set("scope", c.scope)
	}

	authURL.RawQuery = authParams.Encode()

	return &authURL
}
