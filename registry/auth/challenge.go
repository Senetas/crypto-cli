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
