package reference

import (
	"errors"
	"strings"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
)

const defaultPrefix = "docker.io/"

// ResloveNamed parses a reference into a repo and tag
func ResloveNamed(ref *reference.Named) (string, string, error) {
	switch r := (*ref).(type) {
	case reference.NamedTagged:
		return localName(ref), r.Tag(), nil
	case reference.Named:
		return localName(ref), "latest", nil
	default:
		return "", "", errors.New("invalid image name")
	}
}

func localName(ref *reference.Named) string {
	return strings.TrimPrefix((*ref).Name(), defaultPrefix)
}

// GetEndPoint returns the endpoint associted witht th reference
func GetEndPoint(ref *reference.Named) (*registry.APIEndpoint, error) {
	repoInfo, err := registry.ParseRepositoryInfo(*ref)
	if err != nil {
		return nil, err
	}

	options := registry.ServiceOptions{}
	options.InsecureRegistries = append(options.InsecureRegistries, "0.0.0.0/0")
	registryService, err := registry.NewService(options)
	if err != nil {
		return nil, err
	}

	endpoints, err := registryService.LookupPushEndpoints(repoInfo.Index.Name)
	if err != nil {
		return nil, err
	}

	// should copy out so the array can be freed?
	endpoint := endpoints[0]

	return &endpoint, nil
}
