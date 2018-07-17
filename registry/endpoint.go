package registry

import (
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
)

// GetEndpoint returns the endpoint associated with the reference
func GetEndpoint(ref reference.Named, repoInfo registry.RepositoryInfo) (registry.APIEndpoint, error) {
	options := registry.ServiceOptions{}
	options.InsecureRegistries = append(options.InsecureRegistries, "0.0.0.0/0")
	registryService, err := registry.NewService(options)
	if err != nil {
		return registry.APIEndpoint{}, errors.Wrapf(err, "opts = %#v", options)
	}

	endpoints, err := registryService.LookupPushEndpoints(repoInfo.Index.Name)
	if err != nil {
		return registry.APIEndpoint{}, errors.Wrapf(err, "index name = %#v", repoInfo.Index.Name)
	}

	endpoint := endpoints[0]

	return endpoint, nil
}
