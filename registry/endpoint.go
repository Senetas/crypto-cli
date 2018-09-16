package registry

import (
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
)

// GetEndpoint returns the endpoint associated with the reference
func GetEndpoint(
	ref reference.Named,
	repoInfo registry.RepositoryInfo,
) (
	_ *registry.APIEndpoint,
	err error,
) {
	options := registry.ServiceOptions{}
	options.InsecureRegistries = append(options.InsecureRegistries, "0.0.0.0/0")

	var registryService *registry.DefaultService
	registryService, err = registry.NewService(options)
	if err != nil {
		err = errors.Wrapf(err, "opts = %#v", options)
		return
	}

	var endpoints []registry.APIEndpoint
	endpoints, err = registryService.LookupPushEndpoints(repoInfo.Index.Name)
	if err != nil {
		err = errors.Wrapf(err, "index name = %#v", repoInfo.Index.Name)
		return
	}

	return &endpoints[0], nil
}
