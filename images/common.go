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

package images

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
)

const labelString = "LABEL com.senetas.crypto.enabled=true"

const (
	user       = "narthanaepa1"
	pass       = "hunter2"
	service    = "registry.docker.io"
	authServer = "auth.docker.io"
	saltBase   = "com.senetas.crypto/%s/%s"
	configSalt = saltBase + "/config"
	layerSalt  = saltBase + "/layer%d"
)

var path = filepath.Join(os.TempDir(), "com.senetas.crypto")

func resloveNamed(ref *reference.Named) (string, string, error) {
	switch r := (*ref).(type) {
	case reference.NamedTagged:
		return reference.Path(r), r.Tag(), nil
	case reference.Named:
		return reference.Path(r), "latest", nil
	default:
		return "", "", errors.New("invalid image name")
	}
}

func getEndPoint(ref *reference.Named) (*registry.APIEndpoint, error) {
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
