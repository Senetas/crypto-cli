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
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	dockerregistry "github.com/docker/docker/registry"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/registry"
)

const (
	labelString = "LABEL com.senetas.crypto.enabled=true"
	saltBase    = "com.senetas.crypto/%s/%s"
	configSalt  = saltBase + "/config"
	layerSalt   = saltBase + "/layer%d"
)

var tempRoot = filepath.Join(os.TempDir(), "com.senetas.crypto")

func authProcedure(ref reference.Named) (
	string,
	*registry.NamedTaggedRepository,
	*dockerregistry.APIEndpoint,
	error,
) {
	nTRep, err := registry.ResolveNamed(ref)
	if err != nil {
		return "", nil, nil, err
	}

	repoInfo, err := dockerregistry.ParseRepositoryInfo(ref)
	if err != nil {
		return "", nil, nil, errors.Wrapf(err, "could not parse ref = %v", ref)
	}

	endpoint, err := registry.GetEndPoint(ref, *repoInfo)
	if err != nil {
		return "", nil, nil,
			errors.Wrapf(err, "could not get endpoint ref = %v, repoInfo = %v", ref, *repoInfo)
	}

	token, err := registry.Authenticate(nTRep, *repoInfo, endpoint)
	if err != nil {
		return "", nil, nil, err
	}

	return token, &nTRep, &endpoint, nil
}
