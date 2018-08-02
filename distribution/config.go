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

package distribution

import (
	"encoding/json"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/image"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/Senetas/crypto-cli/crypto"
)

// the following two structs contain fields of the github.com/docker/docker/images/Image
// struct. This represents the "config" file in the manifest of a docker image

// the fields to encrypt
type secretFields struct {
	ID              string            `json:"id,omitempty"`
	Parent          image.ID          `json:"parent,omitempty"`
	Comment         string            `json:"comment,omitempty"`
	Container       string            `json:"container,omitempty"`
	ContainerConfig container.Config  `json:"container_config,omitempty"`
	Config          *container.Config `json:"config,omitempty"`
	RootFS          *image.RootFS     `json:"rootfs,omitempty"`
	History         []image.History   `json:"history,omitempty"`
}

// the fields to keep in the clear
type clearFields struct {
	Created       time.Time `json:"created"`
	DockerVersion string    `json:"docker_version,omitempty"`
	Author        string    `json:"author,omitempty"`
	Architecture  string    `json:"architecture,omitempty"`
	OS            string    `json:"os,omitempty"`
	Size          int64     `json:",omitempty"`
	OSVersion     string    `json:"os.version,omitempty"`
	OSFeatures    []string  `json:"os.features,omitempty"`
}

// DecConfig is config that may be encrypted
type DecConfig interface {
	Encrypt(key []byte, opts crypto.Opts) (EncConfig, error)
}

type decConfig struct {
	secretFields
	clearFields
}

// NewDecConfig creates a new DecConfig
func NewDecConfig() DecConfig { return &decConfig{} }

func (c *decConfig) Equal(o *decConfig) bool {
	return cmp.Equal(c.secretFields, o.secretFields) && cmp.Equal(c.clearFields, o.clearFields)
}

// Sort the keys when marshalling
func (c *decConfig) MarshalJSON() ([]byte, error) {
	type MarshalImage decConfig

	pass1, err := json.Marshal(MarshalImage(*c))
	if err != nil {
		return nil, err
	}

	var sorted map[string]*json.RawMessage
	if err := json.Unmarshal(pass1, &sorted); err != nil {
		return nil, err
	}
	return json.Marshal(sorted)
}

func (c *decConfig) Encrypt(key []byte, opts crypto.Opts) (EncConfig, error) {
	enc, err := crypto.EncryptJSON(c.secretFields, key, []byte(opts.Salt))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	ec := &encConfig{
		clearFields: c.clearFields,
		Enc:         enc,
	}
	return ec, nil
}

// EncConfig has the secretFields encrypted
type EncConfig interface {
	Decrypt(key []byte, opts crypto.Opts) (DecConfig, error)
}

type encConfig struct {
	Enc string `json:"enc,omitempty"`
	clearFields
}

func (c *encConfig) Decrypt(key []byte, opts crypto.Opts) (DecConfig, error) {
	dc := decConfig{clearFields: c.clearFields}
	log.Debug().Msgf("%v", opts)
	if err := crypto.DecryptJSON(c.Enc, key, []byte(opts.Salt), &dc.secretFields); err != nil {
		return nil, errors.WithStack(err)
	}
	return &dc, nil
}
