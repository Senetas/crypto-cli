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

package names

import (
	"bytes"

	"github.com/docker/distribution/reference"
)

// NamedTaggedRepository is a represents a image refererence where the Name
// evaluates to the repository name with out the domain
type NamedTaggedRepository interface {
	reference.NamedTagged
	Domain() string
	Path() string
}

type taggedRepository struct {
	tag    string
	domain string
	path   string
}

func (r *taggedRepository) String() string {
	var b bytes.Buffer
	if r.domain != "" {
		if _, err := b.WriteString(r.domain); err != nil {
			return b.String()
		}
		if _, err := b.WriteString("/"); err != nil {
			return b.String()
		}
	}
	if _, err := b.WriteString(r.path); err != nil {
		return b.String()
	}
	if r.path != "" {
		if _, err := b.WriteString(":"); err != nil {
			return b.String()
		}
		if _, err := b.WriteString(r.tag); err != nil {
			return b.String()
		}
	}
	return b.String()
}

func (r *taggedRepository) Name() string {
	return r.path
}

func (r *taggedRepository) Tag() string {
	return r.tag
}

func (r *taggedRepository) Domain() string {
	return r.domain
}

func (r *taggedRepository) Path() string {
	return r.path
}
