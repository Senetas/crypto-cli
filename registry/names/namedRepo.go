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

// NamedRepository is a represents a image refererence where the Name
// evaluates to the repository name with out the domain
type NamedRepository interface {
	reference.Named
	Domain() string
	Path() string
}

type repository struct {
	domain string
	path   string
}

func (r *repository) String() string {
	var b bytes.Buffer
	if r.domain != "" {
		b.WriteString(r.domain)
		b.WriteString("/")
	}
	b.WriteString(r.path)
	return b.String()
}

func (r *repository) Name() string {
	return r.Path()
}

func (r *repository) Domain() string {
	return r.domain
}

func (r *repository) Path() string {
	return r.path
}
