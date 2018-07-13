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

package registry

import (
	"bytes"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

// GetEndPoint returns the endpoint associted with the reference
func GetEndPoint(ref reference.Named, repoInfo registry.RepositoryInfo) (registry.APIEndpoint, error) {
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

	// should copy out so the array can be freed?
	endpoint := endpoints[0]

	return endpoint, nil
}

// TrimNamed removes a tag from a Named
func TrimNamed(ref reference.NamedTagged) NamedRepository {
	switch r := ref.(type) {
	case NamedTaggedRepository:
		return repository{domain: r.Domain(), path: r.Path()}
	default:
		domain, path := reference.SplitHostname(ref)
		return repository{domain: domain, path: path}
	}
}

// SeperateTaggedRepository converts a named into a named where the output of the Name()
// function will not had the domain as a prefi
func SeperateTaggedRepository(ref reference.NamedTagged) NamedTaggedRepository {
	domain, path := reference.SplitHostname(ref)
	return taggedRepository{domain: domain, path: path, tag: ref.Tag()}
}

// SeperateRepository converts a named into a named where the output of the Name()
// function will not had the domain as a prefi
func SeperateRepository(ref reference.Named) NamedRepository {
	domain, path := reference.SplitHostname(ref)
	return repository{domain: domain, path: path}
}

// ResolveNamed converts a Named into a NamedTaggedRepository, chooseing the default
// "latest" tag if necessary
func ResolveNamed(ref reference.Named) (NamedTaggedRepository, error) {
	switch r := ref.(type) {
	case reference.NamedTagged:
		return SeperateTaggedRepository(r), nil
	case reference.Named:
		sep := SeperateRepository(r)
		return taggedRepository{"latest", sep.Domain(), sep.Path()}, nil
	default:
		return nil, errors.New("invalid image name")
	}
}

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

func (r taggedRepository) String() string {
	var b bytes.Buffer
	if r.domain != "" {
		b.WriteString(r.domain)
		b.WriteString("/")
	}
	b.WriteString(r.path)
	if r.path != "" {
		b.WriteString(":")
		b.WriteString(r.tag)
	}
	return b.String()
}

func (r taggedRepository) Name() string {
	return r.path
}

func (r taggedRepository) Tag() string {
	return r.tag
}

func (r taggedRepository) Domain() string {
	return r.domain
}

func (r taggedRepository) Path() string {
	return r.path
}

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

func (r repository) String() string {
	var b bytes.Buffer
	if r.domain != "" {
		b.WriteString(r.domain)
		b.WriteString("/")
	}
	b.WriteString(r.path)
	return b.String()
}

func (r repository) Name() string {
	return r.Path()
}

func (r repository) Domain() string {
	return r.domain
}

func (r repository) Path() string {
	return r.path
}

type canonicalReference struct {
	NamedTaggedRepository
	d digest.Digest
}

func (r canonicalReference) Digest() digest.Digest {
	return r.d
}

type digestedReference struct {
	NamedRepository
	d digest.Digest
}

func (r digestedReference) Digest() digest.Digest {
	return r.d
}
