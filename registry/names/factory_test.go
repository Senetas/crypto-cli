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

package names_test

import (
	_ "crypto/sha256"
	"fmt"
	"testing"

	"github.com/docker/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/registry/names"
)

const (
	domain        = "localhost:5000"
	defaultDomain = "docker.io"
	repo          = "hello/alpine"
	tag           = "atag"
	defaultTag    = "latest"
)

func TestTrimedNamed(t *testing.T) {
	assert := assert.New(t)

	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	assert.Nil(err)

	type results struct {
		domain string
		path   string
	}

	tests := []struct {
		ref reference.Named
		results
	}{
		{ref, results{domain, repo}},
	}

	for _, test := range tests {
		trimed := names.TrimNamed(ref)
		assert.Equal(trimed.Domain(), test.domain)
		assert.Equal(trimed.Path(), test.path)
	}
}

func TestSeperateRepository(t *testing.T) {
	assert := assert.New(t)

	ref1, err := reference.ParseNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	assert.Nil(err)
	ref2, err := reference.ParseNormalizedNamed(fmt.Sprintf("%s:%s", repo, tag))
	assert.Nil(err)
	ref3, err := reference.ParseNormalizedNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	assert.Nil(err)

	type results struct {
		domain string
		path   string
		name   string
	}

	tests := []struct {
		ref reference.Named
		results
	}{
		{ref1, results{domain, repo, repo}},
		{ref2, results{defaultDomain, repo, repo}},
		{ref3, results{domain, repo, repo}},
	}

	for _, test := range tests {
		sep := names.SeperateRepository(test.ref)
		assert.Equal(sep.Domain(), test.domain)
		assert.Equal(sep.Path(), test.path)
		assert.Equal(sep.Name(), test.name)
	}
}

func TestSeperateTaggedRepository(t *testing.T) {
	assert := assert.New(t)

	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s", domain, repo))
	assert.Nil(err)

	tagged, err := reference.WithTag(ref, tag)
	assert.Nil(err)

	sep := names.SeperateTaggedRepository(tagged)
	assert.Equal(sep.Domain(), domain)
	assert.Equal(sep.Path(), repo)
	assert.Equal(sep.Name(), repo)
	assert.Equal(sep.Tag(), tag)
}

func TestCastToTagged(t *testing.T) {
	assert := assert.New(t)

	ref1, err := reference.ParseNamed(fmt.Sprintf("%s/%s", domain, repo))
	assert.Nil(err)
	ref2, err := reference.ParseNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	assert.Nil(err)

	type results struct {
		domain string
		path   string
		name   string
		tag    string
	}

	tests := []struct {
		ref reference.Named
		results
	}{
		{ref1, results{domain, repo, repo, defaultTag}},
		{ref2, results{domain, repo, repo, tag}},
	}

	for _, test := range tests {
		cast, err := names.CastToTagged(test.ref)
		assert.Nil(err)
		assert.Equal(cast.Domain(), test.domain)
		assert.Equal(cast.Path(), test.path)
		assert.Equal(cast.Name(), test.name)
		assert.Equal(cast.Tag(), test.tag)
	}
}

func TestAppendDigest(t *testing.T) {
	assert := assert.New(t)

	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s", domain, repo))
	assert.Nil(err)

	sep := names.SeperateRepository(ref)
	d := digest.Canonical.FromString("foobar")

	dig := names.AppendDigest(sep, d)
	assert.Equal(dig.Name(), repo)
	assert.Equal(dig.Digest(), d)
}
