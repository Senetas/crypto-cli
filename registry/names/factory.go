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
	"github.com/docker/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"github.com/rs/zerolog/log"
)

// TrimNamed removes a tag from a Named
func TrimNamed(ref reference.Named) NamedRepository {
	switch r := ref.(type) {
	case NamedTaggedRepository:
		return &repository{domain: r.Domain(), path: r.Path()}
	default:
		log.Debug().Msg("here")
		domain, path := reference.SplitHostname(ref)
		return &repository{domain: domain, path: path}
	}
}

// SeperateRepository converts a named into a named where the output of the Name()
// function will not have the domain as a prefix
func SeperateRepository(ref reference.Named) NamedRepository {
	domain, path := reference.SplitHostname(ref)
	return &repository{domain: domain, path: path}
}

// SeperateTaggedRepository converts a named into a named where the output of the Name()
// method will not have the domain as a prefix
func SeperateTaggedRepository(ref reference.NamedTagged) NamedTaggedRepository {
	domain, path := reference.SplitHostname(ref)
	return &taggedRepository{domain: domain, path: path, tag: ref.Tag()}
}

// CastToTagged converts a Named into a NamedTaggedRepository, choosing the
// default "latest" tag if necessary
func CastToTagged(ref reference.Named) (NamedTaggedRepository, error) {
	switch r := ref.(type) {
	case reference.NamedTagged:
		return SeperateTaggedRepository(r), nil
	default:
		sep := SeperateRepository(r)
		return &taggedRepository{"latest", sep.Domain(), sep.Path()}, nil
	}
}

// AppendDigest appends a digest to a named repository
func AppendDigest(ref NamedRepository, d digest.Digest) reference.Canonical {
	return &digestedReference{ref, d}
}
