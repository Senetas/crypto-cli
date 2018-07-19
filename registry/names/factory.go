package names

import (
	"errors"

	"github.com/docker/distribution/reference"
	digest "github.com/opencontainers/go-digest"
)

// TrimNamed removes a tag from a Named
func TrimNamed(ref reference.Named) NamedRepository {
	switch r := ref.(type) {
	case NamedTaggedRepository:
		return &repository{domain: r.Domain(), path: r.Path()}
	default:
		domain, path := reference.SplitHostname(ref)
		return &repository{domain: domain, path: path}
	}
}

// SeperateRepository converts a named into a named where the output of the Name()
// function will not had the domain as a prefi
func SeperateRepository(ref reference.Named) NamedRepository {
	domain, path := reference.SplitHostname(ref)
	return &repository{domain: domain, path: path}
}

// SeperateTaggedRepository converts a named into a named where the output of the Name()
// function will not had the domain as a prefi
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
	case reference.Named:
		sep := SeperateRepository(r)
		return &taggedRepository{"latest", sep.Domain(), sep.Path()}, nil
	default:
		return nil, errors.New("invalid image name")
	}
}

// AppendDigest appends a digest to a named repository
func AppendDigest(ref NamedRepository, d digest.Digest) reference.Canonical {
	return &digestedReference{ref, d}
}
