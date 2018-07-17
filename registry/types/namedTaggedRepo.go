package types

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
