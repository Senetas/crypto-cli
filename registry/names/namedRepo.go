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
