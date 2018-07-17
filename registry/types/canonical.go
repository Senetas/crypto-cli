package types

import digest "github.com/opencontainers/go-digest"

type canonicalReference struct {
	NamedTaggedRepository
	d digest.Digest
}

func (r *canonicalReference) Digest() digest.Digest {
	return r.d
}
