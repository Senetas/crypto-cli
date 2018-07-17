package types

import digest "github.com/opencontainers/go-digest"

type digestedReference struct {
	NamedRepository
	d digest.Digest
}

func (r *digestedReference) Digest() digest.Digest {
	return r.d
}
