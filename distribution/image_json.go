package distribution

import (
	"encoding/json"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

type blobType int

const (
	unknown blobType = iota
	current
	compat
	plain
)

// UnmarshalJSON converts json into a image manifest, chosoing the appropriate
// types for the blob subobjects
func (m *ImageManifest) UnmarshalJSON(data []byte) (err error) {

	manifestMap := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &manifestMap); err != nil {
		return errors.WithStack(err)
	}

	for k, v := range manifestMap {
		switch k {
		case "mediaType":
			if err := json.Unmarshal(v, &m.MediaType); err != nil {
				return errors.WithStack(err)
			}
		case "schemaVersion":
			if err := json.Unmarshal(v, &m.SchemaVersion); err != nil {
				return errors.WithStack(err)
			}
		case "config":
			if m.Config, err = unmarshalBlob(v); err != nil {
				return errors.WithStack(err)
			}
		case "layers":
			var layerJSONs []json.RawMessage
			if err := json.Unmarshal(v, &layerJSONs); err != nil {
				return errors.WithStack(err)
			}

			m.Layers = make([]Blob, len(layerJSONs))
			for i, l := range layerJSONs {
				if m.Layers[i], err = unmarshalBlob(l); err != nil {
					return errors.WithStack(err)
				}
			}
		default:
		}
	}
	return nil
}

func unmarshalBlob(m json.RawMessage) (_ Blob, err error) {
	var (
		bT        blobType
		mediaType string
		size      int64
		d         digest.Digest
		enCrypto  EnCrypto
		urls      []string
	)

	blobMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(m, &blobMap); err != nil {
		return nil, errors.WithStack(err)
	}

	for k, v := range blobMap {
		switch k {
		case "mediatype":
			if err = json.Unmarshal(v, &mediaType); err != nil {
				return nil, errors.WithStack(err)
			}
		case "size":
			if err = json.Unmarshal(v, &size); err != nil {
				return nil, errors.WithStack(err)
			}
		case "digest":
			var digestStr string
			if err = json.Unmarshal(v, &digestStr); err != nil {
				return nil, errors.WithStack(err)
			}
			if d, err = digest.Parse(digestStr); err != nil {
				return nil, errors.WithStack(err)
			}
		case "crypto":
			if err = json.Unmarshal(v, &enCrypto); err != nil {
				return nil, errors.WithStack(err)
			}
			bT = current
		case "urls":
			if err = json.Unmarshal(v, &urls); err != nil {
				return nil, errors.WithStack(err)
			}
			if bT == unknown {
				bT = compat
			} else {
				return nil, errors.New("blob contains both new and compat crypto formats")
			}
		default:
		}
	}

	if bT == unknown {
		bT = plain
	}

	nb := &NoncryptedBlob{
		ContentType: mediaType,
		Size:        size,
		Digest:      &d,
	}

	switch bT {
	case current:
		return &encryptedBlobNew{
			NoncryptedBlob: nb,
			EnCrypto:       &enCrypto,
		}, nil
	case compat:
		return &encryptedBlobCompat{
			NoncryptedBlob: nb,
			URLs:           urls,
		}, nil
	case plain:
		return nb, nil
	default:
	}

	return nil, errors.New("could not determine type of crypto")
}
