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
	if err = json.Unmarshal(data, &manifestMap); err != nil {
		return errors.WithStack(err)
	}

	for k, v := range manifestMap {
		switch k {
		case "mediaType":
			err = json.Unmarshal(v, &m.MediaType)
		case "schemaVersion":
			err = json.Unmarshal(v, &m.SchemaVersion)
		case "config":
			m.Config, err = unmarshalConfig(v)
		case "layers":
			m.Layers, err = unmarshalLayers(v)
		default:
		}
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func unmarshalConfig(m json.RawMessage) (_ Blob, err error) {
	var (
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

	bT, err := loadFields(blobMap, &mediaType, &size, &d, &enCrypto, &urls)
	if err != nil {
		return nil, err
	}

	nb := &NoncryptedBlob{
		ContentType: mediaType,
		Size:        size,
		Digest:      d,
	}

	return addCryptoConfig(bT, nb, &enCrypto, urls)
}

func unmarshalLayers(v json.RawMessage) (_ []Blob, err error) {
	var layerJSONs []json.RawMessage
	err = json.Unmarshal(v, &layerJSONs)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	layers := make([]Blob, len(layerJSONs))
	for i, l := range layerJSONs {
		if layers[i], err = unmarshalLayer(l); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return layers, nil
}

func unmarshalLayer(m json.RawMessage) (_ Blob, err error) {
	var (
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

	bT, err := loadFields(blobMap, &mediaType, &size, &d, &enCrypto, &urls)
	if err != nil {
		return nil, err
	}

	nb := &NoncryptedBlob{
		ContentType: mediaType,
		Size:        size,
		Digest:      d,
	}

	return addCryptoLayer(bT, nb, &enCrypto, urls)
}

func loadFields(
	blobMap map[string]json.RawMessage,
	mediaType *string,
	size *int64,
	d *digest.Digest,
	enCrypto *EnCrypto,
	urls *[]string,
) (_ blobType, err error) {
	bT := unknown

	for k, v := range blobMap {
		if err = parseKey(k, v, blobMap, &bT, mediaType, size, d, enCrypto, urls); err != nil {
			return unknown, errors.WithStack(err)
		}
	}

	if bT == unknown {
		return plain, nil
	}

	return bT, nil
}

// TODO: support urls field that are not crypto related
func parseKey(
	k string,
	v json.RawMessage,
	blobMap map[string]json.RawMessage,
	bT *blobType,
	mediaType *string,
	size *int64,
	d *digest.Digest,
	enCrypto *EnCrypto,
	urls *[]string,
) (err error) {
	switch k {
	case "mediaType":
		return json.Unmarshal(v, mediaType)
	case "size":
		return json.Unmarshal(v, size)
	case "digest":
		return unmarshalDigest(v, d)
	case "crypto":
		*bT = current
		return json.Unmarshal(v, enCrypto)
	case "urls":
		if *bT == unknown {
			*bT = compat
		} else {
			return errors.New("blob contains both new and compat crypto formats")
		}
		return json.Unmarshal(v, urls)
	default:
		return nil
	}
}

func unmarshalDigest(v json.RawMessage, d *digest.Digest) (err error) {
	var digestStr string
	err = json.Unmarshal(v, &digestStr)
	if err != nil {
		return errors.WithStack(err)
	}
	*d, err = digest.Parse(digestStr)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func addCryptoConfig(bT blobType, nb *NoncryptedBlob, enCrypto *EnCrypto, urls []string) (Blob, error) {
	switch bT {
	case current:
		return &encryptedConfigNew{
			NoncryptedBlob: nb,
			EnCrypto:       enCrypto,
		}, nil
	case compat:
		return &encryptedConfigCompat{
			NoncryptedBlob: nb,
			URLs:           urls,
		}, nil
	case plain:
		return nb, nil
	default:
		return nil, errors.New("could not determine type of crypto")
	}
}

func addCryptoLayer(bT blobType, nb *NoncryptedBlob, enCrypto *EnCrypto, urls []string) (Blob, error) {
	switch bT {
	case current:
		return &encryptedBlobNew{
			NoncryptedBlob: nb,
			EnCrypto:       enCrypto,
		}, nil
	case compat:
		return &encryptedBlobCompat{
			NoncryptedBlob: nb,
			URLs:           urls,
		}, nil
	case plain:
		return nb, nil
	default:
		return nil, errors.New("could not determine type of crypto")
	}
}
