package distribution

import (
	"encoding/json"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
)

// MarshalJSON customises the marshalling of an ImageManifest
func (m *ImageManifest) MarshalJSON() (bs []byte, err error) {
	type Alias ImageManifest
	aux := &struct {
		*Alias
		Config json.RawMessage   `json:"config"`
		Layers []json.RawMessage `json:"layers"`
	}{
		Alias: (*Alias)(m),
	}

	aux.Config, err = marshalBlob(m.Config)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	aux.Layers, err = marshalLayers(m.Layers)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	return json.Marshal(aux)
}

func marshalBlob(config Blob) (bs json.RawMessage, err error) {
	type Layer struct {
		Digest    digest.Digest `json:"digest"`
		MediaType string        `json:"mediaType"`
		Size      int64         `json:"size"`
	}
	layer := Layer{
		Digest:    config.GetDigest(),
		Size:      config.GetSize(),
		MediaType: config.GetContentType(),
	}
	aux := &struct {
		Layer
		Crypto crypto.EnCrypto `json:"crypto"`
	}{
		Layer: layer,
	}
	switch b := config.(type) {
	case *encryptedConfigNew:
		aux.Crypto = *b.EnCrypto
	case *encryptedBlobNew:
		aux.Crypto = *b.EnCrypto
	default:
		return json.Marshal(layer)
	}
	return json.Marshal(aux)
}

func marshalLayers(layers []Blob) (out []json.RawMessage, err error) {
	out = make([]json.RawMessage, len(layers))
	for i, l := range layers {
		out[i], err = marshalBlob(l)
		if err != nil {
			return
		}
	}
	return
}

// UnmarshalJSON converts json into a image manifest, chosing the appropriate
// types for the blob subobjects
func (m *ImageManifest) UnmarshalJSON(data []byte) (err error) {
	manifestMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(data, &manifestMap); err != nil {
		err = errors.WithStack(err)
		return
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
			err = errors.WithStack(err)
			return
		}
	}

	return
}

func unmarshalConfig(m json.RawMessage) (blob Blob, err error) {
	blobMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(m, &blobMap); err != nil {
		return
	}

	if c, ok := blobMap["crypto"]; ok {
		eblob := &encryptedConfigNew{}
		eblob.EnCrypto = &crypto.EnCrypto{}
		err = json.Unmarshal(c, eblob.EnCrypto)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		nblob := &NoncryptedBlob{}
		err = json.Unmarshal(m, nblob)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		eblob.NoncryptedBlob = nblob
		return eblob, nil
	} else if _, ok := blobMap["urls"]; ok {
		blob = &encryptedConfigCompat{}
	} else {
		blob = &NoncryptedBlob{}
	}

	if err = json.Unmarshal(m, blob); err != nil {
		err = errors.WithStack(err)
		return
	}

	return
}

func unmarshalLayers(v json.RawMessage) (layers []Blob, err error) {
	var layerJSONs []json.RawMessage
	err = json.Unmarshal(v, &layerJSONs)
	if err != nil {
		return
	}

	layers = make([]Blob, len(layerJSONs))
	for i, l := range layerJSONs {
		if layers[i], err = unmarshalLayer(l); err != nil {
			return
		}
	}

	return
}

func unmarshalLayer(m json.RawMessage) (blob Blob, err error) {
	blobMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(m, &blobMap); err != nil {
		return
	}

	if c, ok := blobMap["crypto"]; ok {
		eblob := &encryptedBlobNew{}
		eblob.EnCrypto = &crypto.EnCrypto{}
		err = json.Unmarshal(c, eblob.EnCrypto)
		if err != nil {
			return
		}
		nblob := &NoncryptedBlob{}
		err = json.Unmarshal(m, nblob)
		if err != nil {
			return
		}
		eblob.NoncryptedBlob = nblob
		return eblob, nil
	} else if _, ok := blobMap["urls"]; ok {
		blob = &encryptedBlobCompat{}
	} else {
		blob = &NoncryptedBlob{}
	}

	err = json.Unmarshal(m, blob)

	return
}
