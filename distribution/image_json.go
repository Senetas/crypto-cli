package distribution

import (
	"encoding/json"

	"github.com/pkg/errors"
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

func unmarshalConfig(m json.RawMessage) (blob Blob, err error) {
	blobMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(m, &blobMap); err != nil {
		return nil, err
	}

	if _, ok := blobMap["crypto"]; ok {
		blob = &encryptedConfigNew{}
	} else if _, ok := blobMap["urls"]; ok {
		blob = &encryptedConfigCompat{}
	} else {
		blob = &NoncryptedBlob{}
	}

	if err = json.Unmarshal(m, blob); err != nil {
		return nil, err
	}

	return blob, nil
}

func unmarshalLayers(v json.RawMessage) (_ []Blob, err error) {
	var layerJSONs []json.RawMessage
	err = json.Unmarshal(v, &layerJSONs)
	if err != nil {
		return nil, err
	}

	layers := make([]Blob, len(layerJSONs))
	for i, l := range layerJSONs {
		if layers[i], err = unmarshalLayer(l); err != nil {
			return nil, err
		}
	}
	return layers, nil
}

func unmarshalLayer(m json.RawMessage) (blob Blob, err error) {
	blobMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(m, &blobMap); err != nil {
		return nil, err
	}

	if _, ok := blobMap["crypto"]; ok {
		blob = &encryptedBlobNew{}
	} else if _, ok := blobMap["urls"]; ok {
		blob = &encryptedBlobCompat{}
	} else {
		blob = &NoncryptedBlob{}
	}

	if err = json.Unmarshal(m, blob); err != nil {
		return nil, err
	}

	return blob, nil
}
