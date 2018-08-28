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

package distribution_test

import (
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/distribution"
)

func TestNonCryptedBlob(t *testing.T) {
	assert := assert.New(t)

	contentType := distribution.MediaTypeImageConfig
	size := int64(0)
	d := digest.Canonical.FromString("Hello")
	filename := "/"

	tests := []struct {
		blob distribution.Blob
	}{
		{distribution.NewConfig(
			filename,
			d,
			size,
			nil,
		)},
		{distribution.NewPlainConfig(
			filename,
			d,
			size,
		)},
	}

	for _, test := range tests {
		_ = assert.Equal(contentType, test.blob.GetContentType()) && assert.Equal(size, test.blob.GetSize()) && assert.Equal(d.String(), test.blob.GetDigest().String()) && assert.Equal(filename, test.blob.GetFilename())
		test.blob.SetFilename("\\")
		assert.Equal("\\", test.blob.GetFilename())
	}
}
