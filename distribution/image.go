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

package distribution

// ImageManifest represents a docker image manifest schema v2.2
type ImageManifest struct {
	SchemaVersion int      `json:"schemaVersion"`
	MediaType     string   `json:"mediaType"`
	Config        *Layer   `json:"config"`
	Layers        []*Layer `json:"layers"`
	DirName       string   `json:"-"`
}