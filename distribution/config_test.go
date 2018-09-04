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
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
)

var config = []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":null,"ArgsEscaped":true,"Image":"sha256:5a351dc6eee242bc8a4e2fb15fe7985b3f553a4dc5e2ad82fb4ecca301622a61","Volumes":null,"WorkingDir":"","Entrypoint":["/bin/sh"],"OnBuild":null,"Labels":{"com.senetas.crypto.enabled":"true"}},"container":"67c38be74a1fddc90908698b7e724f26744bd05018163011b0aaf29d2d413aa7","container_config":{"Hostname":"67c38be74a1f","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","ENTRYPOINT [\"/bin/sh\"]"],"ArgsEscaped":true,"Image":"sha256:5a351dc6eee242bc8a4e2fb15fe7985b3f553a4dc5e2ad82fb4ecca301622a61","Volumes":null,"WorkingDir":"","Entrypoint":["/bin/sh"],"OnBuild":null,"Labels":{"com.senetas.crypto.enabled":"true"}},"created":"2018-07-11T01:56:47.38138392Z","docker_version":"18.05.0-ce","history":[{"created":"2018-01-09T21:10:58.365737589Z","created_by":"/bin/sh -c #(nop) ADD file:093f0723fa46f6cdbd6f7bd146448bb70ecce54254c35701feeceb956414622f in / "},{"created":"2018-01-09T21:10:58.579708634Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2018-07-11T01:56:43.359869986Z","created_by":"/bin/sh -c #(nop)  LABEL com.senetas.crypto.enabled=true","empty_layer":true},{"created":"2018-07-11T01:56:45.1510526Z","created_by":"/bin/sh -c echo \"hello\" \u003e file.txt"},{"created":"2018-07-11T01:56:46.436482883Z","created_by":"/bin/sh -c rm file.txt"},{"created":"2018-07-11T01:56:47.38138392Z","created_by":"/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:cd7100a72410606589a54b932cabd804a17f9ae5b42a1882bd56d263e02b6215","sha256:2255988eab05d4aa6c41d4b8ead52dc329cca811fcedbeb2c3eddf997f6d0c38","sha256:6ef624ce93872b025415857f16bc01d5bbac005d197e7c45eb2c6fc93fd61c03"]}}`)

func TestUnMarshalling(t *testing.T) {
	require := require.New(t)

	val := distribution.NewDecConfig()
	err := json.Unmarshal(config, val)
	require.NoError(err)

	config2, err := json.Marshal(val)
	require.NoError(err)

	require.Equal(config, config2)

	t.Log(spew.Sprint(val))

	val2 := distribution.NewDecConfig()
	err = json.Unmarshal(config2, val2)
	require.NoError(err)

	require.Equal(val, val2)

	key := make([]byte, 32)
	_, err = rand.Read(key[:])
	require.NoError(err)

	opts := &crypto.Opts{
		EncType: crypto.Pbkdf2Aes256Gcm,
	}
	opts.SetPassphrase("hunter2")

	salt := []byte("0123456789012345")

	ec, err := val.Encrypt(key, salt)
	require.NoError(err)

	dc, err := ec.Decrypt(key, opts)
	require.NoError(err)

	require.Equal(val, dc)
}
