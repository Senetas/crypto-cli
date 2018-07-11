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

package cmd

import (
	"github.com/docker/distribution/reference"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/images"
)

// pushCmd represents the push command
var pushCmd = &cobra.Command{
	Use:   "push [OPTIONS] NAME[:TAG]",
	Short: "Encrypt an image and then pushed it to a remote repository.",
	Long: `push will encrypt a docker images and upload it
to a remote repositories. It maybe used to distribute docker images
confidentially. It does not sign images so cannot garuntee identities.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Flags().VisitAll(checkFlags)
		cryptotype, err := validateCryptoType(ctstr)
		if err != nil {
			return err
		}
		return runPush(args[0], passphrase, cryptotype)
	},
	Args: cobra.ExactArgs(1),
}

func runPush(remote, passphrase string, cryptotype crypto.EncAlgo) error {
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return errors.Wrapf(err, "remote = ", remote)
	}

	if err = images.PushImage(ref, passphrase, cryptotype); err != nil {
		return errors.Wrapf(err, "ref = %v, cryptotype = %v", ref, cryptotype)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(pushCmd)

	pushCmd.Flags().StringVarP(&passphrase, "pass", "p", "", "Specifies the passphrase to use if passphrase encryption is selected")
	pushCmd.Flags().StringVarP(&ctstr, "type", "t", string(crypto.Pbkdf2Aes256Gcm), "Specifies the type of encryption to use.")
}
