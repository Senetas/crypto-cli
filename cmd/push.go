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
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
		cmd.Flags().VisitAll(checkFlagsPush)
		return runPush(args[0], opts)
	},
	Args: cobra.ExactArgs(1),
}

func checkFlagsPush(f *pflag.Flag) {
	switch f.Name {
	case "pass":
		if !f.Changed {
			passphrase1 := getPassSTDIN("Enter passphrase: ")
			passphrase2 := getPassSTDIN("Re-enter passphrase: ")
			if passphrase1 == passphrase2 {
				opts.Passphrase = passphrase1
			} else {
				log.Fatal().Msg("Passphrases do not match.")
			}
		}
	}
}

func runPush(remote string, opts crypto.Opts) error {
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return err
	}

	if err = images.PushImage(ref, opts); err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(pushCmd)

	pushCmd.Flags().BoolVar(
		&opts.Compat,
		"compat",
		false,
		`whether manifests should be compatible with the Docker image manifest schema v2.2
or a slight modfication of it`,
	)
}
