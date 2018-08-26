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
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		opts.EncType, err = crypto.ValidateAlgos(ctstr)
		if err != nil {
			return err
		}
		cmd.Flags().VisitAll(checkFlagsPush)
		return runPush(args[0], &opts)
	},
	Args: cobra.ExactArgs(1),
}

func checkFlagsPush(f *pflag.Flag) {
	switch f.Name {
	case "pass":
		if opts.EncType != crypto.None {
			if !f.Changed {
				var err error
				passphrase, err = crypto.GetPassSTDIN("Enter passphrase: ", crypto.StdinPassReader)
				if err != nil {
					log.Fatal().Err(err).Msgf("Could not obtain passphrase")
				}

				passphrase1, err := crypto.GetPassSTDIN("Re-enter passphrase: ", crypto.StdinPassReader)
				if err != nil {
					log.Fatal().Err(err).Msgf("Could not obtain passphrase")
				}

				if passphrase != passphrase1 {
					log.Fatal().Msg("Passphrases do not match.")
				}
			}
			opts.SetPassphrase(passphrase)
		}
	default:
	}
}

func runPush(remote string, opts *crypto.Opts) error {
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return err
	}
	log.Info().Msgf("Pushing image: %s.", ref)
	return images.PushImage(ref, opts)
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
	pushCmd.Flags().StringVarP(
		&ctstr,
		"type",
		"t",
		string(crypto.Pbkdf2Aes256Gcm),
		"Specifies the type of encryption to use.",
	)
}
