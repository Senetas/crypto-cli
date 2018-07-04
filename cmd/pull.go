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
	"github.com/spf13/cobra"

	"github.com/Senetas/crypto-cli/images"
)

// pullCmd represents the pull command
var pullCmd = &cobra.Command{
	Use:   "pull [OPTIONS] NAME[:TAG]",
	Short: "Pull an image from a remote repository, decrypting if necessary.",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPull(args[0])
	},
	Args: cobra.ExactArgs(1),
}

func runPull(remote string) error {
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return err
	}

	if err = images.PullImage(&ref); err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(pullCmd)

	pullCmd.Flags().StringVarP(&passphrase, "pass", "p", "", "Specifies the passphrase to use if passphrase encryption is selected")
	pullCmd.Flags().StringVarP(&cryptotype, "type", "t", "", "Specifies the type of encryption to use.")
}
