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
	"fmt"
	"syscall"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

var (
	passphrase string
	ctstr      string
	//cfgFile    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "crypto-cli [OPTIONS] [command]",
	Short: "A command line utility to encrypt and decrypt docker images and store them in docker registries",
	Long: `Crypto-Cli is a command line utility to encrypt and decrypt docker images and stores
them in repositories online. It maybe used to distribute docker images
confidentially. It does not sign images so cannot garuntee identities.


Its basic operations emulated docker push and docker pull and will encrypt then
MAC the images before uploading them, and check the MAC and decrypt after
downloading them.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		e, ok := errors.Cause(err).(utils.Error)
		if ok && !e.HasStack {
			log.Fatal().Msgf("%v", err)
		}
		log.Fatal().Msgf("%+v", err)
	}
}

func init() {
	//cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.crypto-cli.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
//func initConfig() {
//if cfgFile != "" {
//// Use config file from the flag.
//viper.SetConfigFile(cfgFile)
//} else {
//// Find home directory.
//home, err := homedir.Dir()
//if err != nil {
//log.Fatal().Msgf("%+v", err)
//}

//// Search config in home directory with name ".crypto-cli" (without extension).
//viper.AddConfigPath(home)
//viper.SetConfigName(".crypto-cli")
//}

//viper.AutomaticEnv() // read in environment variables that match

//// If a config file is found, read it in.
//if err := viper.ReadInConfig(); err == nil {
//fmt.Println("Using config file:", viper.ConfigFileUsed())
//}
//}

func checkFlags(f *pflag.Flag) {
	switch f.Name {
	case "pass":
		if !f.Changed {
			passphrase = getPassSTDIN()
		}
	default:
	}
}

func getPassSTDIN() string {
	fmt.Print("Enter Passpharase: ")
	passphrase, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		log.Fatal().Err(errors.Wrapf(err, "password typed: %s", passphrase)).Msg("")
	}
	fmt.Println()
	return string(passphrase)
}

func validateCryptoType(ctstr string) (crypto.EncAlgo, error) {
	if ctstr == string(crypto.None) {
		return crypto.None, nil
	} else if ctstr == string(crypto.Pbkdf2Aes256Gcm) {
		return crypto.Pbkdf2Aes256Gcm, nil
	}
	return crypto.EncAlgo(""), errors.New("invalid encryption type")
}
