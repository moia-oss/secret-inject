/*
Copyright 2021 MOIA GmbH.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/moia-dev/secret-inject/await"
	"github.com/moia-dev/secret-inject/config"
	"github.com/moia-dev/secret-inject/exec"
	"github.com/moia-dev/secret-inject/inject"
	"github.com/spf13/cobra"
)

// package vars

var (
	verboseFlag  bool
	confFileFlag string

	awaitCmd = &cobra.Command{
		Use:   "await",
		Short: "Waits for credentials and provides them to the CI pipeline",
		Run:   awaitCmdHandle,
	}
	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validates the application config",
		Run:   validateCmdHandle,
	}
	execCmd = &cobra.Command{
		Use:   "exec [stage] [command to execute]",
		Short: "Executes a command with the AWS credentials of the stage, i.e. with the role assumed",
		Run:   execCmdHandle,
		Args:  cobra.MinimumNArgs(2),
	}
	injCmd = &cobra.Command{
		Use:   "inject [execution-id]",
		Short: "Injects credentials into the CI workflow",
		Run:   injectCmdHandle,
		Args:  cobra.MinimumNArgs(1),
	}
	rootCmd = &cobra.Command{
		Use:   "secret-inject",
		Short: "Manages injection of short-term AWS credentials into CI/CD workflows",
	}
)

// utility functions

func handleVerbosity() {
	if verboseFlag {
		log.Println("Using verbose mode.")
	} else {
		log.SetOutput(ioutil.Discard)
	}
}

func handleConfigLoading() config.ApplicationConfig {
	conf, err := config.LoadAndParseConf(confFileFlag)

	if err != nil {
		fmt.Printf("Unable to find or parse config file. Config file is searched for in current dir and Git top-level, if applicable. "+
			"You could also provide a config file location via `--config`. The error encountered was: %v\n", err)
		os.Exit(1)
	}

	err = conf.Validate()
	if err != nil {
		fmt.Printf("Validation of config failed: %v\n", err)
		os.Exit(1)
	}

	return conf
}

func handleCommonCmdSetup() (config.ApplicationConfig, *session.Session) {
	handleVerbosity()

	conf := handleConfigLoading()

	sess, err := session.NewSession()
	if err != nil {
		log.Println("Getting an AWS Session failed. Make sure you are executing the utility with AWS credentials. " +
			"E.g. if you use aws-vault you might use `aws-vault exec [your-root-profile] -- secret-inject ...`")
		os.Exit(1)
	}

	return conf, sess
}

// Cmd handlers

func awaitCmdHandle(cmd *cobra.Command, args []string) {
	conf, sess := handleCommonCmdSetup()

	handler := await.NewHandler(conf, sess)

	fmt.Printf("Please push credentials by running: `secret-inject inject %s` in your repo.\n",
		handler.PromptUser(),
	)

	creds, timeoutReached, err := handler.Await()
	if err != nil {
		fmt.Printf("Error while awaiting credentials: %v\n", err)
		os.Exit(1)
	}

	if timeoutReached {
		fmt.Println("Timed out waiting for credentials.")
		os.Exit(1)
	}

	err = creds.PersistToDisk(conf.CredentialsPathOrDefault())
	if err != nil {
		fmt.Printf("Error when attempting to write credential-set to disk: %v\n", err)
		os.Exit(1)
	}

	err = handler.NotifyUserIfConfigured()
	if err != nil {
		fmt.Printf("Error when attempting to notify users: %v\n", err)
		os.Exit(1)
	}
}

func validateCmdHandle(cmd *cobra.Command, args []string) {
	handleVerbosity()

	_ = handleConfigLoading()
}

func execCmdHandle(cmd *cobra.Command, args []string) {
	handleVerbosity()

	conf := handleConfigLoading()
	h := exec.NewHandler(conf)

	exitErr, err := h.Execute(args[0], args[1:])
	if err != nil {
		fmt.Printf("Error while exeuting command(s) '%s': %v\n", strings.Join(args[1:], " "), err)

		if exitErr != nil {
			os.Exit(exitErr.ExitCode())
		}

		os.Exit(-1)
	}
}

func injectCmdHandle(cmd *cobra.Command, args []string) {
	conf, sess := handleCommonCmdSetup()

	handler := inject.NewHandler(sess, conf)

	err := handler.Inject(args[0])
	if err != nil {
		fmt.Printf("Encountered error trying to inject credential set: %v\n", err)
		os.Exit(1)
	}
}

// main func

func main() {
	rootCmd.AddCommand(awaitCmd, injCmd, execCmd, validateCmd)

	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVarP(&confFileFlag, "config", "c", "",
		"Config file path (by default current dir and Git repo top-level are checked)")

	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	os.Exit(1)
}
