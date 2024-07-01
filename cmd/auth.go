/*
 * Copyright 2020 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/netflix/weep/pkg/logging"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(authCmd)
}

var authCmd = &cobra.Command{
	Use:   "login",
	Short: loginShortHelp,
	Long:  loginLongHelp,
	RunE:  runLogin,
}

func userLogin() (string, error) {
	// Get environment variables
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")

	if tenantID == "" || clientID == "" {
		log.Fatalf("Environment variables AZURE_TENANT_ID, AZURE_CLIENT_ID must be set.")
	}

	cred, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
		TenantID: tenantID,
		ClientID: clientID,
	})
	if err != nil {
		log.Fatalf("Failed to create credential")
		return "", err
	}

	// Use the credential to get a token
	token, err := cred.GetToken(context.TODO(), policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return "", err
	}

	fmt.Printf("Successfully authenticated. Access Token")

	return token.Token, nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	rolesData, err := userLogin()
	if err != nil {
		logging.LogError(err, "Error loggin into User Account")
		return err
	}
	cmd.SetOut(os.Stdout)
	cmd.Println(rolesData)
	return nil
}
