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
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/netflix/weep/pkg/logging"
	"github.com/spf13/cobra"

	vault "github.com/hashicorp/vault/api"
)

func init() {
	rootCmd.AddCommand(authCmd)
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: loginShortHelp,
	Long:  loginLongHelp,
	RunE:  runLogin,
}

func userLogin() error {
	// Get environment variables
	TENANTID := os.Getenv("AZURE_TENANT_ID")
	CLIENTID := os.Getenv("AZURE_CLIENT_ID")
	VAULT_ADDR := os.Getenv("VAULT_ADDR") // Vault address, e.g., http://127.0.0.1:8200
	VAULT_ROLE := os.Getenv("VAULT_ROLE")
	ROOT_TOKEN := "root"
	CERT_PATH := os.Getenv("CERT_PATH")

	if TENANTID == "" || CLIENTID == "" {
		log.Fatalf("Environment variables AZURE_TENANT_ID, AZURE_CLIENT_ID must be set.")
	}

	cred, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
		TenantID: TENANTID,
		ClientID: CLIENTID,
		// RedirectURL: redirectURL,
	})
	if err != nil {
		log.Fatalf("Failed to create credential: %v", err)
		return err
	}

	// Open browser and wait for the token
	fmt.Println("Opening browser for authentication...")
	token, err := cred.GetToken(context.TODO(), policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
		return err
	}

	fmt.Println("Successfully authenticated with Microsoft: ", token.Token[1:9])
	//////////////////////////////////////////////////////////////////////

	os.Setenv("VAULT_ADDR", VAULT_ADDR)

	// Initialize a Vault client with TLS verification disabled
	config := vault.DefaultConfig()
	tlsConfig := &vault.TLSConfig{
		Insecure: true,
	}
	if err := config.ConfigureTLS(tlsConfig); err != nil {
		log.Fatalf("Unable to configure TLS: %v", err)
	}

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("Unable to initialize Vault client: %v", err)
	}

	// Authenticate with the Vault token
	client.SetToken(ROOT_TOKEN)

	// Define the parameters for the certificate generation
	data := map[string]interface{}{
		"common_name": "sudoconsultant.com",
		"ttl":         "24h",
	}

	// Generate the certificate
	secret, err := client.Logical().Write(VAULT_ROLE, data)
	if err != nil {
		log.Fatalf("Unable to generate certificate: %v", err)
	}

	// Get certificate details
	certificate, ok := secret.Data["certificate"].(string)
	if !ok {
		log.Fatalf("Expected certificate to be a string")
	}

	privateKey, ok := secret.Data["private_key"].(string)
	if !ok {
		log.Fatalf("Expected private_key to be a string")
	}

	// Handle CA Chain which is typically a list of strings
	caChainIface, ok := secret.Data["ca_chain"].([]interface{})
	if !ok {
		log.Fatalf("Expected ca_chain to be a list of strings")
	}

	// Convert []interface{} to []string
	var caChain []string
	for _, iface := range caChainIface {
		str, ok := iface.(string)
		if !ok {
			log.Fatalf("Expected ca_chain element to be a string")
		}
		caChain = append(caChain, str)
	}

	// Create the directory if it does not exist
	dir := filepath.Join(os.Getenv("HOME"), CERT_PATH)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("Unable to create directory %s: %v", dir, err)
	}

	// Write certificate to file
	if err := writeToFile(filepath.Join(dir, "mtls.crt"), certificate); err != nil {
		log.Fatalf("Unable to write certificate to file: %v", err)
	}

	// Write private key to file
	if err := writeToFile(filepath.Join(dir, "mtls.key"), privateKey); err != nil {
		log.Fatalf("Unable to write private key to file: %v", err)
	}

	// Write CA chain to file
	if err := writeToFile(filepath.Join(dir, "mtlsCA.key"), strings.Join(caChain, "\n")); err != nil {
		log.Fatalf("Unable to write CA chain to file: %v", err)
	}

	fmt.Println("Certificate, private key, and CA chain have been written to ", CERT_PATH)

	return nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	err := userLogin()
	if err != nil {
		logging.LogError(err, "Error loggin into User Account")
		return err
	}
	cmd.SetOut(os.Stdout)
	cmd.Println("Sucessfull")
	return nil
}

// writeToFile writes the given content to a file with the given filename.
func writeToFile(filename, content string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}
