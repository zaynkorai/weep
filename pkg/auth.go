/*
 * Copyright 2024 Sudoconsultants, Inc.
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
	"github.com/spf13/viper"

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
	tenant_id := viper.GetString("azure.tenant_id")
	client_id := viper.GetString("azure.client_id")
	vault_addr := viper.GetString("vault.address") // Vault address, e.g., http://127.0.0.1:8200
	vault_role := viper.GetString("vault.role")
	vault_token := viper.GetString("vault.token")
	certs_path := viper.GetString("mtls_settings.path")
	certs_ttl := viper.GetString("mtls_settings.ttl")
	certs_common_name := viper.GetString("mtls_settings.common_name")

	if tenant_id == "" || client_id == "" {
		log.Fatalf("Environment variables AZURE tenant id, AZUR client id must be set.")
	}

	cred, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
		TenantID: tenant_id,
		ClientID: client_id,
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

	os.Setenv("vault_addr", vault_addr)

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
	client.SetToken(vault_token)

	// Define the parameters for the certificate generation
	data := map[string]interface{}{
		"common_name": certs_common_name,
		"ttl":         certs_ttl,
	}

	// Generate the certificate
	secret, err := client.Logical().Write(vault_role, data)
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
	dir := filepath.Join(certs_path)
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

	fmt.Println("Certificate, private key, and CA chain have been written to ", certs_path)

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
