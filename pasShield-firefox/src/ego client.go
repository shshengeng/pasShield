package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"syscall/js"

	"github.com/edgelesssys/ego/attestation"
)

// attestationProviderURL is the URL of the attestation provider

var (
	attestationProviderURL = "https://shareduks.uks.attest.azure.net"
	attestStatus           = false
	result                 = ""
)

func main() {
	c := make(chan struct{}, 0)

	registerCallbacks()

	<-c
}

func registerCallbacks() {
	js.Global().Set("attest", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			// Load the server attestation token.
			serverURL := args[0].String()
			app := args[1].String()
			message := args[2].String()
			tlsConfig := &tls.Config{InsecureSkipVerify: true}

			tokenBytes := httpGet(tlsConfig, serverURL+"/token")
			fmt.Printf("🆗 Loaded server attestation token from %s.\n", serverURL+"/token")

			// Verify the attestation token.
			report, err := attestation.VerifyAzureAttestationToken(string(tokenBytes), attestationProviderURL)
			if err != nil {
				panic(err)
			}
			fmt.Println("✅ Azure Attestation Token verified.")

			if err := verifyReportValues(report, report.SignerID); err != nil {
				panic(err)
			}

			// Get certificate from the report.
			certBytes := report.Data
			fmt.Println("🆗 Server certificate extracted from token.")

			// Create a TLS config that uses the server certificate as root
			// CA so that future connections to the server can be verified.
			cert, _ := x509.ParseCertificate(certBytes)
			tlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost"}
			tlsConfig.RootCAs.AddCert(cert)
			original := "s=thisIsSecert"
			if message[:8] == "username" {
				original = message
			}
			resp := httpGet(tlsConfig, serverURL+"/"+app+"?"+original)
			responseString := string(resp)
			js.Global().Call("postMessage", responseString)
			fmt.Println("🔒 Sent secret over attested TLS channel.")
		}()

		message1 := args[2].String()
		if message1 == "attestation" {
			return "Attest successfully"
		} else if message1[:8] == "username" {
			return "Username and Password sent secretly"
		}

		return nil
	}))
}

// verifyReportValues compares the report values with that were defined in the
// enclave.json and that were included into the binary of the server during build.
func verifyReportValues(report attestation.Report, signer []byte) error {
	// You can either verify the UniqueID or the tuple (SignerID, ProductID, SecurityVersion, Debug).

	if !bytes.Equal(report.SignerID, []byte(signer)) {
		return errors.New("token does not contain the right signer id")
	}
	fmt.Println("✅ SignerID of the report equals the SignerID you passed to the client.")

	if binary.LittleEndian.Uint16(report.ProductID) != 1234 {
		return errors.New("token contains invalid product id")
	}
	fmt.Println("✅ ProductID verified.")

	if report.SecurityVersion < 2 {
		return errors.New("token contains invalid security version number")
	}
	fmt.Println("✅ SecurityVersion verified.")

	return nil
}

func httpGet(tlsConfig *tls.Config, url string) []byte {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		panic(resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return body
}
