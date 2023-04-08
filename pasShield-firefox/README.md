pasShield - Protecting Web Passwords using Intel SGX
=========================================================
Introduction
--------------
pasShield is a server-side technology for protecting password databases. For users who use pasShield, they need to install the web extension of pasShield in the local Firefox browser. This web extension will perform remote attestation on the accessed server. If the server is safe, the extension icon will be changed and the highlight input fields will be be sent. For the server side of pasShield, the password protection service is a direct replacement for the standard password hash function. It computes a hash-based message authentication code (HMAC) before storing the password in the database. An adversary must obtain the HMAC key to perform an offline guessing attack on a stolen password database. Pashield generates and secures this key in a Trusted Execution Environment implemented using the Ego SDK.

Installation
--------------
To install the extension, make sure you have installed firefox browser(this addon is built for firefox) and downlowned the passhield-firefox code in your own computer, open the firefox and input about:addons, then click settings is on the same line as 'manage your extensions', then choose 'install add-on from file'

Remote attestation
---------------------
Go remote attestation using Microsoft Azure Attestation. The remote attestation of an EGo enclave in combination with [Microsoft Azure Attestation](https://docs.microsoft.com/en-us/azure/attestation/). It consists of a server running in an enclave and a client (the relying party) that attests the server before sending a secret. The Azure Attestation Provider simplifies the attestation process for the client.

**Note: This sample only works on SGX-FLC systems with a [quote provider](https://docs.edgeless.systems/ego/reference/attest) installed.**

## How it works

![azure attestation sample](illustration.svg)

1. The server generates a self-signed certificate and a report for remote attestation that includes the certificate's hash. It thereby binds the certificate to the enclave's identity.

1. An Attestation Request containing the report and the gernerated certificate is sent from the server to the Azure Attestation Provider. In this example, a [Regional Shared Provider](https://docs.microsoft.com/en-us/azure/attestation/basic-concepts#regional-shared-provider) is used, but it is also possible to run one's own Attestation Provider.

1. The Azure Attestation Provider validates the Quote, which is part of the report, and ensures that the report contains the hash of the Enclave Held Data, which in this case is the self-signed certificate.

1. If the validation succeeds, the Attestation Provider generates a signed JSON Web Token (JWT) and returns the token to the server in the Attestation Response. The token contains the Enclave Held Data (the certificate) and information for the token verification.

1. The server runs HTTPS and provides the following endpoints to the client:
    * `/token` returns the JSON Web Token. The client requests the token skipping TLS certificate verification.
    * `/secret` receives the secret via a query parameter named `s`.

1. From the Attestation Provider's OpenID Metadata Endpoint, the client queries the public key which the token was signed with. In this case, we need to ensure the channel used to get the signing keys is secure by using TLS.

1. The client verifies the token's signature and the claims from the token body. If the token is valid and contains the correct report, the identity and integrity of the server is guranteed. The certificate is extracted from the report.

The client can now establish a secure TLS connection to the enclaved server using the validated certificate and send its secret.

EGo's API provides helpful functions to simplify the remote attestation with Microsoft Azure Attestation. The server can use the [CreateAzureAttestationToken()](https://pkg.go.dev/github.com/edgelesssys/ego/enclave#CreateAzureAttestationToken) function form the enclave package to conduct steps 1 - 4 and get the token. The client can use the [VerifyAzureAttestationToken()](https://pkg.go.dev/github.com/edgelesssys/ego/attestation#VerifyAzureAttestationToken) function from EGo's attestation package to perform steps 6 and 7. While this function verifies the signature and the public claims of the token, the client has to verify the resulting report values.

Highlight input fields
----------------------------
When pasShield successfully authenticates the accessed server, it will highlight the input tag that needs to be encrypted. If the server authentication is successful, a global variable sgx_enabled will become true, and the content script will monitor this value. When it is true, the content script will get the input tag objects whose name is username and password, and change the border color of this object to green, and a div will be added behind them to show that this data will be sent through a secure channel.
