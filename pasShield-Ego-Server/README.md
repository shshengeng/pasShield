pasShield - Server-side Password Protection
==========================================================================

Introduction
------------

We have implemented a server-side password protection service using Edgeless Systems‘s recent EGO base on Software Guard Extensions (SGX). However, pasShield can use any equivalent Trusted Execution Environment (TEE) that provides isolated execution, sealed storage, and remote attestation. We chose EGO for its ease of use, superior performance.

Our SGX enclave design is kept minimalistic, consisting of only four Function calls; see Listing 1
- When the enclave is started for the first time, the init() function uses Intel's true random number generator (via the RDRAND instruction) to generate a new strong random SafeKey. 
- When the enclave is later restarted, this function is used to pass previously-sealed data to the enclave. The genHmac() function calculates the keyed one-way function on the password using the SafeKey and returns the result. We use the crypto-128 HMAC function, as this meets our security requirements and can be computed using the AES-NI hardware extensions. 
- The reset_attempts() function forms part of our in-enclave rate-limiting mechanism. 
- The shutdown() function is used to perform a graceful shutdown of the enclave (e.g., in case the server needs to reboot). This function seals the SafeKey and the current state of the enclave.

Listing 1:
```sh
initialize(in(database),out(hmacKey,salt_with_attempt, resetTime, err));
genHmac(in(salting,hmacKey), out(hmac));
resetAttempts(salt_with_attempt, resetTime, maxAttempts);
shutdown ( out_sealed ( key || attempts ));
```


Building instructions
---------------------
- make sure change the directory in the mouts of enclave.json to the directory of your own:
```sh
 "securityVersion": 2,
    "mounts": [
        {
            "source": "/the directory of your own",
            "target": "/the directory of your own",
            "type": "hostfs",
            "readOnly": false
        }
    ],
```

- Building and running a confidential Go app is as easy as:
```sh
ego-go build server.go
ego sign server
ego run server
```

 Rate Limiting
------------
Rate Limiting. In addition to rate limiting at the web server level (e.g. using Captchas after a certain number of failed attempts), we also implement a rate limiting algorithm in our TEE-protected password service . Our enclave program maintains a memory map (using golang  make(map[string]int)) that associates each salt with the remaining number of attempts(salt_with_attempt) . For maximum flexibility, our implementation uses a string salt and a int integer as salt_with_attempt, but this value can be reduced if memory consumption needs to be minimized.

When the Login() http.Handle function for is called, the function first checks the value of salt_with_attempt[salt]; if the value is zero, the function only returns an error; otherwise, salt_with_attempt is decremented by 1, and the HMAC result is returned. The enclave stores reset_attempts, which is the time at which all attempt values are reset to a predefined value attemptsmax. When reset_attempts() is called, the function first gets the current time; then, if the reset has already passed, all attempt values are set to attemptsmax and the reset is incremented by a predefined value.

To allow the enclave to restart (e.g. if the server restarts), the shutdown() function is used to securely store the state information outside the enclave. Specifically, the enclave seals the mapping of SafeKey, salt and attempt values, reset time. This sealed data can be restored to the enclave using the init() function. 

A malicious server may attempt to reset the attempt values by abruptly terminating the enclave without first sealing its state. However, the enclave will detect this and raise an exception to prevent such attacks.

Remote attestation
------------
Go remote attestation using Microsoft Azure Attestation
The remote attestation of an EGo enclave in combination with [Microsoft Azure Attestation](https://docs.microsoft.com/en-us/azure/attestation/). It consists of a server running in an enclave and a client (the relying party) that attests the server before sending a secret. The Azure Attestation Provider simplifies the attestation process for the client.

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

