pasShield - Server-side Password Protection
==========================================================================

Introduction
------------

We have implemented a server-side password protection service using Edgeless Systems‘s recent EGO base on Software Guard Extensions (SGX). However, pasShield can use any equivalent Trusted Execution Environment (TEE) that provides isolated execution, sealed storage, and remote attestation. We chose EGO for its ease of use, superior performance.

Our SGX enclave design is kept minimalistic, consisting of only four ecalls; see Listing 1. When the enclave is started for the first time, the init() function uses Intel's true random number generator (via the RDRAND instruction) to generate a new strong random SafeKey. When the enclave is later restarted, this function is used to pass previously-sealed data to the enclave. The process() function calculates the keyed one-way function on the password using the SafeKey and returns the result. We use the Rijndael-128 HMAC function, as this meets our security requirements and can be computed using the AES-NI hardware extensions. The reset_attempts() function forms part of our in-enclave rate-limiting mechanism. The shutdown() function is used to perform a graceful shutdown of the enclave (e.g., in case the server needs to reboot). This function seals the SafeKey and the current state of the enclave.

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

