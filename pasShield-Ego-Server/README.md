pasShield - Server-side Password Protection
==========================================================================

Introduction
------------

We have implemented a server-side password protection service using Edgeless Systems‘s recent EGO base on Software Guard Extensions (SGX). However, pasShield can use any equivalent Trusted Execution Environment (TEE) that provides isolated execution, sealed storage, and remote attestation. We chose EGO for its ease of use, superior performance.

Our SGX enclave design is kept minimalistic, consisting of only four Function calls; see Listing 1. When the enclave is started for the first time, the init() function uses Intel's true random number generator (via the RDRAND instruction) to generate a new strong random SafeKey. When the enclave is later restarted, this function is used to pass previously-sealed data to the enclave. The process() function calculates the keyed one-way function on the password using the SafeKey and returns the result. We use the Rijndael-128 HMAC function, as this meets our security requirements and can be computed using the AES-NI hardware extensions. The reset_attempts() function forms part of our in-enclave rate-limiting mechanism. The shutdown() function is used to perform a graceful shutdown of the enclave (e.g., in case the server needs to reboot). This function seals the SafeKey and the current state of the enclave.

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


