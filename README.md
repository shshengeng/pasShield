pasShield - Protecting Web Passwords using Intel SGX
==========================================================================

Introduction
------------

pasShield is a server-side technology for protecting password databases. pasShield's server-side password protection service is a drop-in replacement for standard password hashing functions. It computes a Hash-based message authentication code(HMAC) on passwords before they are stored in the
database. An adversary must obtain the HMAC key in order to perform offline guessing attacks against a stolen password database. SafeKeeper generates and protects this key within a Trusted Execution Environment, realized using Ego SDK.


Building instructions
---------------------

### Prerequisites

- Install Ego SDK, The easiest way to install EGo is via the snap:
```sh
sudo snap install ego-dev --classic
```

You also need `gcc` and `libcrypto`. On Ubuntu install them with:
```sh
sudo apt install build-essential libssl-dev
```

### Building and run
- Building and running a confidential Go app is as easy as:
```sh
ego-go build hello.go
ego sign hello
ego run hello
```


[![PkgGoDev][go-pkg-badge]][go-pkg]

<!-- refs -->
[github-actions]: https://github.com/edgelesssys/ego/actions
[github-actions-badge]: https://github.com/edgelesssys/ego/workflows/Unit%20Tests/badge.svg
[go-pkg]: https://pkg.go.dev/github.com/edgelesssys/ego
[go-pkg-badge]: https://pkg.go.dev/badge/github.com/edgelesssys/ego
[go-report-card]: https://goreportcard.com/report/github.com/edgelesssys/ego
[go-report-card-badge]: https://goreportcard.com/badge/github.com/edgelesssys/ego
[license-badge]: https://img.shields.io/github/license/edgelesssys/ego
[discord]: https://discord.gg/rH8QTH56JN
[discord-badge]: https://img.shields.io/badge/chat-on%20Discord-blue

For developper:
-----------------
Server side should install python server and passhield ego server, git clone this repo:

Python Server Installation
---------------
First clone this repo, then run app.py under backend folder in background, you run it by gunicorn(that's we used). You cao do it like this:
```
pip3 install gunicorn\
gunicorn -w 4 -b 127.0.0.1:5001 app.py
```

Make sure install depencies first:
```
pip3 install -r requirements.txt
```

PasShield Ego server Installation
----------------------------------

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


For user/client:
-----------------
Passhield Webaddon Installation:
---------------------------------
To install the extension, make sure you have installed firefox browser(this addon is built for firefox) and downlowned the passhield-firefox code in your own computer, open the firefox and input address about:debugging, then click 'this firefox' on left side, then click 'Load Temporary Add-on', select the manifest.json under pasShield-firefox folder. Then, you are all set to use pasShield.