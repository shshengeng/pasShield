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

[![GitHub Actions Status][github-actions-badge]][github-actions]
[![Go Report Card][go-report-card-badge]][go-report-card]
[![PkgGoDev][go-pkg-badge]][go-pkg]
[![Discord Chat][discord-badge]][discord]


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
