[![Go Report Card](https://goreportcard.com/badge/github.com/Senetas/crypto-cli)](https://goreportcard.com/report/github.com/Senetas/crypto-cli)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat)](https://raw.githubusercontent.com/Senetas/crypto-cli/master/LICENSE)

# Crypto-Cli

A command line utility to push and pull encrypted docker images. Currently, it only runs on Linux with Linux images. See also the privacy section below.

## Warning
This application is not suitable for use in a production environment. There are no guarantees as to the security of these implementations. Use at your own risk...that being said we make a concerted effort on the crypto side. See the cryptography section below.

## Issues
Don't try to pull an encrypted image with `docker pull`, it will fail.

## License
Apache 2.0

## Prerequisites
Ensure that `docker` and `go` are installed and that `$GOPATH` has been set and that `$GOPATH/bin` is in the `$PATH`.
This document assumes that `docker` may be run without prefixing it with `sudo`, for a guide on how to achieve this, see <https://docs.docker.com/install/linux/linux-postinstall/>.

## Installation
```console
go get github.com/Senetas/crypto-cli
```

## Usage
For now the syntax is limited to:
```console
crypto-cli (push|pull) NAME:TAG [opts]
```
Here, `NAME` is the name of a repository and `TAG` is a mandatory tag. For a `push` command, the image `NAME:TAG` must be present in the local docker engine.

To specify which layers to encrypt, insert the line
```Dockerfile
LABEL com.senetas.crypto.enabled=true
```
in the `Dockerfile` before building the image.
Any layers that result from lines in the docker file between this and the next
```Dockerfile
LABEL com.senetas.crypto.enabled=false
```
or the end of the file or stage will be encrypted.
As many of these may be specified to encrypt any nonempty subset of the layers that is disjoint from the base image.

However, the typical usage is expected to have the `Dockerfile` containing exactly one `com.senetas.crypto.enabled=true` after the initial `FROM`.
This will leave the base image unencrypted but encrypt any layers created on top of it.

For example, in the following Dockerfile:
```Dockerfile
FROM alpine:latest
LABEL "com.senetas.crypto.enabled"="true"
RUN echo "some secret" > secret-file.txt
LABEL "com.senetas.crypto.enabled"="false"
RUN echo "some not secret" > not-secret-file.txt
ENTRYPOINT ["/bin/sh"]
```
only the layer resulting from the command `RUN echo "some secret" > secret-file.txt` will be encrypted.

Note that although in general a `LABEL` line may contain multiple labels, this is not supported for the `com.senetas.crypto.enabled` label for the purposes of this application.

### Global Options

#### `--pass=<PASSPHRASE>`
Specifies `<PASSPHRASE>` as the passphrase to use for encryption. Is ignored if encryption is disabled.

#### `--verbose`
Verbose output.

### Push Options

#### `--compat`
Makes the generated image manifests adhere more strictly to the [Docker v2.2 image manifest schema](https://docs.docker.com/registry/spec/manifest-v2-2/#image-manifest-field-descriptions).

#### `--type=<TYPE>`
Specifies the encryption scheme to use.
At the moment `<TYPE>` may be `NONE` or `PBKDF2-AES256-GCM`.
The former does no encryption, and the latter offers passphrase derived symmetric encryption and is the default.

### Pull Options
[None]

## Credentials
The user must be able to `pull` and `push` to a repository.
For the default `docker.io` (aka Docker Hub/Cloud), they need to enter their credentials using:
```console
docker login
```
See also the privacy note below.

## Privacy
The user MUST be logged into a docker hub account. Because `docker login` stores an encoded username and password, the clear text password is exposed to this utility. While the password is not transmitted anywhere other then the repository, it may be logged to `STDOUT` in certain situations. Thus, it is recommended to set up an alternate Docker Hub account while this is under development.

## Cryptography
The layer archives and the config are encrypted using AES-GCM, with a 256-bit key that is randomly generated.
Chunking is handled by the go SIO library: <https://github.com/minio/sio>, which implements the DARE standard for data encryption at rest.
The keys are encrypted using AES-GCM from a key derived from a user specified passphrase and a random salt.
The salt, nonce and data key are randomly generated for each layer and the config.
The key derivation function is 40,000 iterations of PBKDF2 with SHA256 used in the HMAC.
The encrypted data key, the none used to encrypt and the salt are stored in the image manifest and may be inspected using the experimental `docker manifest inspect` command.
