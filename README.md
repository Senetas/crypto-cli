# Crypto-Cli

A command line utility to push and pull encrypted docker images. This is in the pre-alpha proof of concept stage and is not indented for any use other than to prove that Docker Hub may be used to distribute encrypted docker images. Finally, DO NOT use this with your main Docker Hub account for reasons disclosed in the privacy section below.

## Prerequisites
Ensure that `docker` and `go` are installed and that `$GOPATH` has been set and that `$GOPATH/bin` is in the `$PATH`.

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
or the end of the file will be encrypted.
As many of these may be specified to encrypt any nonempty subset of the layers that either contains all or none of the base image layers.
However, the typical usage is expected to have the `Dockerfile` containing exactly one `com.senetas.crypto.enabled=true` after the initial `FROM`.
This will leave the base image unencrypted but encrypt any layers created on top of it.
A compliant example Dockerfile is provided in the `test` directory.

Note that although in general a `LABEL` line may contain multiple labels, this is not supported for the `com.senetas.crypto.enabled` label for the purposes of this application.

### Global Options

#### `--pass=PASSPHRASE`
Specifies `PASSPHRASE` as the passphrase to use for encryption. Is ignored if encryption is disabled.

#### `--verbose`
Verbose output.

### Push Options

#### `--compat`
Makes the produced image manifests adhere more strictly to the Docker v2.2 manifest schema.

#### `--type=TYPE`
Specifies the encryption scheme to use. At the moment the options are `NONE` and `PBKDF2-AES256-GCM`.
The former does no encryption, and the latter offers passphrase derived symmetric encryption.

### Pull Options
[None]

### Credentials
The user must be able to `pull` and `push` to a repository.
For the default `registry-1.docker.io` (aka Docker Hub/Cloud), then need to run the following command:
```console
docker login -u <docker-hub-username>
```
and entered the password in `STDIN`. See also the privacy note below.

## Privacy
The user MUST be logged into a docker hub account. Because `docker login` stores an encoded username and password, the clear text password is exposed to this utility. While the password is not transmitted anywhere other then the repository in either a clear, encoded or encrypted form, it may be logged to `STDOUT` in certain situations. Thus, it is strongly recommended to set up an alternate Docker Hub account and login to it with `docker login` prior to running this utility while it is under development.
