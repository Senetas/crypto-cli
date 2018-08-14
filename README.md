# Crypto-Cli

A command line utility to push and pull encrypted docker images. This is in the pre-alpha proof of concept stage and is not indented for any use other than to prove that Docker Hub may be used to distribute encrypted docker images. Finally, DO NOT use this with your main Docker Hub account for reasons disclosed in the privacy section below.

## Prerequisites
Ensure that `docker`, `go` and `dep` are installed and that `$GOPATH` has been set and that `$GOPATH/bin` is in the `$PATH`.
The following sections provide guidance on how to install these on Ubuntu 18.04 Desktop.

### Docker
Follow these instructions: <https://docs.docker.com/install/linux/docker-ce/ubuntu/> to install `docker`.
It is more convenient to run `docker` as a non-privileged user, and these instructions assume that you are able to.
Follow these instructions to enable this: <https://docs.docker.com/install/linux/linux-postinstall/> and note the warnings.

### Go
```console
sudo apt-get install golang
```

### \$GOPATH, etc
Add the lines
```
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```
to the file `~/.bashrc`. A relogin may be necessary to complete the process.

## Installation
```console
go get github.com/Senetas/crypto-cli
```

If this command fails, it is likely because the github repository is private.
The following sequence of commands should rectify the error, provided you have enough permissions.
```console
cd $GOPATH/src/github.com/Senetas
git clone https://github.com/Senetas/crypto-cli.git
cd crypto-cli
go install
```
Note: you may need to use `git@github.com:Senetas/crypto-cli.git` if using ssh keys for authentication.

## Usage
For now the syntax is limited to:
```console
crypto-cli (push|pull) NAME:TAG [opts]
```
Here, `NAME` is the name of a repository and `TAG` is a mandatory tag. For a `push` command, the image `NAME:TAG` must be present in the local docker engine. Furthermore, only images that were built with at least one occurrence of:
```Dockerfile
LABEL com.senetas.crypto.enabled=true
```
in their `Dockerfile` will be supported.
A compliant example Dockerfile is provided in the `test` directory.

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
