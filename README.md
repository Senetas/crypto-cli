# Crypto-Cli

A command line utility to push and pull encrypted docker images. This is in the pre-alpha proof of concept stage and is not indented for any use other than to prove that Docker Hub may be used to distribute encrypted docker images. Finally, DO NOT use this with your main Docker Hub account for reasons disclosed in the privacy section below.

## Installation
Ensure that `go` is installed and that `$GOPATH` has been set and that `$GOPATH/bin` is in the `$PATm`. Then run:
```bash
go get -u github.com/Senetas/crypto-cli
```
Also a running docker engine is required on the system.

Unfortunately, because the repository is private, the `go get` command may not work if you use ssh keys.
Furthermore, because of the way the dependencies are currently set up, the semi-official package manager `dep` must also be installed. It is called `go-dep` in Ubuntu 18.04.

Then the full sequence of commands is
```bash
cd $GOPATH/src/github.com/Senetas
git clone git@github.com:Senetas/crypto-cli.git
cd crypto-cli
dep ensure
go get -u github.com/Senetas/crypto-cli
```
This will only pull the project source files, and the `go get -u` command above MUST still be issued to pull the dependencies.

## Usage
For now the syntax is limited and some parameters are hard coded.
```bash
crypto-cli (push|pull) NAME:TAG
```

Here, `NAME` is the name of a repository and `TAG` is a tag. For a `push` command, the image `NAME:TAG` must be present in the local docker engine. Furthermore, only images that were built with at least one occurrence of:
```bash
LABEL com.senetas.crypto.enabled=true
```
In their `Dockerfile` are supported. For the moment, only images that where built on that machine and have never been removed from it are supported. This means that a test image is ideally freshly built.

The user must be able to `pull` and `push` to `registry-1.docker.io` (aka Docker Hub/Cloud). To do this, they should have logged in via the command:
```bash
docker login -u <docker-hub-username>
```
and entered the password in `STDIN`. See also the privacy note below.

## Privacy
The user MUST be logged into a docker hub account. Because `docker login` stores and encoded username and password, the clear text password is exposed to this utility. While the password is not transmitted anywhere other then Docker Hub in either a clear, encoded or encrypted form, it may be logged to `STDOUT` in certain situations. Thus, it is strongly recommended to set up a temporary Docker Hub account and login to it with `docker login` prior to running this utility while it is under development.
