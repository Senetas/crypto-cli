# Crypto-Cli

A command line utility to push and pull encrypted docker images. This is in the pre-alpha proof of concept stage and is not indented for any use other than to prove that Docker Hub may be used to distribute encrypted docker images. Finally, DO NOT use this with your main Docker Hub account for reasons disclosed in the privacy section below.

## Installation
Ensure that `go` is installed properly and that `$GOPATH` has been set. Then run:
```
go get github.com/Senetas/crypto-cli
```
Also a running docker engine is required on the system.

## Usage
For now the syntax is limited and some parameters are hard coded.
```
crypto-cli (push|pull) NAME:TAG
```

Here, `NAME` is the name of a repository and `TAG` is a tag. For a `push` command, the image `NAME:TAG` must be present in the local docker engine. Furthermore, only images that were built with at least one occurrence of:
```
LABEL com.senetas.crypto.enabled=true
```
In their `Dockerfile` are supported. For the moment, only images that where built on that machine and have never been removed from it are supported. This means that a test image is ideally freshly built.

The user must be able to `pull` and `push` to `registry-1.docker.io` (aka Docker Hub/Cloud). To do this, they should have logged in via the command:
```
docker login -u <docker-hub-username>
```
and entered the password in `STDIN`. See also the privacy note below.


## Privacy
Then user MUST be logged into a docker hub account. Be warned that this means that the username and password for the Docker Hub account are exposed to this utility, and it executing it will cause the both to be loaded into memory. However, only the username is read by this utility and in particular the password is not transmitted to Docker Hub or elsewhere. Nevertheless, it is strongly recommended to set up a temporary Docker Hub account and login to it with `docker login` prior to running this utility.
