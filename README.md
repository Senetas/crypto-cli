# Crypto-Cli

A command line utility to push and pull encrypted docker images. This is in the pre-alpha proof of concept stage and is not indented for any use other than to prove that Docker Hub may be used to distribute encrypted docker images. Finally, DO NOT use this with your main Docker Hub account for reasons disclosed in the privacy section below.

## Prerequisites
Ensure that `docker`, `go` and `dep` are installed and that `$GOPATH` has been set and that `$GOPATH/bin` is in the `$PATH`.
The following sections provide guidance on how to install these on Ubuntu 18.04 Desktop.

### Docker
Follow these instructions: <https://docs.docker.com/install/linux/docker-ce/ubuntu/> to install `docker`.
It is convenient to run `docker` as a non-privileged user: <https://docs.docker.com/install/linux/linux-postinstall/>.

### Go
```console
$ sudo apt-get install golang
```

### Dep
```console
$ sudo apt-get install go-dep
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
$ go get github.com/Senetas/crypto-cli
```
Unfortunately, because the repository is private, the `go get` command may not work if you use ssh keys.
Furthermore, because of the way the dependencies are currently set up, the semi-official package manager `dep` may need to be used as well.

If the previous command fails, the following sequence of commands should rectify it.
```console
$ cd $GOPATH/src/github.com/Senetas
$ git clone git@github.com:Senetas/crypto-cli.git
$ cd crypto-cli
$ dep ensure
$ go get github.com/Senetas/crypto-cli
```
Note: use `https://github.com/Senetas/crypto-cli.git` if not using ssh keys for authentication.
The `go get` and `dep ensure` commands will take a long time to execute.

## Usage
For now the syntax is limited and some parameters are hard coded.
```
crypto-cli (push|pull) NAME:TAG
```
Here, `NAME` is the name of a repository and `TAG` is a mandatory tag. For a `push` command, the image `NAME:TAG` must be present in the local docker engine. Furthermore, only images that were built with at least one occurrence of:
```Dockerfile
LABEL com.senetas.crypto.enabled=true
```
in their `Dockerfile` will be supported.
For the moment, only images that were built on the same machine and have never been removed from it are supported.
This means that the ideal test image is one that was freshly built.
A compliant Dockerfile is provided in the `test` directory.

### Credentials
The user must be able to `pull` and `push` to `registry-1.docker.io` (aka Docker Hub/Cloud). To do this, they should have logged in via the command:
```console
$ docker login -u <docker-hub-username>
```
and entered the password in `STDIN`. See also the privacy note below.

## Privacy
The user MUST be logged into a docker hub account. Because `docker login` stores and encoded username and password, the clear text password is exposed to this utility. While the password is not transmitted anywhere other then Docker Hub in either a clear, encoded or encrypted form, it may be logged to `STDOUT` in certain situations. Thus, it is strongly recommended to set up a temporary Docker Hub account and login to it with `docker login` prior to running this utility while it is under development.
