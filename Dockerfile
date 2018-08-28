FROM alpine:latest

COPY ./crypto-cli /usr/local/bin/crypto-cli

ENTRYPOINT ["/bin/sh"]
