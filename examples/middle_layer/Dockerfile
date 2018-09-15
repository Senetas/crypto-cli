FROM alpine:latest
LABEL "com.senetas.crypto.enabled"="true"
RUN echo "hello" > file.txt
LABEL "com.senetas.crypto.enabled"="false"
RUN rm file.txt
ENTRYPOINT ["/bin/sh"]
