FROM docker.io/golang:1-alpine

RUN apk add -U --no-cache gcc musl-dev git bash make && \
    adduser -h /home/user -s /bin/bash -D -g user user
