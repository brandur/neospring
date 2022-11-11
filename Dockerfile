# -*- mode: dockerfile -*-
#
# A multi-stage Dockerfile that builds a Linux target then creates a small
# final image for deployment.

#
# STAGE 1
#
# Build from source.
#

FROM golang:alpine AS builder

RUN go version

# The Go Alpine image gets an automatic `$GOPATH` of `/go`, which we know in
# advance and are going to take advantage of here.
ENV BUILD_DIR=/go/src/neospring

# Add source code. Note that `.dockerignore` will take care of excluding the
# vast majority of files in the current directory and just bring in the couple
# core files that we need.
ADD ./ $BUILD_DIR/

# Build the project.
WORKDIR $BUILD_DIR
RUN ls -R .
RUN go build -o neospring .

#
# STAGE 2
#
# Use a tiny base image (alpine) and copy in the release target. This produces
# a very small output image for deployment.
#

FROM alpine:latest
RUN apk --no-cache add ca-certificates

ENV BUILD_DIR=/go/src/neospring

COPY --from=builder $BUILD_DIR/neospring /

ENV PORT 4434
ENTRYPOINT ["/neospring"]
