# Use the same base image as falco to ensure compatibility with glibc version
FROM golang:buster as builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /src/
RUN cd /src && go mod download

COPY ./ /src
RUN cd /src && make -C falco-plugin

# Use the following command to get the built files:
# DOCKER_BUILDKIT=1 docker build -f falco-plugin/Dockerfile --output=falco-plugin/ .
FROM scratch AS deploy-source
COPY --from=builder /src/falco-plugin/*.so /

