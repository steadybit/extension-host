# syntax=docker/dockerfile:1

##
## Build
##
FROM golang:1.20-alpine AS build

ARG NAME
ARG VERSION
ARG REVISION

WORKDIR /app


RUN apk add build-base stress-ng
COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build \
    -ldflags="\
    -X 'github.com/steadybit/extension-kit/extbuild.ExtensionName=${NAME}' \
    -X 'github.com/steadybit/extension-kit/extbuild.Version=${VERSION}' \
    -X 'github.com/steadybit/extension-kit/extbuild.Revision=${REVISION}'" \
    -o ./extension

##
## Runtime
##
FROM alpine:3.16

ARG USERNAME=steadybit
ARG USER_UID=1000

RUN apk update && \
# install needed tools
#    apk add iproute2 stress-ng iptables bind9-dnsutils runc skopeo cgroup-tools gnupg umoci procps && \
    apk add stress-ng && \
# cleanup
    rm -rf /var/cache/apk/*

RUN adduser -u $USER_UID -D $USERNAME

USER $USERNAME

WORKDIR /

COPY --from=build /app/extension /extension
ADD ./check-tools.sh /opt/steadybit/extension/check/
RUN /opt/steadybit/extension/check/check-tools.sh

EXPOSE 8085 8081

ENTRYPOINT ["/extension"]
