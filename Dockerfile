# syntax=docker/dockerfile:1

##
## Build
##
FROM golang:1.20-bookworm AS build

ARG BUILD_WITH_COVERAGE

WORKDIR /app

RUN echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' > /etc/apt/sources.list.d/goreleaser.list \
    && apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends build-essential libcap2-bin goreleaser

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN goreleaser build --snapshot --single-target -o extension \
    && setcap "cap_sys_boot,cap_sys_time,cap_setuid,cap_setgid,cap_net_raw,cap_net_admin,cap_sys_admin,cap_dac_override+eip" ./extension


##
## Runtime
##
FROM debian:bookworm-slim

ARG USERNAME=steadybit
ARG USER_UID=10000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends procps stress-ng iptables iproute2 dnsutils libcap2-bin \
    && apt-get -y autoremove \
    && rm -rf /var/lib/apt/lists/*

USER $USERNAME

WORKDIR /

COPY --from=build /app/extension /extension


EXPOSE 8085 8081

ENTRYPOINT ["/extension"]
