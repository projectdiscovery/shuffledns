# Build image: golang:1.14-alpine3.13
FROM golang@sha256:ef409ff24dd3d79ec313efe88153d703fee8b80a522d294bb7908216dc7aa168 as build

# Pull and install massdns
RUN apk --no-cache add git ldns \
  && apk --no-cache --virtual .deps add ldns-dev \
                                        git \
                                        build-base \
  && git clone --branch=master \
               --depth=1 \
               https://github.com/blechschmidt/massdns.git /massdns \
  && cd /massdns \
  && make

# Pull and install ShuffleDNS
RUN go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns; exit 0
WORKDIR src/github.com/projectdiscovery/shuffledns/cmd/shuffledns
RUN GO111MODULE=on go install ./...

# Release Image: alpine:3.14.1
FROM alpine@sha256:be9bdc0ef8e96dbc428dc189b31e2e3b05523d96d12ed627c37aa2936653258c

COPY --from=build /go/bin/shuffledns /massdns/bin/massdns /usr/bin/

RUN adduser \
    --gecos "" \
    --disabled-password \
    shuffledns

USER shuffledns

ENTRYPOINT ["/usr/bin/shuffledns"]
