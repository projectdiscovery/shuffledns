FROM golang:1.17-alpine as build
RUN apk --no-cache add git
RUN go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns; exit 0
ENV GO111MODULE on
WORKDIR github.com/projectdiscovery/shuffledns/cmd/shuffledns
RUN go install ./...

FROM alpine:3.15.0
RUN apk --update --no-cache add ldns \
  && apk --no-cache --virtual .deps add ldns-dev \
                                        git \
                                        build-base \
  && git clone --branch=master \
               --depth=1 \
               https://github.com/blechschmidt/massdns.git \
  && cd massdns \
  && make \
  && mv bin/massdns /usr/bin/massdns \
  && rm -rf /massdns \
  && apk del .deps

COPY --from=build /go/bin/shuffledns /usr/bin/shuffledns
ENV HOME /
ENTRYPOINT ["/usr/bin/shuffledns"]
