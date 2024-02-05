FROM golang:1.21.6-alpine as build-env
RUN apk --no-cache add git
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

FROM alpine:3.17.3
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

COPY --from=build-env /go/bin/shuffledns /usr/bin/shuffledns
ENV HOME /
ENTRYPOINT ["/usr/bin/shuffledns"]