FROM docker.io/golang:alpine as build

RUN apk update && apk add libpcap-dev gcc libc-dev

WORKDIR /go/src/app
COPY . .

ENV CGO_ENABLED=1
RUN go mod download && \
    go vet -v && \
    go test -v && \
    go build -o /go/bin/app

FROM docker.io/alpine:latest

ARG intfname="wg0"
ENV intfname=$intfname

RUN apk update && \
    apk upgrade && \
    apk add wireguard-tools nftables libpcap
COPY --from=build /go/bin/app wgtrack

CMD [ "/bin/sh", "-c", "wg-quick up \"${intfname}\" && trap : TERM INT; /wgtrack"]
