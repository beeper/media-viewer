FROM golang:1-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum /build/
RUN go get

COPY . /build
RUN go build -o /usr/bin/mediaviewer

FROM alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /usr/bin/mediaviewer /usr/bin/mediaviewer

VOLUME /data
ENV BMV_DATABASE_DRIVER="sqlite3" BMV_DATABASE_URL="/data/beeper-media-viewer.db"
EXPOSE 29333

CMD ["/usr/bin/mediaviewer"]
