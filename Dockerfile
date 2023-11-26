FROM alpine as build-env

RUN apk add --no-cache build-base pkgconfig libuv-dev argp-standalone

WORKDIR /app

COPY . .

RUN make mdns EXTRA_LDFLAGS=-largp

FROM alpine

RUN apk add --no-cache libuv-dev

COPY --from=build-env /app/mdns /app/mdns

WORKDIR /app

EXPOSE 5353/udp

CMD ["/app/mdns"]
