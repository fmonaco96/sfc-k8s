FROM alpine:3.18.4

RUN apk update && apk add iperf3

ENTRYPOINT [ "iperf3", "-s" ]