FROM alpine:3.18.4

RUN apk update && apk add iptables

COPY ./scripts/firewall/setup-iptables-firewall.sh /setup-iptables-firewall.sh

ENTRYPOINT [ "sleep", "infinity"]