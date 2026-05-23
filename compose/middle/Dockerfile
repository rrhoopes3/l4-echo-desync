FROM alpine:3.19

RUN apk add --no-cache \
    bash \
    iproute2 \
    iptables \
    iputils \
    tcpdump \
    ca-certificates

# We will run as root (required for raw capture + netem + iptables in later phases)
WORKDIR /root

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]