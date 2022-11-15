FROM golang:1.17 as builder

# Create workspace folder
WORKDIR /workspace

# Copy go module files
COPY cni-plugin/go.mod go.mod
COPY cni-plugin/go.sum go.sum
RUN go mod download

# Copy sfc-ptp plugin source code and build
COPY cni-plugin/sfc-ptp.go sfc-ptp.go
RUN go build -o sfc-ptp

# Download static IPAM plugin
RUN curl -L -O  https://github.com/containernetworking/plugins/releases/download/v1.0.1/cni-plugins-linux-amd64-v1.0.1.tgz
RUN tar -zxf cni-plugins-linux-amd64-v1.0.1.tgz ./static

FROM python:3.9-alpine

RUN ln -s $(which python3) /usr/bin/python

RUN apk update && apk add bcc-tools bcc-doc

# Needed because python was not installed from a package
ENV PYTHONPATH=/usr/lib/python3.9/site-packages

RUN pip install pyroute2
RUN pip install kopf
RUN pip install kubernetes

# Copy cni plugins and install scripts
COPY --from=builder /workspace/sfc-ptp  /cni-plugins/sfc-ptp
COPY --from=builder /workspace/static /cni-plugins/static
COPY scripts/install-cni.sh scripts/uninstall-cni.sh /cni-plugins/

# Copy operator source files
COPY loadbalancer/sfc_loadbalancer_dp_template.c /src/
COPY operator/sfc_manager.py /src/
COPY operator/sfc.py /src/
COPY operator/loadbalancer_template.yaml /src/

ENTRYPOINT kopf run /src/sfc_manager.py --standalone --all-namespaces