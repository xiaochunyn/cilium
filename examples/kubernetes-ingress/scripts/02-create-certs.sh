#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

certs_dir="${dir}/certs"

mkdir -p "${certs_dir}"

cd "${certs_dir}"

if [ -n "${INSTALL}" ]; then
    cfssl_url="https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
    cfssljson_url="https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
    wget ${cfssl_url}
    chmod +x cfssl_linux-amd64
    sudo mv cfssl_linux-amd64 /usr/bin/cfssl
    wget ${cfssljson_url}
    chmod +x cfssljson_linux-amd64
    sudo mv cfssljson_linux-amd64 /usr/bin/cfssljson
fi

generate_ca_certs(){
    if [ $# -ne 1 ]; then
        echo "Invalid arguments: usage generate_ca_certs <name>"
        exit
    fi
    name=${1}
    cat > ${name}-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "2191h"
    },
    "profiles": {
      "${name}": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "2191h"
      }
    }
  }
}
EOF

    cat > ca-${name}-csr.json <<EOF
{
  "CN": "${name}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert -initca ca-${name}-csr.json | cfssljson -bare ca-${name}

    openssl x509 -in ca-${name}.pem -text -noout
}

generate_server_certs() {
    if [ $# -ne 2 ]; then
        echo "Invalid arguments: usage generate_client_certs <ca-name> <cli-name>"
        exit
    fi
    ca_name=${1}
    cli_name=${2}
    cat > ${cli_name}-csr.json <<EOF
{
  "CN": "${cli_name}",
  "hosts": [
    "cilium-k8s-master",
    "${master_ip}",
    "${cluster_api_server_ip}",
    "127.0.0.1",
    "::1",
    "${cli_name}.cluster.default"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${ca_name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${cli_name}-csr.json | cfssljson -bare ${cli_name}

    openssl x509 -in ${cli_name}.pem -text -noout
}

generate_kubelet_client_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_client_certs <ca-name> <cli-name> <filename>"
        exit
    fi
    ca_name=${1}
    cli_name=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${cli_name}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "system:nodes",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

generate_kubelet_controller_manager_certs() {
    if [ $# -ne  ]; then
        echo "Invalid arguments: usage generate_kubelet_controller_manager_certs <ca-name> <k8s-component-name> <filename>"
        exit
    fi
    ca_name=${1}
    k8s_name=${2}
    cm_name=${3}
    cat > ${cm_name}-csr.json <<EOF
{
  "CN": "${k8s_name}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${k8s_name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${cm_name}-csr.json | cfssljson -bare ${cm_name}

    openssl x509 -in ${cm_name}.pem -text -noout
}

generate_kubectl_admin_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_kubectl_admin_certs <ca-name> <username> <filename>"
        exit
    fi
    ca_name=${1}
    username=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${username}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "system:masters",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

generate_client_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_kubectl_admin_certs <ca-name> <username> <filename>"
        exit
    fi
    ca_name=${1}
    username=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${username}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "kubernetes",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

generate_ca_certs k8s

generate_server_certs k8s k8s-api-server

generate_kubelet_controller_manager_certs k8s system:kube-controller-manager k8s-controller-manager
generate_kubelet_controller_manager_certs k8s system:kube-scheduler k8s-scheduler
generate_kubelet_client_certs k8s system:node:cilium-k8s-master k8s-kubelet-cilium-k8s-master
generate_kubelet_client_certs k8s system:node:cilium-k8s-node-2 k8s-kubelet-cilium-k8s-node-2
generate_kubectl_admin_certs k8s admin k8s-admin
generate_kubectl_admin_certs k8s cilium k8s-cilium

generate_ca_certs etcd

generate_server_certs etcd etcd-server

generate_client_certs etcd api-server etcd-k8s-api-server
generate_client_certs etcd cilium etcd-cilium
