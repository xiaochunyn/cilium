#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

certs_dir="${dir}/certs"

set -e

sudo mkdir -p /etc/etcd/

cp "${certs_dir}/etcd-server.pem" \
   "${certs_dir}/etcd-server-key.pem" \
   "${certs_dir}/ca-etcd.pem" \
   /etc/etcd/

#wget -nv https://github.com/coreos/etcd/releases/download/${etcd_version}/etcd-${etcd_version}-linux-amd64.tar.gz

cd /home/vagrant/go/src/github.com/cilium/cilium/examples/kubernetes-ingress/scripts

tar -xvf etcd-${etcd_version}-linux-amd64.tar.gz

sudo mv etcd-${etcd_version}-linux-amd64/etcd* /usr/bin/

cd -

sudo mkdir -p /var/lib/etcd

ETCD_NAME=controller0

sudo tee /etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/bin/etcd --name ${ETCD_NAME} \\
  --data-dir=/var/lib/etcd \\
  --listen-client-urls https://${controllers_ips[0]}:2379,http://127.0.0.1:2379 \\
  --initial-advertise-peer-urls https://${controllers_ips[0]}:2380 \\
  --initial-cluster-state new \\
  --initial-cluster ${ETCD_NAME}=https://${controllers_ips[0]}:2380 \\
  --advertise-client-urls https://${controllers_ips[0]}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --cert-file='/etc/etcd/etcd-server.pem' \\
  --key-file='/etc/etcd/etcd-server-key.pem' \\
  --trusted-ca-file='/etc/etcd/ca-etcd.pem' \\
  --client-cert-auth
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

sudo systemctl enable etcd

sudo systemctl restart etcd

sudo systemctl status etcd --no-pager

#sudo etcdctl cluster-health
