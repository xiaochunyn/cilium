#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

certs_dir="${dir}/certs"

set -e

sudo mkdir -p /var/lib/kubernetes

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/k8s-controller-manager-key.pem" \
   "${certs_dir}/k8s-controller-manager.pem" \
   "${certs_dir}/k8s-scheduler-key.pem" \
   "${certs_dir}/k8s-scheduler.pem" \
   "${certs_dir}/ca-etcd.pem" \
   "${certs_dir}/etcd-k8s-api-server-key.pem" \
   "${certs_dir}/etcd-k8s-api-server.pem" \
   "${certs_dir}/k8s-api-server-key.pem" \
   "${certs_dir}/k8s-api-server.pem" \
   "${certs_dir}/k8s-kubelet-key.pem" \
   "${certs_dir}/k8s-kubelet.pem" \
   /var/lib/kubernetes

#wget -nv https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-apiserver
#
#wget -nv https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-controller-manager
#
#wget -nv https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-scheduler
#
#wget -nv https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubectl

cd /home/vagrant/go/src/github.com/cilium/cilium/examples/kubernetes-ingress/scripts

chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl

sudo cp kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/bin/

cd -

sudo tee /etc/systemd/system/kube-apiserver.service <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-apiserver \\
  --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,NodeRestriction,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota,DefaultTolerationSeconds \\
  --advertise-address=${controllers_ips[1]} \\
  --allow-privileged=true \\
  --authorization-mode=Node,RBAC \\
  --bind-address=0.0.0.0 \\
  --cert-dir=/var/run/kubernetes \\
  --client-ca-file='/var/lib/kubernetes/ca-k8s.pem' \\
  --enable-swagger-ui=false \\
  --etcd-cafile='/var/lib/kubernetes/ca-etcd.pem' \\
  --etcd-certfile='/var/lib/kubernetes/etcd-k8s-api-server.pem' \\
  --etcd-keyfile='/var/lib/kubernetes/etcd-k8s-api-server-key.pem' \\
  --etcd-servers=https://${controllers_ips[0]}:2379 \\
  --kubelet-certificate-authority='/var/lib/kubernetes/ca-k8s.pem' \\
  --kubelet-client-certificate='/var/lib/kubernetes/k8s-kubelet.pem' \\
  --kubelet-client-key='/var/lib/kubernetes/k8s-kubelet-key.pem' \\
  --kubelet-https \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --service-node-port-range=30000-32767 \\
  --tls-ca-file='/var/lib/kubernetes/ca-k8s.pem' \\
  --tls-cert-file='/var/lib/kubernetes/k8s-api-server.pem' \\
  --tls-private-key-file='/var/lib/kubernetes/k8s-api-server-key.pem' \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-apiserver
sudo systemctl restart kube-apiserver

sudo systemctl status kube-apiserver --no-pager

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kubernetes/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=controller-manager.kubeconfig

kubectl config set-credentials controller-manager \
    --client-certificate=/var/lib/kubernetes/k8s-controller-manager.pem \
    --client-key=/var/lib/kubernetes/k8s-controller-manager-key.pem \
    --embed-certs=true \
    --kubeconfig=controller-manager.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=controller-manager \
    --kubeconfig=controller-manager.kubeconfig

kubectl config use-context default \
    --kubeconfig=controller-manager.kubeconfig

sudo cp ./controller-manager.kubeconfig /var/lib/kubernetes/controller-manager.kubeconfig

#  --allocate-node-cidrs=true \\
sudo tee /etc/systemd/system/kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-controller-manager \\
  --cluster-cidr=${k8s_cluster_cidr} \\
  --cluster-name=kubernetes \\
  --configure-cloud-routes=false \\
  --kubeconfig='/var/lib/kubernetes/controller-manager.kubeconfig' \\
  --leader-elect=true \\
  --node-cidr-mask-size ${k8s_node_cidr_mask_size} \\
  --use-service-account-credentials \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-controller-manager
sudo systemctl restart kube-controller-manager

sudo systemctl status kube-controller-manager --no-pager

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kubernetes/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=scheduler.kubeconfig

kubectl config set-credentials scheduler \
    --client-certificate=/var/lib/kubernetes/k8s-scheduler.pem \
    --client-key=/var/lib/kubernetes/k8s-scheduler-key.pem \
    --embed-certs=true \
    --kubeconfig=scheduler.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=scheduler \
    --kubeconfig=scheduler.kubeconfig

kubectl config use-context default \
    --kubeconfig=scheduler.kubeconfig

sudo cp ./scheduler.kubeconfig /var/lib/kubernetes/scheduler.kubeconfig

sudo tee /etc/systemd/system/kube-scheduler.service <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-scheduler \\
  --kubeconfig='/var/lib/kubernetes/scheduler.kubeconfig' \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-scheduler
sudo systemctl restart kube-scheduler

sudo systemctl status kube-scheduler --no-pager

sleep 2s

#kubectl -s http://${controllers_ips[0]}:8080 get componentstatuses || true
