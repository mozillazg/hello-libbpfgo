#!/usr/bin/env bash
set -e

# base on https://github.com/aquasecurity/tracee/blob/main/Vagrantfile

GO_VERSION="1.18"
OPA_VERSION="v0.35.0"

apt-get update
apt-get install --yes build-essential pkgconf libelf-dev llvm-12 clang-12 bpftrace

for tool in "clang" "llc" "llvm-strip"
do
  path=$(which $tool-12)
  sudo ln -s $path ${path%-*}
done

snap install microk8s --classic
microk8s status --wait-ready
usermod -a -G microk8s vagrant
# microk8s enable dashboard
microk8s enable dns

mkdir -p /home/vagrant/.kube/
microk8s kubectl config view --raw > /home/vagrant/.kube/config
microk8s stop

apt-get install --yes apt-transport-https ca-certificates curl
curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install --yes kubectl
echo 'source <(kubectl completion bash)' >> /home/vagrant/.bashrc

apt-get install --yes linux-tools-$(uname -r)

apt-get install --yes docker.io
usermod -aG docker vagrant

wget https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz
tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile

echo 'PROMPT_COMMAND="history -a; $PROMPT_COMMAND"' >> /home/vagrant/.profile
echo 'export PS1="$PS1\n\$ "' >> /home/vagrant/.profile
cat <<EOF | tee -a /home/vagrant/.profile
export GOPATH=/go_workshop
alias cdcode='cd /go_workshop/src/github.com/mozillazg/hello-libbpfgo'
export HISTFILESIZE=
export HISTTIMEFORMAT="[%F %T] "
export HISTFILE=~/.bash_eternal_history
EOF

#curl -L -o /usr/bin/opa https://github.com/open-policy-agent/opa/releases/download/$OPA_VERSION/opa_linux_amd64
#chmod 755 /usr/bin/opa
