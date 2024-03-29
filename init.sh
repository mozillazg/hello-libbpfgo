#!/usr/bin/env bash
set -e

# base on https://github.com/aquasecurity/tracee/blob/main/Vagrantfile

GO_VERSION="1.21.7"

apt-get update
apt-get install --yes build-essential pkgconf libelf-dev llvm-12 clang-12 bpftrace linux-tools-generic

for tool in "clang" "llc" "llvm-strip"
do
  path=$(which $tool-12)
  sudo ln -fs $path ${path%-*}
done

snap install microk8s --classic
# microk8s status --wait-ready
usermod -a -G microk8s vagrant
microk8s enable dns

mkdir -p /home/vagrant/.kube/
microk8s kubectl config view --raw > /home/vagrant/.kube/config
microk8s stop

apt-get install --yes apt-transport-https ca-certificates curl
#curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
#echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
#apt-get update
#apt-get install --yes kubectl
#echo 'source <(kubectl completion bash)' >> /home/vagrant/.bashrc

apt-get install --yes linux-tools-$(uname -r)

apt-get install --yes docker.io
usermod -aG docker vagrant

wget https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz
tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile
echo 'export PATH=$PATH:/usr/local/go/bin && export GOPATH=/go_workshop' >> /root/.profile

echo 'PROMPT_COMMAND="history -a; $PROMPT_COMMAND"' >> /home/vagrant/.profile
echo 'export PS1="$PS1\n\$ "' >> /home/vagrant/.profile
echo 'export PS1="$PS1\n\$ "' >> /root/.profile
cat <<EOF | tee -a /home/vagrant/.profile
export GOPATH=/go_workshop
alias cdcode='cd /go_workshop/src/github.com/mozillazg/hello-libbpfgo'
export HISTFILESIZE=
export HISTTIMEFORMAT="[%F %T] "
export HISTFILE=~/.bash_eternal_history
EOF
