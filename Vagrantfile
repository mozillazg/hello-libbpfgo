# -*- mode: ruby -*-
# vi: set ft=ruby :

# base on https://github.com/aquasecurity/tracee/blob/main/Vagrantfile
Vagrant.configure("2") do |config|
  # config.vm.box = "ubuntu/focal64"     # Ubuntu 20.04 Focal Fossa (non CO-RE)
  # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
  # config.vm.box = "ubuntu/impish64"      # Ubuntu 21.10 Impish Indri (CO-RE)
  config.vm.box = "ubuntu/jammy64"       #  Ubuntu 22.04 Jammy Jellyfish (CO-RE)
  config.vm.box_version = "20220902.0.0"

  # config.ssh.username = "vagrant"
  config.ssh.extra_args = ["-t", "cd /vagrant; bash --login"]

  config.env.enable # Enable vagrant-env(.env)

  # Forward MkDocs dev server to preview documentation on the host at http://localhost:8000/tracee
#   config.vm.network :forwarded_port, guest: 8000, host: 8000

  # Forward MicroK8s dashboard to access it on the host at https://localhost:10443
  #
  # To access the Kubernetes dashboard from the host run the following command:
  #     kubectl port-forward --address 0.0.0.0 -n kube-system service/kubernetes-dashboard 10443:443
  #
  # To sing in use the token retrieved with
  #     token=$(microk8s kubectl -n kube-system get secret | grep default-token | cut -d " " -f1)
  #     kubectl -n kube-system describe secret $token
  #
  # TIP For Google Chrome you may allow insecure TLS connections at chrome://flags/#allow-insecure-localhost
#   config.vm.network :forwarded_port, guest: 10443, host: 10443

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "2048"
  end

  config.vm.provision "shell", path: "init.sh"

  config.vm.synced_folder ENV["GOPATH"], "/go_workshop"
end
