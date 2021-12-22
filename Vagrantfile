Vagrant.configure("2") do |config|
  config.vm.define "nyako" do |server|
    server.vm.box = "generic/centos8"
    server.vm.network "private_network", ip: "192.168.56.11"
    server.vm.hostname = "nyako"
    server.vm.define "nyako"
    server.vm.provision :shell, path: "setup_environment.sh"
    server.vm.synced_folder "nyako", "/home/vagrant/nyako"
    server.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = "2"
    end
  end

  config.vm.define "nyatta" do |client|
    client.vm.box = "generic/centos8"
    client.vm.network "private_network", ip: "192.168.56.12"
    client.vm.hostname = "nyatta"
    client.vm.define "nyatta"
    client.vm.provision :shell, path: "setup_environment.sh"
    client.vm.synced_folder "nyatta", "/home/vagrant/nyatta"
    client.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = "2"
    end
  end
end