num_instances=1
instance_name_prefix="node"
['vagrant-reload'].each do |plugin|
  unless Vagrant.has_plugin?(plugin)
    raise "Vagrant plugin #{plugin} is not installed!"
  end
end

Vagrant.configure('2') do |config|
  config.vm.box = "ubuntu/disco64" # Ubuntu 18.04
  config.vm.box_check_update = false
  config.vm.network "private_network", type: "dhcp"

  # fix issues with slow dns http://serverfault.com/a/595010
  config.vm.provider :virtualbox do |vb, override|
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
      vb.customize ["modifyvm", :id, "--memory", "2048"]
      vb.customize ["modifyvm", :id, "--cpus", 2]
  end
  (1..num_instances).each do |i|
    vm_name = "%s-%02d" % [instance_name_prefix, i-1]
    # config.vm.provision "shell", path: "bootstrap.sh"
    config.vm.define vm_name do |host|
      host.vm.hostname = vm_name
      ip = "172.18.18.#{i+100}"
      host.vm.network :private_network, ip: ip

      config.vm.provision :shell, :privileged => true, :path => "vagrant/setup.sh"
      config.vm.provision :shell, :privileged => true, :inline => "/usr/sbin/usermod -aG docker vagrant"
      config.vm.provision :reload
    end
  end
end

