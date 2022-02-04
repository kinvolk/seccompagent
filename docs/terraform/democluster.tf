module "democluster" {
  source = "git::https://github.com/poseidon/typhoon//azure/flatcar-linux/kubernetes?ref=v1.23.3"

  # Azure
  cluster_name   = "democluster"
  region         = "westeurope"
  dns_zone       = "example.com"
  dns_zone_group = "my-resource-group"

  # configuration
  ssh_authorized_key = "ssh-rsa ..."

  os_image        = "flatcar-alpha"
  # calico currently does not work: https://github.com/projectcalico/calico/issues/5011
  networking      = "cilium"
  # worker_type's default Standard_DS1_v2 does not have enough CPU for SPO
  worker_type     = "Standard_DS2_v2"
  worker_count    = 2
  host_cidr       = "10.0.0.0/20"

}

resource "local_file" "kubeconfig-democluster" {
  content  = module.democluster.kubeconfig-admin
  filename = "/home/user/.kube/democluster-config"
}

