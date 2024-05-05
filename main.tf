module "freeipa-smallstep" {
  source        = "git::https://github.com/patsevanton/terraform-yandex-compute.git?ref=v1.23.0"
  image_family  = var.family_images_linux
  subnet_id     = data.yandex_vpc_subnet.default-ru-central1-b.id
  zone          = data.yandex_vpc_subnet.default-ru-central1-b.zone
  name          = "smallstep"
  hostname      = "smallstep"
  memory        = "4"
  is_nat        = true
  preemptible   = true
  core_fraction = 100
  user          = var.ssh_user
  nat_ip_address = var.nat_ip_address
}

resource "local_file" "inventory_yml" {
  content = templatefile("inventory_yml.tpl",
    {
      ssh_user               = var.ssh_user
      public_ip      = module.freeipa-smallstep.external_ip[0]
      internal_ip    = module.freeipa-smallstep.internal_ip[0]
      freeipa_password       = var.freeipa_password
      freeipa_fqdn           = var.freeipa_fqdn
      freeipa_domain         = var.freeipa_domain
      ssh_user               = var.ssh_user
    }
  )
  filename = "inventory.yml"
}


output "public_ip" {
  description = "Public IP address freeipa-smallstep"
  value       = module.freeipa-smallstep.external_ip[0]
}

output "internal_ip" {
  description = "Internal IP address freeipa-smallstep"
  value       = module.freeipa-smallstep.internal_ip[0]
}
