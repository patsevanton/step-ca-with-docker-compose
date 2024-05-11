module "smallstep" {
  source        = "git::https://github.com/patsevanton/terraform-yandex-compute.git?ref=v1.23.0"
  image_family  = var.family_images_linux
  subnet_id     = data.yandex_vpc_subnet.default-ru-central1-b.id
  zone          = data.yandex_vpc_subnet.default-ru-central1-b.zone
  name          = "smallstep"
  hostname      = "smallstep"
  memory        = "2"
  is_nat        = true
  preemptible   = true
  core_fraction = 100
  user          = var.ssh_user
  nat_ip_address = var.nat_ip_address
}

module "freeipa" {
  source        = "git::https://github.com/patsevanton/terraform-yandex-compute.git?ref=v1.23.0"
  image_family  = var.family_images_linux
  subnet_id     = data.yandex_vpc_subnet.default-ru-central1-b.id
  zone          = data.yandex_vpc_subnet.default-ru-central1-b.zone
  name          = "freeipa"
  hostname      = "freeipa"
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
      smallstep_public_ip    = module.smallstep.external_ip[0]
      freeipa_public_ip      = module.freeipa.external_ip[0]
      freeipa_password       = var.freeipa_password
      freeipa_fqdn           = "freeipa.mydomain.int"
      freeipa_domain         = "MYDOMAIN.INT"
      ssh_user               = var.ssh_user
    }
  )
  filename = "inventory.yml"
}


output "smallstep_public_ip" {
  description = "Public IP address smallstep"
  value       = module.smallstep.external_ip[0]
}

output "freeipa_public_ip" {
  description = "Public IP address smallstep"
  value       = module.freeipa.external_ip[0]
}
