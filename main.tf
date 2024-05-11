module "smallstep" {
  source        = "git::https://github.com/terraform-yacloud-modules/terraform-yandex-instance.git?ref=main"
  image_family  = var.family_images_linux
  subnet_id     = data.yandex_vpc_subnet.default-ru-central1-b.id
  zone          = data.yandex_vpc_subnet.default-ru-central1-b.zone
  name          = "smallstep"
  hostname      = "smallstep"
  memory        = "4"
  enable_nat    = true
  preemptible   = true
  core_fraction = 100
  ssh_user      = var.ssh_user
  ssh_pubkey    = "~/.ssh/id_rsa.pub"
  generate_ssh_key = false
}

module "freeipa" {
  source        = "git::https://github.com/terraform-yacloud-modules/terraform-yandex-instance.git?ref=main"
  image_family  = var.family_images_linux
  subnet_id     = data.yandex_vpc_subnet.default-ru-central1-b.id
  zone          = data.yandex_vpc_subnet.default-ru-central1-b.zone
  name          = "freeipa"
  hostname      = "freeipa"
  memory        = "4"
  enable_nat    = true
  preemptible   = true
  core_fraction = 100
  ssh_user      = var.ssh_user
  ssh_pubkey    = "~/.ssh/id_rsa.pub"
  generate_ssh_key = false
}

resource "local_file" "inventory_yml" {
  content = templatefile("inventory_yml.tpl",
    {
      ssh_user               = var.ssh_user
      smallstep_public_ip    = module.smallstep.instance_public_ip
      freeipa_public_ip      = module.freeipa.instance_public_ip
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
  value       = module.smallstep.instance_public_ip
}

output "freeipa_public_ip" {
  description = "Public IP address smallstep"
  value       = module.freeipa.instance_public_ip
}

