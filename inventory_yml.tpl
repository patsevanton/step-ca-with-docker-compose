all:
  children:
    freeipa-smallstep:
      hosts:
        "freeipa-smallstep":
          ansible_host: "${public_ip}"
  vars:
    ansible_user:  ${ssh_user}
    ansible_ssh_private_key_file: ~/.ssh/id_rsa
    freeipa_password: "${freeipa_password}"
    freeipa_fqdn: "freeipa.${freeipa_domain}"
    freeipa_domain: "${freeipa_domain}"
    ssh_user: "${ssh_user}"
