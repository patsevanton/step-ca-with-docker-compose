all:
  children:
    smallstep:
      hosts:
        "smallstep":
          ansible_host: "${smallstep_public_ip}"
    freeipa:
      hosts:
        "freeipa":
          ansible_host: "${freeipa_public_ip}"
  vars:
    ansible_user:  ${ssh_user}
    ansible_ssh_private_key_file: ~/.ssh/id_rsa
    freeipa_password: "${freeipa_password}"
    freeipa_fqdn: "freeipa.${freeipa_domain}"
    freeipa_domain: "${freeipa_domain}"
    ssh_user: "${ssh_user}"
