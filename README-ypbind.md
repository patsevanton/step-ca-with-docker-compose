[Step-CA](https://smallstep.com/docs/step-ca) is sophisticated open source (Apache License 2.0) CA system with support for the ACME protocol.

# Initialisation
After the installation of the required packages (`step-ca` for the CA itself and `step-cli` for the client program), the CA itself can be initialised. For the initialisation, the DNS names, the CA name (will be part of the certificate subject of the Root CA and ther intermediate CA certificate), the deployment type and IP and port for the CA service to listen are required.

### Important
`The deployment type and the CA name can not be changed afterwards!`

To initialise the CA, run `step ca init …​`. The environment variable `STEPPATH` can be set to specify the directory of the CA, otherwise the current directory is used:

```
root@vasquez:~# export STEPPATH=/etc/step-ca
root@vasquez:~# step ca init --dns=pki.internal.ypbind.de --dns=pki.ypbind.de --address='[::]:8443'  --address=0.0.0.0:8443  --name="Certificate authority for internal.ypbind.de" --deployment-type=standalone --provisioner="root@internal.ypbind.de" --password-file=/etc/step/initial_pass

Generating root certificate... done!
Generating intermediate certificate... done!

✔ Root certificate: /etc/step/certs/root_ca.crt
✔ Root private key: /etc/step/secrets/root_ca_key
✔ Root fingerprint: b7413e0c6a0572862fcc81feddefef3bdfe76fe03c56058571c4b7d859a2924f
✔ Intermediate certificate: /etc/step/certs/intermediate_ca.crt
✔ Intermediate private key: /etc/step/secrets/intermediate_ca_key
✔ Database folder: /etc/step/db
✔ Default configuration: /etc/step/config/defaults.json
✔ Certificate Authority configuration: /etc/step/config/ca.json

Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.

FEEDBACK 😍 🍻
  The step utility is not instrumented for usage statistics. It does not phone
  home. But your feedback is extremely valuable. Any information you can provide
  regarding how you’re using `step` helps. Please send us a sentence or two,
  good or bad at feedback@smallstep.com or join GitHub Discussions
  https://github.com/smallstep/certificates/discussions and our Discord
  https://u.step.sm/discord.
```
Take a note of the root fingerprint, it is required by the bootstrap for every user. It can also be obtained from the output at the start of the step-ca service.

# Use PostgreSQL as database backend
The default database type is BoltDB. The downside of BoltDB is the access is limited to a single process, in this case the step-ca service. In a productive environment multiple processess will access the database at the same time, e.g. to crate CRL, export statistics to Prometheus, …

The database bacekend can be changed easily. It doesn’t matter if PostgreSQL or MySQL/MariaDB is used. The only difference is the database configuration and the configuration section in the Step-CA configuration.

Just install PostgreSQL, add a user - in this case step-ca - for the database:

postgres@vasquez:~$ createuser --no-createdb --login --pwprompt --no-createrole --no-superuser --no-replication step-ca
Enter password for new role:
Enter it again:
Create the empty database step_ca_db in this case and assign it to the new user:

postgres@vasquez:~$ createdb --encoding=UTF-8 --owner=step-ca step_ca_db
Note: The encoding is not required, but for the sake of consistency all my databases uses UTF-8 as encoding.

In the configuration file of the CA (${STEPPATH}/config/ca.json) replace configuration in the db dictionary with the PostgreSQL configuration:

--- /etc/step-ca/config/ca.json.orig       2022-07-23 14:36:14.192091833 +0200
+++ /etc/step-ca/config/ca.json    2022-07-23 14:38:18.671617838 +0200
@@ -13,9 +13,9 @@
                "format": "text"
        },
        "db": {
-               "type": "badgerv2",
-               "dataSource": "/etc/step-ca/db",
-               "badgerFileLoadingMode": ""
+               "type": "postgresql",
+               "dataSource": "postgresql://step-ca:ItsSoFluffyImgonnaD1E@127.0.0.1:5432/",
+               "database": "step_ca_db"
        },
        "authority": {
                "provisioners": [
@@ -44,4 +44,4 @@
                "maxVersion": 1.3,
                "renegotiation": false
        }
-}
\ No newline at end of file
+}
Store provisioners in the database
Instead of storing the provisioners in the configuration file, it is more convenient to use the database instead. This can easily be archived by removing all provisioners from the configuration file ca.json and +enable support for administrative remote provisioners by setting enableAdmin to true in the authority section:

--- /etc/step-ca/config/ca.json.lprov     2022-07-23 15:00:09.130731156 +0200
+++ /etc/step-ca/config/ca.json    2022-07-23 15:00:39.816582101 +0200
@@ -18,22 +18,8 @@
                "database": "step_ca_db"
        },
        "authority": {
-               "provisioners": [
-                       {
-                               "type": "JWK",
-                               "name": "root@internal.ypbind.de",
-                               "key": {
-                                       "use": "sig",
-                                       "kty": "EC",
-                                       "kid": "...",
-                                       "crv": "P-256",
-                                       "alg": "ES256",
-                                       "x": "X..",
-                                       "y": "y..."
-                               },
-                               "encryptedKey": "..."
-                       }
-               ]
+               "enableAdmin": true,
+               "provisioners": []
        },
        "tls": {
                "cipherSuites": [
This will add a JWK provisioner Admin JWK to the database and create the default user step with super administration privileges to the newly created provisioner. The password of the step user is the same password as for the root CA private key, provided by the step ca init process.

Enable ACME provisioner
Because most service certificates will be renewed using the ACME protocol, the ACME provisioner must be added to the provisioner section of the configuration file.

By default server certificates for internal services will be valid for 90 days (2160 hours) and if no CN can be found a value of the subject alternate name extension will be used instead (forceCN set to true).

--- /etc/step-ca/config/ca.json.no_acme     2022-08-14 09:57:08.869306887 +0200
+++ /etc/step-ca/config/ca.json 2022-08-14 09:59:41.768801437 +0200
@@ -19,7 +19,18 @@
        },
        "authority": {
                "enableAdmin": true,
-               "provisioners": [],
+               "provisioners": [
+                   {
+                       "type": "ACME",
+                       "name": "acme",
+                       "forceCN": true,
+                       "claims": {
+                           "minTLSCertDuration": "24h",
+                           "defaultTLSCertDuration": "2160h",
+                           "maxTLSCertDuration": "2160h"
+                       }
+                   }
+               ],
                "claims": {
                    "minTLSCertDuration": "5m",
                    "maxTLSCertDuration": "43830h",
Adding additional certificate extensions
By default generated certificates lack information about CRL distribution point, OCSP URL and authority information access.

Additional extensions
Authority information access - http://pki.internal.ypbind.de:8888/intermediate_ca.crt

CRL distribution point - http://pki.internal.ypbind.de:8888/intermediate_ca.crl

OCSP responder URL - http://pki.internal.ypbind.de:8889/

This can easily archived by creating a custom certificate template /etc/step-ca/templates/leaf_certificate.tpl defining the additional certificate extensions:

{
{{- if .SANs }}
    "sans": {{ toJson .SANs }},
{{- end }}
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
    "keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
    "keyUsage": ["digitalSignature"],
{{- end }}
    "extKeyUsage": ["serverAuth", "clientAuth"],
    "crlDistributionPoints": "http://pki.internal.ypbind.de:8888/intermediate_ca.crl"
    "issuingCertificateURL": "http://pki.internal.ypbind.de:8888/intermediate_ca.crt",
    "ocspServer": "http://pki.internal.ypbind.de:8889/",
}
If the provisioner is configured in the ca.json file, the template file must be added to the provisioner(s).

Important
Provisioners in the database
If the provisioners are stored in the databsse, like in this setup, the template file must be configured for every provisioner in the database. Futhermore all newly created provisioners must be created with the new certificate template too! At the moment templateFile can’t be set by step ca provisioner add / step ca provisioner update for remote provisioners, see Let step ca provisioner update set the templateFile option of a provisioner #720
Site specific changes
In an enterprise environment there are some systems (like management boards for servers) that doesn’t support the ACME protocol. As servers are usually replaced every three years and the management boards are in a sepearted network segment, accessible only from some dedicated jump hostss, the will use SSL certificates valid for about 3 years.

Note
Management boards
Although most management boards support the Redfish REST API, not every hardware vendor supports automated SSL certificate deployment. Additionally replacing the SSL certificates of the management board will require a reboot of the management processor which will disrupt access to the management board.
For this site, all service certificates will be valid for 30 days instead of the default of 1 day because some services require restart upon SSL certificate changes which will lead to disruption for some clients, e.g. using REDIS publish/subscribe, MQTT or HTTP long polling, and a reconnect storm.

To avoid signing of certificates for other domains, the allowed (and rejected) values for x509.v3 subjectAltername extensions can be limited.

This can be archived by extending the authority section of the CA configuration file ca.json:

--- /etc/step-ca/config/ca.json.unrstr     2022-07-24 10:53:07.580078893 +0200
+++ /etc/step-ca/config/ca.json 2022-07-24 11:09:54.808077262 +0200
@@ -19,7 +19,32 @@
        },
        "authority": {
                "enableAdmin": true,
-               "provisioners": []
+               "provisioners": [],
+               "claims": {
+                   "minTLSCertDuration": "5m",
+                   "maxTLSCertDuration": "26400h",
+                   "defaultTLSCertDuration": "720h"
+               },
+               "policy": {
+                   "x509": {
+                       "allow": {
+                           "dns": [
+                               "*.insecure",
+                               "*.internal.ypbind.de",
+                               "*.ypbind.de"
+                           ],
+                           "email": [
+                               "@internal.ypbind.de",
+                               "@ypbind.de"
+                           ],
+                           "ip": [
+                               "192.168.142.0/24",
+                               "10.147.239.0/24",
+                               "fd0a:93ef:ee26:cdbe:://64"
+                           ]
+                       }
+                   }
+               }
        },
        "tls": {
                "cipherSuites": [
Hardening
Removal of the private key of the root CA
All certificates are signed by the intermediate CA so there is no need to store the private key of the Root CA on the system. Because it could be required to use the root CA private key later, e.g. upon rotation or replacement of the intermediate certificate keys, store the private key of the root CA and it’s encryption password in a save location before removing the root CA private key from the system!

The private SSL key of the root certificate is stored in ${STEPPATH}/secrets/root_ca_key

Important: Do NOT remove the public key! All clients require the public key of your root CA for certificate validation.

Change the password if the intermediate CA
The private keys of the intermediate CA and the root CA are encrypted using the same password.

To avoid password leakage of the encryption password, the password of the encrypted SSL key of the intermediate CA should be changed.

This can be done by running step ca crypto change-pass:

root@vasquez:~# step crypto change-pass /etc/step-ca/secrets/intermediate_ca_key
Please enter the password to decrypt /etc/step-ca/secrets/intermediate_ca_key:
Please enter the password to encrypt /etc/step-ca/secrets/intermediate_ca_key:
✔ Would you like to overwrite /etc/step-ca/secrets/intermediate_ca_key [y/n]: y
Your key has been saved in /etc/step-ca/secrets/intermediate_ca_key.
Save the new password in a file which will be provided to CA service, for instance in secrets/intermediate.pass below ${STEPPATH}

Important! Never provide the password as command line option to the service! Every user (even nobody) can use connmands like ps to view the command line - and the password - of all processes. Important! Don’t use environment variables for passwords too, they are exported to /proc/<pid>/env of each process and can be easily read, e.g. by xargs -0 < /proc/<pid>/env

Create a service user for the CA service
Following the principal of leaste privilege, it is not recommended to run the CA service as root. Simply create a service user for the CA service, e.g.:

getent passwd step
step:*:777:777:Step-CA service user:/etc/step-ca:/sbin/nologin
Enforcing permissions and ownership
Depending on your umask settings, the permissions of the files created can be to permissive. Additionally all files and directories must belong to the service user - called step in this case - to allow the CA service to access the data.

A good permission should be:

root@vasquez:~# find /etc/step-ca/ -ls
       34      1 drwx------   7 step     step            7 Jul 23 14:48 /etc/step-ca/
       11      1 drwx------   2 step     step            4 Jul 23 14:29 /etc/step-ca/certs
      140      2 -rw-------   1 step     step          818 Jul 23 14:29 /etc/step-ca/certs/root_ca.crt
      134      2 -rw-------   1 step     step          875 Jul 23 14:29 /etc/step-ca/certs/intermediate_ca.crt
       17      1 drwx------   2 step     step            5 Jul 24 11:09 /etc/step-ca/config
      121      2 -rw-------   1 step     step         1276 Jul 24 11:09 /etc/step-ca/config/ca.json
      158      1 -rw-------   1 step     step          225 Jul 23 15:50 /etc/step-ca/config/defaults.json
      149      1 drwx------   2 step     step            2 Jul 23 14:29 /etc/step-ca/db
       14      1 drwx------   2 step     step            5 Jul 24 11:37 /etc/step-ca/secrets
      233      1 -rw-------   1 step     step           70 Jul 24 11:37 /etc/step-ca/secrets/intermediate.pass
      137      1 -rw-------   1 step     step          314 Jul 24 11:34 /etc/step-ca/secrets/intermediate_ca_key
       20      1 drwx------   2 step     step            2 Jul 23 14:29 /etc/step-ca/templates
Info: Don’t worry about the access to the public key of the root CA, it can be obtained either by bootstraping the step environment of the user or by download from https://<your_ca>:8443/roots.pem, e.g. https://pki.internal.ypbind.de:8443/roots.pem in this case.

Running the CA as a service for remote access
step-ca runs as a process to allow remote access to the CA.

Although the package don’t contain a service unit for systemd, it can be easily created.

A systemd unit file called step-ca.service could look like:

[Unit]
Description=step-ca service
Documentation=https://smallstep.com/docs/step-ca
Documentation=https://smallstep.com/docs/step-ca/certificate-authority-server-production
After=network-online.target sssd.service
Wants=network-online.target sssd.service
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=simple
User=step
Group=step
Environment=STEPPATH=/etc/step-ca
WorkingDirectory=/etc/step-ca
ExecStart=/usr/bin/step-ca config/ca.json --password-file secrets/intermediate.pass
ExecReload=/bin/kill --signal HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=30
StartLimitBurst=3

; Process capabilities & privileges
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureBits=keep-caps
NoNewPrivileges=yes

; Sandboxing
; This sandboxing works with YubiKey PIV (via pcscd HTTP API), but it is likely
; too restrictive for PKCS#11 HSMs.
;
; NOTE: Comment out the rest of this section for troubleshooting.
ProtectSystem=full
ProtectHome=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectKernelModules=true
LockPersonality=true
RestrictSUIDSGID=true
RemoveIPC=true
RestrictRealtime=true
PrivateDevices=true
SystemCallFilter=@system-service
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
ReadWriteDirectories=/etc/step-ca/db

[Install]
WantedBy=multi-user.target
After reloading the systemd configuration (systemctl daemon-reload) the service can be enabled and stared (systemctl enable --now step-ca.service)

Handling provisioners
Administrators and super administrators
An administrator account are accounts which can manage providers, where as the super administrator accounts can manage providers and manage administrator accounts.

Default JWK provisioner
The configuration of the remote provisioner can be queried after the service start by running:

[maus@vasquez:~]$ step ca admin list
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): step
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
SUBJECT PROVISIONER     TYPE
step    Admin JWK (JWK) SUPER_ADMIN
Adding additional super administrator accounts
In a real envirionment of multiple administrators. This involves managing of accounts for SSL certificate processes (signing, revoking, renewal, …)

To add an account with super administration rights, the command line option --super must be provided, e.g.:

[maus@vasquez:~]$ step ca admin add --super superadmin "Admin JWK"
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): step
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
SUBJECT         PROVISIONER     TYPE
superadmin      Admin JWK (JWK) SUPER_ADMIN
Removal of the default super administrator
After the creation of the first new super administrator account, the default account step should be removed. This will be done by the step ca admin remove command:

[maus@vasquez:~]$ step ca admin remove step
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): superadmin
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
✔ Admin: subject: step, provisioner: Admin JWK(JWK), type: SUPER_ADMIN
Adding a (non-super admin) JWT provisioner
For regular tasks a JWT provisioner (without super admin privileges) can be added by a provisioner with super admin privileges

maus@vasquez:~$ step ca provisioner add new_admin --type JWK --create
Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]:
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): superadmin
Use the arrow keys to navigate: ↓ ↑ → ←
What provisioner key do you want to use?
  ▸ Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
    acme (ACME)
    maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
Removing a provisioner
Using a provisioner with super admin privileges, existing provisioners can be removed by running the `step ca admin

maus@vasquez:~$ step ca  provisioner remove new_admin
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): superadmin
Use the arrow keys to navigate: ↓ ↑ → ←
What provisioner key do you want to use?
  ▸ Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
    acme (ACME)
    maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
    new_admin (JWK) [kid: mLpg9HogT6u3TZUmgxlHjPS7iStJB5lC-k186mKg6k0]
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
Listing existing provisioners
The list of existing provisioners can be obtained by running the step ca provisioner list command which will output te informations about present provisioners in JSON format.

This can be filtered using jq, for instance to list the names of existing provisioners:

maus@vasquez:~$ step ca provisioner list | jq -r '.[].name'
Admin JWK
acme
maus
new_admin
Adding provisioner for ACME
If possible, SSL certificates for services should be short lived and renewed automatically using the ACME protocol. To allow certificate renewal using ACME, a provisioner for ACME must be added too.

This can be easily done by running:

[maus@vasquez:~]$ step ca provisioner add acme --type ACME
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): superadmin
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
Steps in a multi-admin environment
In a larger, real environment administration will be done multiple persons. New administrators will join, other administrators will leave or change to another customers.

Important
Super admmin privileges
All commands, including changing a provisioners password require super admin privileges.
Adding a new user
At the moment the only way to manage separate accounts each with it’s own passwords is the creation of a provisioner for each account.

The default provisioner type of JWK token is ok for us, so we stick with it.

Creating a new provisioner can be done by the step ca provisionier add command:

[maus@vasquez:~]$ step ca provisioner add maus --type JWK --create
Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]:
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): superadmin
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
Every new administrator must boottrap the local environment by running step ca bootstrap, e.g.:

[maus@vasquez:~]$ step ca bootstrap --ca-url=https://pki.internal.ypbind.de:8443 --fingerprint=b7413e0c6a0572862fcc81feddefef3bdfe76fe03c56058571c4b7d859a2924f
The root certificate has been saved in /home/maus/.step/certs/root_ca.crt.
The authority configuration has been saved in /home/maus/.step/config/defaults.json.
Removing old user
If an administrator is leaving, it’s provisioner should be remove too. Similar to the creation of a new provisioner an existing provisioner can be removed by running step ca provisioner remove <name>

Change a (JWT) provisioners password
To change the password of a JWT provisionert, it’s encrypted private key must be decrypted using the old passphrase and re-encrypted with the new passphrase. At first the current encrypted JWT key must be obtained:

maus@vasquez:~$ OLD_KEY=$(step ca provisioner list | jq -r '.[] | select(.name == "provisionername").encryptedKey')
To generate the new encrypted key, the old key must be decrypted and re-encrypted:

maus@vasquez:~$ NEW_KEY=$(echo $OLD_KEY | step crypto jwe decrypt | step crypto jwe encrypt -alg PBES2-HS256+A128KW | step crypto jose format)
Please enter the password to decrypt the content encryption key:
Please enter the password to encrypt the content encryption key:
Finally the provisioners data can be updated to the newly generated key:

maus@vasquez:~$ step ca provisioner update forgetful_admin --private-key=<(echo -n "${NEW_KEY}")
No admin credentials found. You must login to execute admin commands.
✔ Please enter admin name/subject (e.g., name@example.com): superadmin
Use the arrow keys to navigate: ↓ ↑ → ←
What provisioner key do you want to use?
  ▸ Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
    acme (ACME)
    maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
    forgetful_admin (JWK) [kid: Yx5mwRnWOzzTe8HXUE3-qY1jTs0WqRST3zYO0iufFYY]
✔ Provisioner: Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Please enter the password to decrypt the provisioner key:
Warning
Although the help text of the step crypto jwe encrypt lists the -alg option as optional if the old JWT token contains the alg field, the -alg field must always be provided when encypting the key.
Reseting the password of a provisioner
Important
Reseting a provisioner password
There is no way to reset a provisioners password! The provisioner must be deleted and newly created.
Common tasks
Manually creating a certificate signing request
Using openssl
Although it’s still possible to create a CSR using openssl req …​ command, it’s not recommended to do so. That’s because the subject alternate names must be included in the CSR it’s rather cumbersome archive because it requires the creation of an openssl configuration file for each CSR to generate..

Using step client
The step command from the step-cli pacakge can be used to create a CSR and set the subject alternate name as specified on the command line

For instance to create a CSR with three differend DNS subject alternate names and a encrypted RSA key with a length of 4096 bits with the subject '/C=DE/O=internal.ypbind.de/OU=Directory service/CN=sulaco.internal.ypbind.de':

maus@vasquez:~$ step certificate create --csr --san=sulaco.internal.ypbind.de --san=sulaco.insecure --san=sulaco.ypbind.de --kty=RSA --size=4096 '/C=DE/O=internal.ypbind.de/OU=Directory service/CN=sulaco.internal.ypbind.de' sulaco.csr sulaco.key
Please enter the password to encrypt the private key:
Your certificate signing request has been saved in sulaco.csr.
Your private key has been saved in sulaco.key.
The generated CSR file can be verfified by the openssl req command:

maus@vasquez:~$ openssl req -in sulaco.csr -noout -text
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = /C=DE/O=internal.ypbind.de/OU=Directory service/CN=sulaco.internal.ypbind.de
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:b4:14:44:5a:fe:f0:3c:54:67:e1:e4:c5:e6:65:
...
                    b3:b9:01
                Exponent: 65537 (0x10001)
        Attributes:
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:sulaco.internal.ypbind.de, DNS:sulaco.insecure, DNS:sulaco.ypbind.de
    Signature Algorithm: sha256WithRSAEncryption
         78:50:7c:a5:2f:40:a5:5f:0b:2b:41:81:97:9b:c2:85:b0:13:
...
         01:c0:72:98:83:3c:a3:c9
Tip
To create a unencyrpted private key, use parameters --no-password --insecure
Certificate signing
Signing with provisioner name and password
Certificate signing requests can be signed by the CA with authentication using a defined provisioner and it’s password, e.g.:

maus@vasquez:~$ step ca sign --not-after=26400h --provisioner=maus sulaco.csr sulaco.pem
✔ Provisioner: maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Please enter the password to decrypt the provisioner key:
✔ CA: https://pki.internal.ypbind.de:8443
✔ Certificate: sulaco.pem
Signing with a JWT token
Signing a CSR by providing provisioner name and password is not recommended for automated use, e.g. inside a container. A more secure way, because it will never expose the provisioner password, is the use of a pre-generated JWT token.

The token is only valid for a short time.

For instance:

maus@vasquez:~$ TOKEN=$(step ca token --provisioner=maus --san=ripley.internal.ypbind.de --san=ripley.badphish.ypbind.de '/C=DE/O=internal.ypbind.de/OU=Directory service/CN=ripley.internal.ypbind.de')
✔ Provisioner: maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Please enter the password to decrypt the provisioner key:
maus@vasquez:~$ echo ${TOKEN}
eyJhbGciOiJFUzI1NiIsImtpZCI6IjFWLU...
After the token has been obtained, it can be passed to the signing command using the --token command line option:

maus@vasquez:~$ step ca sign --not-after=26400h --token=${TOKEN} ripley.csr ripley.pem
✔ CA: https://pki.internal.ypbind.de:8443
✔ Certificate: ripley.pem
Caution
The command to create the token MUST contain ALL subject alternate names and exactly as given by ths CSR geneation command If the subject alternate names are missing, incomplete or wrong the CA wil reject the signing process, e.g.:
maus@vasquez:~$ step ca sign --not-after=26400h --token=${TOKEN_WITH_SAN_INCOMPLEE} ripley.csr ripley.pem
✔ CA: https://pki.internal.ypbind.de:8443
The request was forbidden by the certificate authority: certificate request does not contain the valid DNS names - got [ripley.internal.ypbind.de ripley.badphish.ypbind.de], want [/C=DE/O=internal.ypbind.de/OU=Directory service/CN=ripley.internal.ypbind.de].
Re-run with STEPDEBUG=1 for more info.
Certificate renewal
Manual renewal
To renew a certificate the private and the public part of the certificate is required. To replace the current public key file of the certificate - instead of creation of a new file (requires --out option) - the --force option can be used for the step ca renew command.

root@vasquez:~# step ca renew  --force /etc/dovecot/ssl/imap_imap.internal.ypbind.de.pem /etc/dovecot/ssl/imap_imap.internal.ypbind.de.key
Your certificate has been saved in /etc/dovecot/ssl/imap_imap.internal.ypbind.de.pem.
For encrypted private keys, the password must be stored in a file (make sure to restrict the access!) and pass it using the --password-file option.

The private key of the certificate is used to authenticate against the Step-CA service for renewal.

Important
It’s not possible to renew a expired certificate:
maus@vasquez:~$ step ca renew  --force /etc/postfix/ssl/new_smtp_ypbind.de.pem /etc/postfix/ssl/new_smtp_ypbind.de.key
error renewing certificate: The request lacked necessary authorization to be completed: certificate expired on 2022-09-20 12:30:07 +0000 UTC
To specify a expiration period of the new certificate add the --expires-in option, otherwise the default setting of .authority.claims.defaultTLSCertDuration from the config/ca.json file will be used.

Automatic renewal
Step-CA client can run as a daemon to renew certificates using the public and private key if two thirds of the certificate expiration has passed. This can be accomplished by passing the --daemon option. If the certificate has been renewed either the signal and PID file (--signal / --pid-file) can be passed to send the PID the defined signal or a command - given by the --exec option - can be defined to run a command.

Certificate revocation
Certificates for compromised services or services / systems no longer in use can and should be revoked before their expiration.

Two types of revocation exists.

Active revocation means client will check for revoked certificates by fetching a CRL file or query an OCSP responder.

Passive revocation means client will not check for revoked certificates. Certificates are only marked as revoked by the CA.

Note
At the momen Step CA only supports passive revocation.
Certificates can be revoked by:
it’s serial number (e.g. fetched by running openssl x509 -in <cert> -noout -text -serial) - step ca revoke serial_mumber

it’s public/private key pair - step ca revoke --cert=/path/to/pulic.pem --key=/path/to/private.key

Tip
Although a revocation reason (--reason="Lore ipsum…​") is optional it should always be used to impreove the transprarency of certificate revocation
Important
If the private key is encrypted, it’s passphrase must be entered to decrypt the key.
Important
Certificates can’t be revoked by their serial number if you use an OIDC provisioner.
Revoke a certificate using a provisioner
By default certificates are revoked using a provisioner for authentication:

maus@vasquez:~$ openssl x509 -in ssl/ripley.pem -noout -serial
serial=7CCDFDB5E70F0993029A6110603B05F4
maus@vasquez:~$ maus@vasquez:~$ step ca revoke --reason="Service has been remove and is no longer in use" 0x7CCDFDB5E70F0993029A6110603B05F4
Use the arrow keys to navigate: ↓ ↑ → ←
What provisioner key do you want to use?
    Admin JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
    acme (ACME)
  ▸ maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Please enter the password to decrypt the provisioner key:
✔ CA: https://pki.internal.ypbind.de:8443
Revoke a certificate using a JWT token
For automation, revocation should be done by generating a JWT revokation token and revoke the certificate by authentication using the JWT token.

A revocation token can be obtained by using the --revoke option of the step ca token command.

maus@vasquez:~$ TOKEN=$(step ca token --issuer=maus --revoke 0x0B5A836AF402C27EBD7B4653EC422804)
✔ Provisioner: maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Please enter the password to decrypt the provisioner key:
maus@vasquez:~$ step ca revoke --reason="HTTP service has been migrated to the new server" --token=${TOKEN} 0x0B5A836AF402C27EBD7B4653EC422804
✔ CA: https://pki.internal.ypbind.de:8443
Certificate with Serial Number 0x0B5A836AF402C27EBD7B4653EC422804 has been revoked.
Note
A revocation token can only be used for certificate revocation.
Using ACME for automatic certificate deployment
Automatic certificate installation and renewal can be done by using the ACME protocol. Using ACME for certicate issuing, installation and renewal is easy with Step CA.

Add and configure an acme provisioner and point the ACME tool to the URL at https://<step_ca_url>/acme/<name_of_the_acme_provisioner>/directory.

For instance for the https://github.com/acmesh-official/acme.sh(acme.sh) tool in this setup use acme.sh --server https://pki.internal.ypbind.de:8443/acme/acme/directory …​

For example a web service - rss.ypbind.de - with the following configuration for the http-01 ACME challenge

Alias /.well-known/acme-challenge "/var/www/rss.ypbind.de/letsencrypt/.well-known/acme-challenge"
<Directory "/var/www/rss.ypbind.de/letsencrypt/.well-known">
    AllowOverride   None
    Require all granted
</Directory>
can be installed by running:

root@vasquez:~# acme.sh --issue --domain rss.ypbind.de --server https://pki.internal.ypbind.de:8443/acme/acme/directory --ca-bundle /etc/step-ca/certs/root_ca.crt --fullchain-file /etc/apache2/ssl/rss.ypbind.de.pem --key-file /etc/apache2/ssl/rss.ypbind.de.key --reloadcmd "service apache2 force-reload" --webroot /var/www/rss.ypbind.de/letsencrypt/
[Mon 12 Dec 2022 05:48:29 PM CET] Using CA: https://pki.internal.ypbind.de:8443/acme/acme/directory
[Mon 12 Dec 2022 05:48:29 PM CET] Single domain='rss.ypbind.de'
[Mon 12 Dec 2022 05:48:29 PM CET] Getting domain auth token for each domain
[Mon 12 Dec 2022 05:48:29 PM CET] Getting webroot for domain='rss.ypbind.de'
[Mon 12 Dec 2022 05:48:29 PM CET] Verifying: rss.ypbind.de
[Mon 12 Dec 2022 05:48:30 PM CET] Success
[Mon 12 Dec 2022 05:48:30 PM CET] Verify finished, start to sign.
[Mon 12 Dec 2022 05:48:30 PM CET] Lets finalize the order.
[Mon 12 Dec 2022 05:48:30 PM CET] Le_OrderFinalize='https://pki.internal.ypbind.de:8443/acme/acme/order/498GyYsv9EnNHqnGnasARdx12WyG32d7/finalize'
[Mon 12 Dec 2022 05:48:30 PM CET] Downloading cert.
[Mon 12 Dec 2022 05:48:30 PM CET] Le_LinkCert='https://pki.internal.ypbind.de:8443/acme/acme/certificate/2cW0M6iT6HqS9eupGVAltFR1SAo0QZMu'
[Mon 12 Dec 2022 05:48:30 PM CET] Cert success.
-----BEGIN CERTIFICATE-----
MIIDDDCCArGgAwIBAgIQPb74n+U+mNE3tDwKv2iRTjAKBggqhkjOPQQDAjB+MTUw
MwYDVQQKEyxDZXJ0aWZpY2F0ZSBhdXRob3JpdHkgZm9yIGludGVybmFsLnlwYmlu
ZC5kZTFFMEMGA1UEAxM8Q2VydGlmaWNhdGUgYXV0aG9yaXR5IGZvciBpbnRlcm5h
bC55cGJpbmQuZGUgSW50ZXJtZWRpYXRlIENBMB4XDTIyMTIxMjE2NDcyOVoXDTIz
MDExMTE2NDgyOVowGDEWMBQGA1UEAxMNcnNzLnlwYmluZC5kZTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBALl7uZ5IZojjqBRMauGG/dYgo/q3a5XqxBwe
qlfaiVNSHYXhsM0K4KOwQIJrcQTdii5XmL/YHpV8UCeN7YIMGvYzrzII9lsiCEkd
y/NHvlN4rZ2Q4zgcFshW8rK436x2LS2yNlF8orIiU1FIYYmzWg+AK1nfnoPoOR6Z
mw+1GUBqFMD+kJdxyHlM3KpGSPSfCfm3Sl0SSW5hv7KPxGS1cAwq6xM+CY8T7VR7
AHLcuXaWAre7lglNhpvmLrKhdnHTQJfmIQdPPeNceISMFif+y2HAreTyTNKjywWe
Ysr4KNVZUao2a2PWq/y5lTNMr5ymEjfQSwdhI4a3A6Q0iBmdSp0CAwEAAaOBqzCB
qDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MB0GA1UdDgQWBBQ9WzU+r0YkaPhntTzBz12U2GBw0DAfBgNVHSMEGDAWgBQ9wBiD
qsyN5DOnBYsfywAYVcEKvDAYBgNVHREEETAPgg1yc3MueXBiaW5kLmRlMB0GDCsG
AQQBgqRkxihAAQQNMAsCAQYEBGFjbWUEADAKBggqhkjOPQQDAgNJADBGAiEAyY5h
gUJa13wCHqONKUoXTSFHhEoxBdEirOM7adboBqYCIQDo3STBKU910lUQjMLHo8RR
n/4AcTOQqbn1bsFSF6xgEg==
-----END CERTIFICATE-----
[Mon 12 Dec 2022 05:48:30 PM CET] Your cert is in: /etc/acme.sh/rss.ypbind.de/rss.ypbind.de.cer
[Mon 12 Dec 2022 05:48:30 PM CET] Your cert key is in: /etc/acme.sh/rss.ypbind.de/rss.ypbind.de.key
[Mon 12 Dec 2022 05:48:30 PM CET] The intermediate CA cert is in: /etc/acme.sh/rss.ypbind.de/ca.cer
[Mon 12 Dec 2022 05:48:30 PM CET] And the full chain certs is there: /etc/acme.sh/rss.ypbind.de/fullchain.cer
[Mon 12 Dec 2022 05:48:30 PM CET] Installing key to: /etc/apache2/ssl/rss.ypbind.de.key
[Mon 12 Dec 2022 05:48:30 PM CET] Installing full chain to: /etc/apache2/ssl/rss.ypbind.de.pem
[Mon 12 Dec 2022 05:48:30 PM CET] Run reload cmd: service apache2 force-reload
[Mon 12 Dec 2022 05:48:31 PM CET] Reload success
Note
We don’t use the --apache flag for acme.sh because it messes up /etc/apache2/apache2.conf by adding /home/.acme as path. In this case /home is an automount path for user homes from central storage servers.
The cronjob /etc/cron.d/acme-sh of the Debian/Ubuntu package for acme.sh will renew the certificate if neccessary and will restart the service if the --reloadcmd was provided.

