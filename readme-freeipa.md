### Install freeipa by ansible and terraform to Yandex Cloud
https://github.com/xetus-oss/freeipa-pwd-portal/blob/master/docker-compose.yaml
https://stackoverflow.com/questions/71096130/freeipa-docker-compose-web-ui
https://www.linkedin.com/pulse/how-install-freeipa-ubuntu-docker-packopsdev-farshad-nickfetrat/
https://habr.com/ru/post/254233/


### Check certificate
```commandline
openssl req -text -in  apatsev.org.ru.csr 
openssl x509 -text -noout -in apatsev.org.ru_cert.pem 
```
