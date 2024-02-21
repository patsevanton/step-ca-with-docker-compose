```shell
sudo eget smallstep/cli --to /usr/local/bin
docker compose up
Find Root fingerprint (CA_FINGERPRINT)
step ca bootstrap --ca-url https://localhost:9000 --fingerprint $CA_FINGERPRINT
```

clean all volume:
```shell
docker volume prune -a
```

https://habr.com/ru/articles/671730/


Генерация ключей и сертификатов

Генерируем ключ и сертификат для сервера и установки TLS соединения, потом для клиента и установки mTLS.

CA Smallstep может одновременно сформировать приватный ключ сервера 2048-бит RSA (server.key) и запрос на сертификат (server.csr). В запросе явно указываем, что пароль должен быть пустой (no-password), localhost - это IP адрес сервера, для которого генерируется запрос:

```
step certificate create --csr --no-password --insecure --kty=RSA --size=2048 localhost server.csr server.key
```

Подписываем сертификат на нашем CA Smallstep:
```
step ca sign server.csr server.crt
```
Смотрим полученный сертификат:
```
step certificate inspect server.crt
```
Получаем с CA Smallstep его корневой сертификат:
```
step ca root root_ca.crt
```
Смотрим корневой сертификат:
```
step certificate inspect root_ca.crt
```
Аналогично OpenSSL копируем ключи и сертификаты на наш HTTPS сервер:

root_ca.crt

server.key

server.crt

Запускаем сервер:
```
node server.js
```
Проверяем сервер curl-ом:
```
curl https://xx.xx.xx.xx:9443
```