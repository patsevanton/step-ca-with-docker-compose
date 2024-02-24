Install binary
```shell
sudo eget smallstep/cli --to /usr/local/bin
```

Init Root CA
```shell
docker compose up -d
sleep 3
fingerprint=$(docker compose logs | grep fingerprint | awk '{print $6}')
rm ${HOME}/.step/certs/root_ca.crt || true
rm ${HOME}/.step/config/defaults.json || true
step ca bootstrap --ca-url https://localhost:9000 --fingerprint $fingerprint
```

clean all volumes:
```shell
docker compose down
yes | docker system prune
yes | docker volume prune -a
```

https://habr.com/ru/articles/671730/

Получаем с CA Smallstep его корневой сертификат:
```shell
step ca root root_ca.crt
```
Смотрим корневой сертификат:
```shell
step certificate inspect root_ca.crt
```

Генерация ключей и сертификатов

Генерируем ключ и сертификат для сервера и установки TLS соединения, потом для клиента и установки mTLS.

CA Smallstep может одновременно сформировать приватный ключ сервера 2048-бит RSA (server.key) и запрос на сертификат (server.csr). В запросе явно указываем, что пароль должен быть пустой (no-password), localhost - это DNS адрес сервера, для которого генерируется запрос:

```shell
step certificate create --csr --no-password --insecure --kty=RSA --size=2048 localhost server.csr server.key
```

Подписываем сертификат на нашем CA Smallstep. Вводим пароль указанный в DOCKER_STEPCA_INIT_PASSWORD_FILE
```shell
step ca sign server.csr server.crt
```
Смотрим полученный сертификат:
```shell
step certificate inspect server.crt
```

Аналогично OpenSSL копируем ключи и сертификаты на наш HTTPS сервер:

root_ca.crt

server.key

server.crt

Запускаем сервер:
```shell
node server.js
```
Проверяем сервер curl-ом:
```shell
curl https://xx.xx.xx.xx:9443
```