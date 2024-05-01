[Step-CA](https://smallstep.com/docs/step-ca) - это сложная система центра сертификации с открытым исходным кодом (Apache License 2.0) с поддержкой протокола [ACME](https://datatracker.ietf.org/doc/html/rfc8555).

# Инициализация
После установки необходимых пакетов (`step-ca` для самого центра сертификации и `step-cli` для клиентской программы) сам центр сертификации может быть инициализирован. Для инициализации требуются DNS-имена, имя центра сертификации (будет частью субъекта сертификата корневого центра сертификации и сертификата промежуточного центра сертификации), тип развертывания, а также IP и порт для прослушивания службой [CA](https://en.wikipedia.org/wiki/Certificate_authority).

## Важно
Тип развертывания и имя центра сертификации впоследствии изменить нельзя!
Чтобы инициализировать центр сертификации, выполните команду `step ca init …​`. Переменная среды `STEPPATH` может быть настроена так, чтобы указывать каталог центра сертификации, в противном случае используется текущий каталог:
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
Обратите внимание на отпечаток root, он требуется начальной загрузкой для каждого пользователя. Его также можно получить из выходных данных при запуске `step-ca` службы.

# Используйте PostgreSQL в качестве серверной части базы данных
Тип базы данных по умолчанию - [BoltDB](https://dbdb.io/db/boltdb). Недостатком BoltDB является то, что доступ ограничен одним процессом, в данном случае step-ca службой. В продуктивной среде несколько процессов будут обращаться к базе данных одновременно, например, для создания [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list), экспорта статистики в [Prometheus](https://github.com/prometheus/prometheus), …

Базу данных можно легко изменить. Не имеет значения, используется ли PostgreSQL или MySQL/MariaDB. Единственное различие заключается в конфигурации базы данных и разделе конфигурации в `Step-CA` configuration.

Просто установите PostgreSQL, добавьте пользователя - в данном случае step-ca - для базы данных:
```
postgres@vasquez:~$ createuser --no-createdb --login --pwprompt --no-createrole --no-superuser --no-replication step-ca
Enter password for new role:
Enter it again:
```
Создайте пустую базу данных `step_ca_db` в этом случае и назначьте ее новому пользователю:
```
postgres@vasquez:~$ createdb --encoding=UTF-8 --owner=step-ca step_ca_db
```
Примечание: Кодировка не требуется, но для обеспечения согласованности все мои базы данных используют UTF-8 в качестве кодировки.

В файле конфигурации центра сертификации (`${STEPPATH}/config/ca.json`) замените конфигурацию в `db` словаре конфигурацией PostgreSQL:
```
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
```
# Сохраняйте провайдеров в базе данных
Вместо хранения провайдеров в файле конфигурации удобнее использовать базу данных. Это можно легко заархивировать, удалив всех провайдеров из файла конфигурации `ca.json` и + включить поддержку удаленных администраторов, установив `enableAdmin` значение `true` в `authority` разделе:
```
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
```
Это добавит поставщика JWK `Admin JWK` в базу данных и создаст пользователя по умолчанию `step` с правами суперадминистрации для вновь созданного поставщика. Пароль `step` пользователя совпадает с паролем для закрытого ключа корневого центра сертификации, предоставленного `step ca init` процессом.

# Включить ACME provisioner
Поскольку большинство сертификатов обслуживания будут обновляться с использованием протокола ACME, ACME provisioner необходимо добавить в `provisioner` раздел файла конфигурации.

По умолчанию сертификаты сервера для внутренних служб будут действительны в течение 90 дней (2160 часов), и если CN не может быть найден, вместо него будет использоваться значение расширения альтернативного имени субъекта (`forceCN` установлено в `true` значение).

```
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
```
Добавление дополнительных расширений сертификатов
По умолчанию в сгенерированных сертификатах отсутствует информация о точке распространения CRL, URL OCSP и доступе к информации о полномочиях.

Дополнительные расширения
 - Доступ к информации об полномочиях - http://pki.internal.ypbind.de:8888/intermediate_ca.crt

 - Точка распространения CRL - http://pki.internal.ypbind.de:8888/intermediate_ca.crl

 - URL-адрес ответчика OCSP - http://pki.internal.ypbind.de:8889/

Это можно легко заархивировать, создав пользовательский шаблон сертификата, `/etc/step-ca/templates/leaf_certificate.tpl` определив дополнительные расширения сертификата:

```
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
```
Если поставщик настроен в ca.json файле, файл шаблона должен быть добавлен к поставщику (ам).

Важно
Провайдеры в базе данных
Если провайдеры хранятся в базе данных, как в этой настройке, файл шаблона должен быть настроен для каждого провайдера в базе данных. Кроме того, все вновь созданные поставщики также должны быть созданы с новым шаблоном сертификата! На данный момент templateFile не может быть настроен с помощью step ca provisioner add / step ca provisioner update для удаленных провайдеров, см. Разрешите step ca provisioner update установить параметр templateFile для провайдера #720
Изменения, зависящие от сайта
В корпоративной среде существуют некоторые системы (например, платы управления серверами), которые не поддерживают протокол ACME. Поскольку серверы обычно заменяются каждые три года, а платы управления находятся в отдельном сегменте сети, доступном только с некоторых выделенных хостов jump, будут использоваться SSL-сертификаты, действительные около 3 лет.

Примечание
Платы управления
Хотя большинство систем управления поддерживают Redfish REST API, не каждый поставщик оборудования поддерживает автоматическое развертывание SSL-сертификатов. Кроме того, для замены SSL-сертификатов системы управления потребуется перезагрузка процессора управления, что приведет к нарушению доступа к системе управления.
Для этого сайта все сертификаты обслуживания будут действительны в течение 30 дней вместо установленного по умолчанию 1 дня, поскольку некоторые службы требуют перезапуска при изменении SSL-сертификата, что приведет к сбоям в работе некоторых клиентов, например, при использовании REDIS publish / subscribe, длительного опроса MQTT или HTTP и шторма повторного подключения.

Чтобы избежать подписания сертификатов для других доменов, разрешенные (и отклоненные) значения для расширений subjectAltername x509.v3 могут быть ограничены.

Это можно заархивировать, расширив authority раздел файла конфигурации центра сертификации ca.json:

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
Усиление
Удаление закрытого ключа корневого центра сертификации
Все сертификаты подписываются промежуточным центром сертификации, поэтому нет необходимости хранить закрытый ключ корневого центра сертификации в системе. Поскольку может потребоваться использовать закрытый ключ корневого центра сертификации позже, например, при ротации или замене ключей промежуточных сертификатов, сохраните закрытый ключ корневого центра сертификации и пароль для шифрования в месте сохранения, прежде чем удалять закрытый ключ корневого центра сертификации из системы!

Закрытый SSL-ключ корневого сертификата хранится в ${STEPPATH}/secrets/root_ca_key

Важно: НЕ удаляйте открытый ключ! Всем клиентам требуется открытый ключ вашего корневого центра сертификации для проверки сертификата.

Измените пароль, если промежуточный центр сертификации
Закрытые ключи промежуточного центра сертификации и корневого центра сертификации зашифрованы с использованием одного и того же пароля.

Чтобы избежать утечки пароля шифрования, пароль зашифрованного SSL-ключа промежуточного центра сертификации должен быть изменен.

Это можно сделать, выполнивstep ca crypto change-pass:

root@vasquez:~# step crypto change-передать /etc/step-ca/secrets/intermediate_ca_key
Пожалуйста, введите пароль для расшифровки /etc/step-ca/secrets/intermediate_ca_key:
Пожалуйста, введите пароль для шифрования /etc/step-ca/secrets/intermediate_ca_key:
✔ Хотите ли вы перезаписать /etc/step-ca/secrets/intermediate_ca_key [y / n]: y
Ваш ключ был сохранен в /etc/step-ca/secrets/intermediate_ca_key.
Сохраните новый пароль в файле, который будет предоставлен службе центра сертификации, например, в secrets/intermediate.pass ниже ${STEPPATH}

Важно! Никогда не предоставляйте службе пароль в качестве опции командной строки! Каждый пользователь (даже nobody) может использовать команды подключения, подобные ps для просмотра командной строки - и пароля - всех процессов. Важно! Также не используйте переменные среды для паролей, они экспортируются в /proc/<pid>/env каждого процесса и могут быть легко прочитаны, например, с помощью xargs -0 < /proc/<pid>/env

Создайте пользователя службы для службы CA
В соответствии с принципом наименьших привилегий не рекомендуется запускать службу CA как root. Просто создайте пользователя службы для службы CA, например:

шаг получения пароля 
шаг: *:777:777: Пользователь службы Step-CA:/etc/step-ca:/sbin/nologin
Обеспечение соблюдения разрешений и прав собственности
В зависимости от ваших umask настроек разрешения для создаваемых файлов могут быть разрешающими. Кроме того, все файлы и каталоги должны принадлежать пользователю службы, в данном случае называемойstep, чтобы разрешить службе центра сертификации доступ к данным.

Хорошее разрешение должно быть:

root@vasquez:~# find /etc/step-ca/ -ls 
 34 1 drwx------ 7 step step 7 июля 23:48 /etc/step-ca/
 11 1 drwx------ 2 шаг 4 23 июля 14:29 /etc/step-ca/сертификаты
 140 2 -rw------- 1 пошаговый шаг 818 23 июля 14:29 /etc/step-ca/сертификаты/root_ca.crt
 134 2 -rw------- 1 step step 875 23 июля 14:29 /etc/step-ca/сертификаты/intermediate_ca.crt 
 17 1 drwx------ 2 шаг шаг 5 24 июля 11:09 /etc/step-ca/config 
 121 2 -rw------- 1 шаг шаг 1276 24 июля 11:09 /etc/step-ca/config/ca.json 
 158 1 -rw------- 1 пошаговый шаг 225 23 июля 15:50 /etc/step-ca/config/defaults.json 
 149 1 drwx------ 2 шаг 2 23 июля 14:29 /etc/step-ca/db
 14 1 drwx------ 2 шаг 5 24 июля 11:37 /etc/step-ca/секреты
 233 1 -rw------- 1 пошаговый шаг 70 24 июля 11:37 /etc/step-ca/секреты / промежуточный уровень.прохождение 
 137 1 -rw------- 1 пошаговый шаг 314 24 июля 11:34 /etc/step-ca/секреты/intermediate_ca_key
 20 1 drwx------ 2 шаг 2 23 июля 14:29 /etc/step-ca/шаблоны
Информация: Не беспокойтесь о доступе к открытому ключу корневого центра сертификации, его можно получить либо путем начальной загрузки из step среды пользователя, либо путем загрузки из https://<your_ca>:8443/roots.pem, например, https://pki.internal.ypbind.de:8443/roots.pem в этом случае.

Запуск центра сертификации как службы для удаленного доступа
step-ca выполняется как процесс, разрешающий удаленный доступ к центру сертификации.

Хотя пакет не содержит сервисного модуля для systemd, его можно легко создать.

Файл модуля systemd с именем step-ca.service может выглядеть следующим образом:

[Модуль]
Описание= служба step-ca
Документация= https://smallstep.com/docs/step-ca
Документация= https://smallstep.com/docs/step-ca/центр сертификации-сервер-производство
После = network-online.target sssd.service
Хочет = сеть-онлайн.целевой sssd.service
StartLimitIntervalSec = 30
StartLimitBurst = 3

[Служба]
Тип = простой
Пользователь = шаг
Группа = шаг
Environment= ПОШАГОВЫЙ ПУТЬ =/etc/step-ca
WorkingDirectory=/etc/step-ca
ExecStart=/usr/bin/step-ca config/ca.json --секреты файла паролей/intermediate.pass
ExecReload=/bin/kill --сигнал HUP $MAINPID
Перезапуск = при сбое
RestartSec = 5
Время ожидания stopsec = 30
StartLimitInterval = 30
StartLimitBurst = 3

; Возможности процесса и привилегии
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureBits = keep-caps
Отсутствие новых привилегий = да

; Изолированная среда
; Эта песочница работает с YubiKey PIV (через pcscd HTTP API), но, скорее всего, это 
; слишком ограничительно для HSM PKCS # 11.
;
; ПРИМЕЧАНИЕ: Прокомментируйте остальную часть этого раздела для устранения неполадок.
ProtectSystem = полный.
ProtectHome = true
RestrictNamespaces = true
Restrict addressfamilies= AF_UNIX AF_INET AF_INET6
PrivateTmp = true
ProtectClock = true
ProtectControlGroups = true
ProtectKernelTunables = true
ProtectKernelLogs = true
ProtectKernelModules = true
LockPersonality = true
RestrictSUIDSGID = true
RemoveIPC = true
RestrictRealtime = true
PrivateDevices = true
SystemCallFilter=@system-service
SystemCallArchitectures = native
MemoryDenyWriteExecute = true
ReadWriteDirectories=/etc/step-ca/db

[Установить]
WantedBy= многопользовательский.target
После перезагрузки конфигурации systemd (systemctl daemon-reload) службу можно включить и просмотреть (systemctl enable --now step-ca.service)

Работа с поставщиками
Администраторы и суперадминистраторы
Учетная запись администратора - это учетные записи, которые могут управлять поставщиками, где в качестве учетных записей суперадминистратора могут управлять поставщиками и управлять учетными записями администратора.

Поставщик JWK по умолчанию
Конфигурацию удаленного поставщика услуг можно запросить после запуска службы, выполнив:

[maus @vasquez: ~] $ список администраторов центра сертификации step
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): шаг
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа provisioner:
ТИП СУБЪЕКТА PROVISIONER 
step Admin JWK (JWK) SUPER_ADMIN
Добавление дополнительных учетных записей суперадминистратора
В реальной среде с несколькими администраторами. Это включает в себя управление учетными записями для процессов SSL-сертификатов (подписание, отзыв, продление, ...).

Чтобы добавить учетную запись с правами администратора, необходимо указать опцию командной строки --super, например:

[maus@vasquez: ~]$ добавить администратора step ca -- super superadmin "Admin JWK"
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): шаг
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа провайдера:
ТИП СУБЪЕКТА-ПРОВАЙДЕРА 
администратор superadmin JWK (JWK) SUPER_ADMIN
Удаление суперадминистратора по умолчанию
После создания первой новой учетной записи суперадминистратора учетная запись по умолчанию step должна быть удалена. Это будет сделано с помощью step ca admin remove команды:

[maus @vasquez: ~] $ step администратор центра сертификации удалить шаг
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): superadmin
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа провайдера:
✔ Администратор: тема: step, провайдер: Администратор JWK (JWK), тип: SUPER_ADMIN
Добавление (не суперадминистратора) JWT provisioner
Для обычных задач поставщик JWT (без прав суперадминистратора) может быть добавлен поставщиком с правами суперадминистратора

maus@vasquez:~$ step ca provisioner add new_admin --введите JWK --create
Пожалуйста, введите пароль для шифрования закрытого ключа provisioner? [оставьте пустым, и мы создадим его]:
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): superadmin
Используйте клавиши со стрелками для навигации: ↓ ↑ → ←
Какой ключ провайдера вы хотите использовать?
 ▸ Администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
 acme (ACME)
 maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа поставщика:
Удаление поставщика
При использовании провайдера с правами суперадминистратора существующие провайдеры могут быть удалены с помощью команды `step ca admin

maus@vasquez: ~$ step ca provisioner удаляет new_admin
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): superadmin
Используйте клавиши со стрелками для навигации: ↓ ↑ → ←
Какой ключ провайдера вы хотите использовать?
 ▸ Администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
 acme (ACME)
 maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
 new_admin (JWK) [kid: mLpg9HogT6u3TZUmgxlHjPS7iStJB5lC-k186mKg6k0]
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа поставщика:
Список существующих провайдеров
Список существующих провайдеров можно получить, выполнив step ca provisioner list команду, которая выведет информацию о существующих провайдерах в формате JSON.

Это можно отфильтровать с помощью jq, например, для получения списка имен существующих провайдеров:

maus@vasquez: ~$ список поставщиков step ca | jq -r '.[].name'
Администратор JWK 
acme 
maus 
new_admin
Добавление provisioner для ACME
По возможности, срок действия SSL-сертификатов для служб должен быть кратковременным, и они должны автоматически обновляться с использованием протокола ACME. Чтобы разрешить продление сертификата с использованием ACME, также необходимо добавить поставщика для ACME.

Это можно легко сделать, выполнив:

[maus@vasquez: ~]$ step ca provisioner добавить acme --введите ACME
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): superadmin
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа поставщика:
Шаги в среде с несколькими администраторами
В более крупной реальной среде администрирование будет осуществляться несколькими лицами. Присоединятся новые администраторы, другие администраторы уйдут или перейдут к другим клиентам.

Важно
Привилегии Super admmin
Для всех команд, включая изменение пароля провайдера, требуются права суперадминистратора.
Добавление нового пользователя
На данный момент единственный способ управлять отдельными учетными записями, каждая из которых имеет свои пароли, - это создание провайдера для каждой учетной записи.

Тип JWK-токена по умолчанию для обеспечения нас устраивает, поэтому мы придерживаемся его.

Создание нового поставщика услуг может быть выполнено командой step ca provisionier add:

[maus@vasquez: ~]$ step ca provisioner добавить maus -введите JWK -создать
Пожалуйста, введите пароль для шифрования закрытого ключа provisioner? [оставьте пустым, и мы создадим его]:
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): superadmin
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа поставщика:
Каждый новый администратор должен выполнить загрузку локальной среды, выполнив step ca bootstrap, например:

[maus@vasquez:~]$ step ca bootstrap--ca-url=https://pki.internal.ypbind.de:8443 --fingerprint=b7413e0c6a0572862fcc81feddefef3bdfe76fe03c56058571c4b7d859a2924f
Корневой сертификат был сохранен в /home/maus/.step/certs/root_ca.crt.
Конфигурация полномочий была сохранена в /home/maus/.step/config/defaults.json.
Удаление старого пользователя
Если администратор уходит, его провайдера также следует удалить. Аналогично созданию нового провайдера, существующего провайдера можно удалить, выполнив step ca provisioner remove <name>

Измените пароль провайдера (JWT)
Чтобы изменить пароль JWT provisionert, его зашифрованный закрытый ключ должен быть расшифрован с использованием старой ключевой фразы и повторно зашифрован новой ключевой фразой. Сначала необходимо получить текущий зашифрованный ключ JWT:

maus@vasquez:~$ OLD_KEY=$(список поставщиков step ca | jq -r '.[] | select(.name == "provisionername").EncryptedKey')
Чтобы сгенерировать новый зашифрованный ключ, старый ключ должен быть расшифрован и повторно зашифрован:

maus@vasquez:~$ NEW_KEY=$(echo $OLD_KEY | step crypto jwe decrypt | step crypto jwe encrypt -alg PBES2-HS256 + A128KW | формат step crypto jose)
Пожалуйста, введите пароль для расшифровки ключа шифрования содержимого:
Пожалуйста, введите пароль для шифрования ключа шифрования содержимого:
Наконец, данные провайдеров могут быть обновлены до вновь сгенерированного ключа:

maus@vasquez: ~$ обновление провайдера step ca forgetful_admin --private-key=<(echo -n "${NEW_KEY}")
Учетные данные администратора не найдены. Вы должны войти в систему, чтобы выполнять команды администратора.
✔ Пожалуйста, введите имя администратора / тему (например, name@example.com): superadmin
Используйте клавиши со стрелками для навигации: ↓ ↑ → ←
Какой ключ провайдера вы хотите использовать?
 ▸ Администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
 acme (ACME)
 maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
 forgetful_admin (JWK) [kid: Yx5mwRnWOzzTe8HXUE3-qY1jTs0WqRST3zYO0iufFYY]
✔ Поставщик: администратор JWK (JWK) [пользователь: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
Пожалуйста, введите пароль для расшифровки ключа поставщика:
Предупреждение
Хотя в тексте справки этот параметр step crypto jwe encrypt указан -alg как необязательный, если старый токен JWT содержит это alg поле, -alg поле всегда должно быть указано при вводе ключа.
Сброс пароля поставщика
Важно
Сброс пароля провайдера
Сбросить пароль провайдера невозможно! Провайдер должен быть удален и создан заново.
Общие задачи
Создание запроса на подписание сертификата вручную
Использование openssl
Хотя по-прежнему возможно создать CSR с помощью openssl req …​ команды, делать это не рекомендуется. Это связано с тем, что альтернативные имена объектов должны быть включены в CSR, это довольно громоздкий архив, поскольку для создания каждого CSR требуется создание файла конфигурации openssl..

Использование step client
step Команда из step-cli pacakge может использоваться для создания CSR и задания альтернативного имени субъекта, как указано в командной строке

Например, создать CSR с тремя разными альтернативными именами субъектов DNS и зашифрованным ключом RSA длиной 4096 бит с темой '/ C = DE/ O= internal.ypbind.de/OU= Служба каталогов / CN= sulaco.internal.ypbind.de':

maus@vasquez:~$ step создание сертификата --csr --san=sulaco.internal.ypbind.de --san= sulaco.небезопасно --san=sulaco.ypbind.de --kty=RSA --size=4096 '/C= DE/O=internal.ypbind.de/OU= Служба каталогов/CN= sulaco.internal.ypbind.de' sulaco.csr sulaco.key
Пожалуйста, введите пароль для шифрования закрытого ключа:
Ваш запрос на подписание сертификата сохранен в sulaco.csr.
Ваш закрытый ключ был сохранен в sulaco.key.
Сгенерированный CSR - файл может быть проверен командой openssl req:

maus@vasquez: ~$ запрос openssl в sulaco.csr -без текста
Запрос сертификата:
 Данные:
 Версия: 1 (0x0)
 Тема: CN = /C = DE/ O=internal.ypbind.de/ OU= Служба каталогов / CN= sulaco.internal.ypbind.de
 Тема: Информация об открытом ключе:
 Алгоритм с открытым ключом: RSAencryption
 Открытый ключ RSA: (4096 бит)
 Модуль:
 00:b4:14:44:5a: fe: f0:3c: 54:67: e1: e4: c5: e6:65:
...
 b3:b9:01
 Показатель: 65537 (0x10001)
 Атрибуты:
 Запрашиваемые расширения:
 Альтернативное имя субъекта X509v3:
 DNS:sulaco.internal.ypbind.de, DNS: sulaco.небезопасно, DNS:sulaco.ypbind.de
 Алгоритм подписи: sha256WithRSAEncryption
 78:50:7c: a5:2f: 40:a5:5f: 0b: 2b: 41:81:97:9b: c2:85: b0:13:
...
 01:c0:72:98:83:3c: a3: c9
Совет
Чтобы создать незашифрованный закрытый ключ, используйте параметры --no-password --insecure
Подписание сертификата
Подписание с использованием имени и пароля поставщика
Запросы на подписание сертификата могут подписываться центром сертификации с аутентификацией с использованием определенного поставщика и его пароля, например:

maus@vasquez:~$ step ca sign --not-after=26400h --provisioner=maus sulaco.csr sulaco.pem
✔ Разработчик: maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Пожалуйста, введите пароль для расшифровки ключа поставщика услуг:
✔ Центр сертификации: https://pki.internal.ypbind.de:8443
✔ Сертификат: sulaco.pem
Подписание с помощью токена JWT
Подписание CSR путем указания имени и пароля поставщика не рекомендуется для автоматического использования, например, внутри контейнера. Более безопасным способом, поскольку он никогда не раскрывает пароль поставщика, является использование предварительно сгенерированного токена JWT.

Токен действителен только в течение короткого времени.

Например:

maus@vasquez:~$ TOKEN=$(токен step ca --provisioner=maus --san=ripley.internal.ypbind.de --san= ripley.badphish.ypbind.de '/C= DE/O=internal.ypbind.de/OU= Служба каталогов /CN= ripley.internal.ypbind.de')
✔ Разработчик: maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Пожалуйста, введите пароль для расшифровки ключа поставщика: 
maus@vasquez: ~$ echo $ {ТОКЕН}
eyJhbGciOiJFUzI1NiIsImtpZCI6IjFWLU...
После получения токена его можно передать команде подписи, используя --token параметр командной строки:

maus@vasquez:~$ step ca sign --not-after=26400h --token=${ТОКЕН} ripley.csr ripley.pem
✔ CA: https://pki.internal.ypbind.de:8443
✔ Сертификат: ripley.pem
Внимание
Команда для создания токена ДОЛЖНА содержать ВСЕ альтернативные имена субъектов и точно соответствует заданным командой генерации CSR, если альтернативные имена субъектов отсутствуют, неполны или неправильны, центр сертификации отклонит процесс подписания, например:
maus@vasquez:~$ step ca sign --not-after=26400h --token=${TOKEN_WITH_SAN_INCOMPLEE} ripley.csr ripley.pem
✔ Центр сертификации: https://pki.internal.ypbind.de:8443
Запрос был запрещен центром сертификации: запрос сертификата не содержит допустимых DNS-имен - получено [ripley.internal.ypbind.de ripley.badphish.ypbind.de], требуется [/C= DE/O=internal.ypbind.de/OU= Служба каталогов /CN=ripley.internal.ypbind.de].
Повторно запустите с помощью STEPDEBUG = 1 для получения дополнительной информации.
Продление сертификата
Обновление вручную
Для продления сертификата требуются частная и общедоступная части сертификата. Для замены текущего файла открытого ключа сертификата - вместо создания нового файла (требуется --out опция) - для --force команды можно использовать step ca renew опцию.

root@vasquez:~# step ca обновить --принудительно /etc/dovecot/ssl/imap_imap.internal.ypbind.de.pem /etc/dovecot/ssl/imap_imap.internal.ypbind.de.key
Ваш сертификат сохранен в /etc/dovecot/ssl/imap_imap.internal.ypbind.de.pem.
Для зашифрованных закрытых ключей пароль необходимо сохранить в файле (обязательно ограничьте доступ!) и передать его с помощью опции --password-file.

Закрытый ключ сертификата используется для аутентификации в службе Step-CA для продления.

Важно
Невозможно обновить сертификат с истекшим сроком действия:
maus@vasquez:~$ step ca renew --force /etc/postfix/ssl/new_smtp_ypbind.de.pem /etc/postfix/ssl/new_smtp_ypbind.de.key 
ошибка при обновлении сертификата: в запросе не хватало необходимой авторизации для завершения: срок действия сертификата истек 2022-09-20 12:30:07 +0000 UTC
Чтобы указать срок действия нового сертификата, добавьте --expires-in опцию, в противном случае будет использоваться настройка по умолчанию для .authority.claims.defaultTLSCertDuration из config/ca.json файла.

Автоматическое продление
Клиент Step-CA может запускаться как демон для обновления сертификатов с использованием открытого и закрытого ключей, если прошло две трети срока действия сертификата. Этого можно добиться, передав опцию --daemon. Если сертификат был обновлен, можно передать либо файл signal и PID (--signal / --pid-file) для отправки PID определенного сигнала, либо команду, заданную --exec опцией, можно определить для запуска команды.

Отзыв сертификата
Сертификаты для скомпрометированных служб или сервисов / систем, которые больше не используются, могут и должны быть отозваны до истечения срока их действия.

Существует два типа отзыва.

Активная отмена означает, что клиент будет проверять наличие отозванных сертификатов, извлекая CRL-файл или запрашивая OCSP-ответчик.

Пассивное аннулирование означает, что клиент не будет проверять наличие отозванных сертификатов. Сертификаты помечаются как отозванные только центром сертификации.

Примечание
На данный момент Step CA поддерживает только пассивный отзыв.
Сертификаты могут быть отозваны:
его серийный номер (например, полученный при запуске openssl x509 -in <cert> -noout -text -serial) - step ca revoke serial_mumber

это пара открытого / закрытого ключей - step ca revoke --cert=/path/to/pulic.pem --key=/path/to/private.key

Совет
Хотя причина отзыва (--reason="Lore ipsum…​") необязательна, ее всегда следует использовать для обеспечения прозрачности отзыва сертификата
Важно
Если закрытый ключ зашифрован, необходимо ввести его кодовую фразу для расшифровки ключа.
Важно
Сертификаты не могут быть отозваны по их серийному номеру, если вы используете поставщика OIDC.
Отзыв сертификата с помощью поставщика
По умолчанию сертификаты отзываются с использованием поставщика для аутентификации:

maus@vasquez: ~$ openssl x509 -в ssl /ripley.pem -nout -serial 
serial=7CCDFDB5E70F0993029A6110603B05F4 
maus@vasquez:~$ maus@vasquez: ~$ step ca revoke --reason="Служба удалена и больше не используется" 0x7CCDFDB5E70F0993029A6110603B05F4
Используйте клавиши со стрелками для навигации: ↓ ↑ → ←
Какой ключ провайдера вы хотите использовать?
 Администратор JWK (JWK) [kid: mj4o6pbvivgPKyK2GGFVRTmoH3fJb6nTOBoTAoshvfU]
 acme (ACME)
 ▸ maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Пожалуйста, введите пароль для расшифровки ключа провайдера:
✔ Центр сертификации: https://pki.internal.ypbind.de:8443
Отзыв сертификата с использованием токена JWT
Для автоматизации отзыв следует производить путем генерации токена отзыва JWT и отзыва сертификата путем аутентификации с использованием токена JWT.

Токен отзыва может быть получен с помощью --revoke опции step ca token команды.

maus@vasquez:~$ TOKEN=$(step ca token --issuer=maus --revoke 0x0B5A836AF402C27EBD7B4653EC422804)
✔ Разработчик: maus (JWK) [kid: 1V-DdUBRAM4-cJnHU47P-tKGDR7wTgvAodzruKrj1Pk]
Пожалуйста, введите пароль для расшифровки ключа поставщика: 
maus@vasquez:~$ step ca отзывает --причина="Служба HTTP перенесена на новый сервер" --токен=${TOKEN} 0x0B5A836AF402C27EBD7B4653EC422804
✔ Центр сертификации: https://pki.internal.ypbind.de:8443
Сертификат с серийным номером 0x0B5A836AF402C27EBD7B4653EC422804 отозван.
Примечание
Токен отзыва может использоваться только для отзыва сертификата.
Использование ACME для автоматического развертывания сертификатов
Автоматическая установка и продление сертификата могут быть выполнены с помощью протокола ACME. Использование ACME для выдачи сертификатов, установка и продление с помощью Step CA просты.

Добавьте и настройте acme провайдера и укажите инструменту ACME URL по адресу https://<step_ca_url>/acme/<name_of_the_acme_provisioner>/directory.

Например, для https://github.com/acmesh-official/acme.sh (acme.sh) инструмента в этой настройке используйте acme.sh --server https://pki.internal.ypbind.de:8443/acme/acme/directory …​

Например, веб-сервис - rss.ypbind.de - со следующей конфигурацией для http-01 ACME challenge

Псевдоним /.well-known/acme-challenge "/var/www/rss.ypbind.de/letsencrypt/.well-known/acme-challenge"
<Каталог "/var/www/rss.ypbind.de/letsencrypt/.well-known">
 Разрешить переопределение нет
 Требовать, чтобы все было предоставлено
</Directory>
можно установить, выполнив:

root@vasquez: ~# acme.sh --проблема --домен rss.ypbind.de --сервер https://pki.internal.ypbind.de:8443/acme/acme/directory --ca-bundle /etc/step-ca/certs/root_ca.crt --файл полной цепочки /etc/apache2/ssl/rss.ypbind.de.pem --файл ключа /etc/apache2/ssl/rss.ypbind.de.key --reloadcmd "принудительная перезагрузка сервиса apache2" --webroot /var/www/rss.ypbind.de/letsencrypt/
[Пн. 12 дек. 2022 г. 05:48:29 CET] Использование центра сертификации: https://pki.internal.ypbind.de:8443/acme/acme/directory
[Пн. 12 дек. 2022 г. 05:48:29 CET] Единый домен = 'rss.ypbind.de '
[Пн. 12 дек. 2022 г. 05:48:29 CET] Получение токена авторизации домена для каждого домена
[Пн. 12 дек. 2022 г. 05:48:29 CET] Получение webroot для домена = 'rss.ypbind.de'
[Пн. 12 дек. 2022 г. 05:48:29 CET] Проверка: rss.ypbind.de
[Пн. 12 дек. 2022 г. 05:48:30 CET] Успех
[Пн. 12 дек. 2022 г., 05:48:30 CET] Подтвердите завершение, начинайте подписывать.
[Пн. 12 дек. 2022 г., 05:48:30 CET] Давайте завершим оформление заказа.
[Пн. 12 дек. 2022 г. 05:48:30 CET] Le_OrderFinalize='https://pki.internal.ypbind.de:8443/acme/acme/order/498GyYsv9EnNHqnGnasARdx12WyG32d7/finalize'
[Пн. 12 дек. 2022 г. 05:48:30 CET] Загрузка сертификата.
[Пн, 12 дек. 2022 г., 05:48:30 CET] Le_LinkCert='https://pki.internal.ypbind.de:8443/acme/acme/certificate/2cW0M6iT6HqS9eupGVAltFR1SAo0QZMu'
[Пн, 12 дек. 2022 г., 05:48:30 CET] Сертификат прошел успешно.
-----НАЧАТЬ ВЫДАЧУ СЕРТИФИКАТА-----
MIIDDDCCArGgAwIBAgIQPb74n+U + mNE3tDwKv2iRTjAKBggqhkjOPQQDAjB+MTUw
MwYDVQQKEyxDZXJ0aWZpY2F0ZSBhdXRob3JpdHkgZm9yIGludGVybmFsLnlwYmlu
ZC5kZTFFMEMGA1UEAxM8Q2VydGlmaWNhdGUgYXV0aG9yaXR5IGZvciBpbnRlcm5h
bC55cGJpbmQuZGUgSW50ZXJtZWRpYXRlIENBMB4XDTIyMTIxMjE2NDcyOVoXDTIz
MDExMTE2NDgyOVowGDEWMBQGA1UEAxMNcnNzLnlwYmluZC5kZTCCASIwDQYJKoZI 
hvcNAQEBBQADggEPADCCAQoCggEBALl7uZ5IZojjqBRMauGG/dYgo/q3a5XqxBwe
qlfaiVNSHYXhsM0K4KOwQIJrcQTdii5XmL/YHpV8UCeN7YIMGvYzrzII9lsiCEkd
y/NHvlN4rZ2Q4zgcFshW8rK436x2LS2yNlF8orIiU1FIYYmzWg+AK1nfnoPoOR6Z 
mw + 1GUBqFMD+ kJdxyHlM3KpGSPSfCfm3Sl0SSW5hv7KPxGS1cAwq6xM+ CY8T7VR7
AHLcuXaWAre7lglNhpvmLrKhdnHTQJfmIQdPPeNceISMFif+y2HAreTyTNKjywWe
Ysr4KNVZUao2a2PWq/y5lTNMr5ymEjfQSwdhI4a3A6Q0iBmdSp0CAwEAAaOBqzCB
qDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MB0GA1UdDgQWBBQ9WzU+r0YkaPhntTzBz12U2GBw0DAfBgNVHSMEGDAWgBQ9wBiD
qsyN5DOnBYsfywAYVcEKvDAYBgNVHREEETAPgg1yc3MueXBiaW5kLmRlMB0GDCsG
AQQBgqRkxihAAQQNMAsCAQYEBGFjbWUEADAKBggqhkjOPQQDAgNJADBGAiEAyY5h
gUJa13wCHqONKUoXTSFHhEoxBdEirOM7adboBqYCIQDo3STBKU910lUQjMLHo8RR 
n/4AcTOQqbn1bsFSF6xgEg==
----КОНЕЧНЫЙ СЕРТИФИКАТ-----
[Пн, 12 Дек. 2022, 05:48:30 по центральноевропейскому времени] Ваш сертификат находится в /etc/acme.sh/rss.ypbind.de/rss.ypbind.de.cer
[Пн, 12 Дек. 2022, 05:48:30 по центральноевропейскому времени] Ваш ключ сертификата находится в /etc/acme.sh/rss.ypbind.de/rss.ypbind.de.key
[Пн, 12 Дек. 2022, 05:48:30 по центральноевропейскому времени] Сертификат промежуточного центра сертификации находится в /etc/acme.sh/rss.ypbind.de/ca.cer
[Пн, 12 Дек. 2022, 05:48:30 по центральноевропейскому времени] И сертификаты полной цепочки есть: /etc/acme.sh/rss.ypbind.de/fullchain.cer
[Пн, 12 Дек. 2022, 05:48:30 по центральноевропейскому времени] Установка ключа в: /etc/apache2/ ssl/ rss.ypbind.de.key
[Пн, 12 Дек. 2022, 05:48:30 по центральноевропейскому времени] Установка полной цепочки в: /etc/ apache2/ ssl/ rss.ypbind.de.pem
[Пн. 12 дек. 2022 г. в 05:48:30 по центральноевропейскому времени] Запустите reload cmd: service apache2 force-reload
[Пн. 12 дек. 2022 г. в 05:48:31 по центральноевропейскому времени] Перезагрузка прошла успешно
Примечание
Мы не используем --apache флаг для acme.sh, потому что это приводит к путанице /etc/apache2/apache2.conf при добавлении /home/.acme в качестве пути. В данном случае /home это путь автоматического монтирования для домов пользователей с серверов центрального хранилища.
cronjob /etc/cron.d/acme-sh пакета Debian / Ubuntu для acme.sh обновит сертификат, если это необходимо, и перезапустит службу, если --reloadcmd был предоставлен.
