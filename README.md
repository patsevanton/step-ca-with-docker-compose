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
