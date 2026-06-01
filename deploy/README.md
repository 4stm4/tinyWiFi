# Развёртывание на netOS (Buildroot/busybox)

Файлы для встраиваемого образа, где сервисами управляет busybox-init.

## init.d/

Per-service скрипты управления для веб-панели. Без `S##` префикса — busybox не
запускает их на загрузке (AP поднимает `S10tinywifi`), но они дают панели
возможность перезапускать сервисы по отдельности после правки настроек.

Установка на устройство:

```sh
install -m755 deploy/init.d/hostapd  /etc/init.d/hostapd
install -m755 deploy/init.d/nanodhcp /etc/init.d/nanodhcp
```

Сервис-слой TinyWifi предпочитает скрипт с точным именем (`hostapd`)
префиксному boot-стабу (`S10nanodhcp`), поэтому Restart и применение правок
Wi-Fi/DHCP из панели работают.

## web.toml

Пример конфига для `tinywifi-web` на устройстве: укажите реальные пути к
`hostapd.conf`/`nanodhcp.conf`/лизам и адрес прослушивания. Запуск:

```sh
TINYWIFI_CONFIG=/etc/tinywifi/web.toml /usr/sbin/tinywifi-web
```
