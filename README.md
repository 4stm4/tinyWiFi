# TinyWifi

Управление точкой доступа Wi-Fi на Raspberry Pi / встраиваемом Linux:
веб-панель и фоновый дисплей-демон поверх `hostapd` и `nanodhcp`.

Главное правило проекта: **всегда проверять доступность сервиса/файла/
интерфейса перед чтением, перезапуском или рендером** — никаких паник на
отсутствующих конфигах или сервисах, всё деградирует мягко.

## Структура

Cargo-воркспейс из трёх крейтов:

| Крейт | Назначение |
|---|---|
| `tinywifi-core` | Общая логика: проверки файлов/сервисов/интерфейсов, парсеры конфигов (hostapd, nanodhcp), лизы, метрики, модель статуса, безопасные правки с откатом. |
| `tinywifi-web` | HTTP-панель на axum: дашборд, страницы Wi-Fi/DHCP/Leases/System и REST API. |
| `tinywifi-display` | Демон, рисующий статус устройства (консоль сейчас, драйвер экрана позже через трейт `Renderer`). |

## Сборка

```bash
cargo build --release
```

Бинари: `target/release/tinywifi-web`, `target/release/tinywifi-display`.

На встраиваемом устройстве (Buildroot/glibc, aarch64) бинарь, собранный на
системе с более старым glibc, запускается forward-совместимо.

## Конфигурация

`tinywifi-web` и `tinywifi-display` читают TOML-конфиг приложения. Путь:
`$TINYWIFI_CONFIG`, иначе `/etc/tinywifi/tinywifi.toml`, иначе локальный
`configs/tinywifi.toml`.

```toml
[web]
listen = "0.0.0.0:80"

[display]
refresh_secs = 5

[paths]
hostapd_conf  = "/etc/hostapd/hostapd.conf"
nanodhcp_conf = "/etc/nanodhcp/nanodhcp.conf"
leases_file   = "/var/lib/nanodhcp/leases"

[services]
hostapd  = "hostapd"
nanodhcp = "nanodhcp"
web      = "tinywifi-web"
display  = "tinywifi-display"
```

Форматы целевых файлов:
- `hostapd.conf` — стандартный `key=value`, правки построчные (комментарии и
  неизвестные директивы переживают round-trip).
- `nanodhcp.conf` — `key=value` (`pool_start`/`pool_end`/`router`/`lease_file`
  и т.д.); неизвестные ключи сохраняются при записи.

## REST API

| Метод | Путь | Описание |
|---|---|---|
| GET | `/api/status` | Статус hostapd/nanodhcp/лизов/интерфейса |
| GET/POST | `/api/wifi` | Чтение/правка SSID, пароля, страны, канала |
| POST | `/api/wifi/confirm` | Подтвердить отложенную правку Wi-Fi |
| GET/POST | `/api/dhcp` | Чтение/правка пула, шлюза, DNS, времени аренды |
| POST | `/api/dhcp/confirm` | Подтвердить отложенную правку DHCP |
| GET | `/api/leases` | Активные DHCP-клиенты |
| GET | `/api/services` | Статусы сервисов |
| POST | `/api/services/:name/restart` | Перезапуск сервиса |
| POST | `/api/system/reboot` | Перезагрузка устройства |

### Безопасные правки (commit-confirm)

`POST /api/wifi?hold=<секунды>` (и аналогично `/api/dhcp`) применяет
изменение и ставит **автооткат**: если за `hold` секунд не пришёл
`POST /api/wifi/confirm`, конфиг восстанавливается из `.bak` и сервис
перезапускается на старых настройках. Это защищает от потери доступа, когда
смена SSID/пароля рвёт собственный линк администратора.

При обычном `POST` (без `hold`) изменение фиксируется сразу после успешного
подъёма сервиса; при сбое запуска — немедленный откат.

## Init-системы

Сервис-слой определяет менеджер один раз и работает поверх:
- **systemd** (`systemctl`);
- **SysV-init** (`/etc/init.d/Sxx`, Buildroot/busybox) — статус через скан
  `/proc`, lifecycle через init-скрипты;
- иначе статус по процессам, lifecycle недоступен.

## Тесты

```bash
cargo test --workspace
cargo clippy --all-targets
```
