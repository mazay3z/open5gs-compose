# Disaster Recovery — open5gs-compose (ветка `fix-mongodb-openbao`)

## 1. Назначение и область применения

Настоящий документ описывает процедуры резервного копирования и восстановления (Disaster Recovery, DR) для стенда **open5gs-compose**: docker-compose стек мобильной сети Open5GS 2.7.7 (4G: MME/HSS/PCRF/SGWC/SGWU; 5G: NRF/AMF/SMF/UPF), WebUI, populate (open5gs-dbctl), мониторинг (Prometheus/Grafana/node_exporter/blackbox), eUPF, NAT-контейнер, RAN-симуляторы (srsRAN, UERANSIM), **Percona Server for MongoDB 5.0 с Data-at-Rest encryption** и **OpenBao 2.0.0 (KMS)**.

Документ покрывает:

- данные БД (логический `mongodump` + физический бэкап зашифрованных `.wt`);
- ключи OpenBao (**unseal-key, root-token, мастер-ключ KEK** — критично!);
- TLS-сертификаты OpenBao;
- конфигурацию стека (git-репозиторий, `.env`, статические IP, iptables/eBPF);
- **сетевую конфигурацию хоста** (netplan: IP-адреса интерфейсов, маршруты, стыки с КСПД и RAN, docker-сеть `core-network`);
- конфигурацию хоста (systemd-юнит `4g5gcorebox.service`, тюнинг `4g5gcorebox-init.sh`);
- порядок установки решения **с нуля на чистый хост Ubuntu 24.04** (раздел 6.2.1).

> **Все команды выполняются НА СЕРВЕРЕ** (стенд `192.168.0.9`, пользователь с правами docker/sudo) в каталоге проекта `~/open5gs-compose`, если не указано иное. Оболочка — `bash`.
> О работе со стенда из Windows/PowerShell — раздел 9.1.

> **Верхнеуровневая (универсальная, деплой-независимая) DR-процедура** — [DISASTER-RECOVERY-OVERVIEW.md](DISASTER-RECOVERY-OVERVIEW.md). Настоящий документ — её деплой-специфичная инстанциация для данного стенда.

Смежный документ: [PSMDB-ENCRYPTION.md](PSMDB-ENCRYPTION.md) — архитектура шифрования, миграция, ротация ключей.

## 2. Целевые показатели (RTO/RPO)

| Сценарий | RPO (допустимая потеря данных) | RTO (время восстановления) |
|---|---|---|
| Штатная перезагрузка хоста | 0 (данные на диске) | ~2–5 мин (автостарт + auto-unseal) |
| Повреждение данных MongoDB | ≤ 24 ч (при ежедневном mongodump) | ~15–30 мин |
| Потеря состояния OpenBao | ≤ 24 ч (логический) / 0 (физический + бэкап OpenBao) | ~30 мин |
| Полная потеря хоста | ≤ 24 ч (логический) / 0 (полный комплект бэкапов) | ~60–90 мин |

## 3. Карта критичных данных

| # | Артефакт | Путь на стенде | В git? | Критичность | Примечание |
|---|----------|----------------|--------|-------------|------------|
| 1 | Данные PSMDB (зашифрованные `.wt`) | `.deploy/docker/local-data/mongodb/` | ❌ (`.gitignore`) | 🔴 Критично | Владелец `1001:1001` (UID mongod). Читаются только при том же мастер-ключе KEK |
| 2 | Состояние OpenBao (storage) | `.deploy/docker/local-data/openbao/data/` | ❌ | 🔴 Критично | Внутри — KV v2 секрет `secret/data/psmdb-encryption` (мастер-ключ KEK) |
| 3 | Ключи OpenBao: `unseal-key`, `root-token`, `vault-token` | `.deploy/docker/local-data/openbao/secrets/` | ❌ | 🔴 **Критично** | Потеря `unseal-key` ⇒ `openbao/data` не расшифровать никогда. `vault-token` пересоздаётся entrypoint при каждом старте — бэкап не обязателен |
| 4 | TLS-сертификаты OpenBao (`ca.crt`, `ca.key`, `server.crt`, `server.key`) | `.deploy/docker/openbao/tls/` | ❌ (`.gitignore`) | 🟡 Важно | Регенерируются `.deploy/scripts/generate-certs.sh`; данных не касаются |
| 5 | Конфигурация стека: compose-файлы, конфиги сервисов, скрипты | корень репозитория + `.deploy/` | ✅ | 🟡 Важно | Восстанавливается из git (remote или bundle) |
| 6 | `.env` (порты, MCC/MNC/TAC, статические IP, профили) | `.env` | ✅ (но на стенде может отличаться) | 🔴 Критично | Источник статических IP (MME `.254`, SGWU `.248`, UPF `.249`, SMF `.247`), UE-подсеть `10.167.71.0/24` |
| 7 | systemd-юнит + тюнинг хоста | `4g5gcorebox.service`, `4g5gcorebox-init.sh`, `affinity.sh` (в git); установка в `/etc/systemd/system/` | ✅ / ❌ (установка) | 🟡 Важно | Пути в юните захардкожены: `/home/test1/open5gs-compose` |
| 8 | История мониторинга | docker volume `open5gs-compose_prometheus_data` | ❌ | 🟢 Опционально | Grafana-дашборды и provisioning — в git |
| 9 | Образ eUPF (приватный реестр) | `ghcr.io/edgecomllc/eupf-dev:feat-combined-dataplane` | — | 🟡 Важно | Требует `docker login` (учётные данные edgecom) либо `docker save` |
| 10 | **Сетевая конфигурация хоста**: netplan (IP интерфейсов `192.168.0.9`, `10.0.0.60` и др.), статические маршруты к сетям КСПД/RAN (`11.131.0.0/16`, `10.0.0.0/24`), MTU, ufw | `/etc/netplan/*.yaml` (+ фактическое состояние `ip addr/route/rule`) | ❌ | 🔴 Критично | Порты compose привязаны к хостовым IP: `192.168.0.9:38412/sctp` (AMF N2), `10.0.0.60:2152/udp` (SGWU S1-U) — без этих IP стек не поднимется |

### 3.1 Стыки с внешними сетями (КСПД / RAN / АРМ)

| Стык | Протокол / порт | Привязка на хосте | Внешняя сторона | Где задаётся |
|---|---|---|---|---|
| S1-C (4G RAN → MME) | SCTP `36412` | `0.0.0.0` (все интерфейсы) | eNodeB (RAN) | compose (`mme.ports`) + `mme.yaml` |
| S1-U (4G RAN → SGWU) | UDP `2152` | **`10.0.0.60:2152`** (хостовый IP!) | eNodeB (RAN) | compose (`sgwu.ports`), advertise `10.0.0.60` в `sgwu.yaml` |
| N2 (5G RAN → AMF) | SCTP `38412` | **`192.168.0.9:38412`** (хостовый IP!) | gNodeB (RAN) | compose (`amf.ports`) |
| N3 (5G RAN/КСПД → eUPF) | UDP `2152` | `0.0.0.0:2152`, advertise `192.168.0.9` | gNodeB / КСПД | `docker-compose.override.yaml` (`UPF_N3_ADV_ADDRESS`) |
| GTP-пилоты eUPF | UDP `2152` | — (исходящие сессии) | `11.131.226.141`, `11.131.218.66`, `10.0.0.150` (КСПД/RAN) | `UPF_GTP_PEER` (`.env` + override) |
| N6 (UE → внешняя сеть) | IP (NAT) | MASQUERADE UE-подсети `10.167.71.0/24` в контейнере `nat` | сеть хоста (шлюз по умолчанию) | compose (`nat.command`) |
| Управление (SSH, WebUI, Grafana, Prometheus, API eUPF) | TCP `22/9999/3000/9091/8081/9115`, MongoDB `27018`, OpenBao `8200` | `0.0.0.0` | АРМ / сервер бэкапов | compose `.env` |

> Следствие: на хосте **обязательно** должны существовать IP `192.168.0.9` и `10.0.0.60` (иначе `docker compose up` упадёт с `Error starting userland proxy: cannot assign requested address`), а также маршруты до сетей GTP-пилотов (`11.131.0.0/16`, `10.0.0.0/24`). Всё это — netplan-конфигурация хоста (артефакт #10).

### 3.2 Хостовые интерфейсы и netplan (типовая конфигурация стенда)

Согласно инструкции по установке pLTE Box, `/etc/netplan/00-config.yaml` создаёт отдельные логические интерфейсы для каждого типа трафика (метод — VLAN, физические порты или смешанный — определяется транспортной архитектурой MBH):

| Интерфейс хоста | Назначение (стык) | IP / маршруты |
|---|---|---|
| `enp88s0` (+ VLAN 2, VLAN 33) | OAM — управление (SSH, WebUI, мониторинг) | VLAN 2: DHCP; VLAN 33: `192.168.2.17/24` (на стенде управление также доступно через `192.168.0.9`) |
| `enp87s0` | **S1 (4G RAN)** — GTP-U SGWU/eUPF | `10.0.0.60/24` (advertise в `sgwu.yaml`) |
| `enx00e04c514330` | NGAP (5G RAN) | — |
| `enp2s0f0np0` + VLAN `301` | **SGI/N6** — выход в интернет/корпоративную сеть | `192.168.10.100/24`, default via `192.168.10.1` (metric 150), DNS `8.8.8.8` |
| `enp2s0f1np1` + VLAN `2202` | **N3 (5G RAN/КСПД)** | `11.131.226.142/30` + точечные маршруты via `11.131.226.141`: `11.131.226.132/30`, `11.131.226.156/30`, `11.131.218.64/30` |
| `enp2s0f1np1` + VLAN `2209` | N3 — оборудование Huawei (КСПД) | `11.131.226.162/30`, маршрут `10.0.0.150/32` via `11.131.226.161` |

> Имена интерфейсов зависят от железа — сверять с `ip link show`. Выход UE в интернет (N6) идёт через SGI-интерфейс (`enp2s0f0.301`, шлюз `192.168.10.1`) — контейнер `nat` должен иметь до него доступ. Абонентская подсеть `10.167.71.0/24` задаётся в **двух** местах compose (`upf`: `ip rule add from ...`; `nat`: `iptables MASQUERADE` + `ip route`) и должна совпадать.

**Что НЕ требует бэкапа** (воспроизводится автоматически при старте стека):

- iptables-правила NAT (`nat`, `upf` — задаются в `command:` compose);
- маршрутная политика `n6if` для UE-подсети (upf);
- eBPF zeroentrypoint (аттачится `upf-init`);
- tun-интерфейс `ogstun` (создаётся upf);
- тюнинг CPU/сетевых карт (восстанавливается `4g5gcorebox-init.sh` через `ExecStartPost`);
- KV v2 engine и наличие мастер-ключа (idempotent `ensure_psmdb_key` в entrypoint OpenBao).

> ⚠️ Ручные изменения iptables/sysctl на хосте **вне** compose и init-скриптов бэкапом не покрываются — их не должно быть (все изменения вносить в compose/init-скрипты, которые в git). Единственное исключение — **netplan-конфигурация хоста** (IP/маршруты стыков): она живёт в `/etc/netplan/` вне репозитория и бэкапится отдельно (раздел 5.8).

## 4. Цепочка ключей и зависимости восстановления

```
unseal-key (secrets/)  ──расшифровывает──►  openbao/data  ──содержит──►  мастер-ключ KEK
                                                                              │
root-token (secrets/)  ──доступ к API──►   KV v2 secret/data/psmdb-encryption
                                                                              │
vault-token (пересоздаётся)  ──аутентификация mongod──►  OpenBao :8200 (TLS)
                                                                              │
KEK ──шифрует DEK──►  WiredTiger .wt  (.deploy/docker/local-data/mongodb/)
```

Следствия (важно понимать до начала восстановления):

1. **Физический бэкап MongoDB пригоден только вместе с парой `openbao/data` + `unseal-key`** (тот же KEK).
2. **Реинициализация OpenBao (удаление `openbao/data`) создаёт НОВЫЙ KEK** ⇒ старые зашифрованные `.wt` становятся нечитаемыми навсегда ⇒ спасает только логический `mongodump`.
3. `mongodump` всегда создаёт **расшифрованный** дамп — хранить только в зашифрованном виде.
4. TLS-сертификаты с данными не связаны — их потеря не влияет на расшифровку.

## 5. Регламент резервного копирования

### 5.1 Что, как и как часто

| Артефакт | Метод | Частота | Хранение |
|---|---|---|---|
| Данные БД (логический) | `mongodump` → tar → openssl AES-256 | **Ежедневно** | Внешний носитель / сервер бэкапов |
| Данные БД (физический) | `cp -a` при остановленном mongod | Еженедельно + перед любыми изменениями (ротация ключа, обновление стека) | Внешний носитель |
| OpenBao `data/` + `secrets/` | tar → openssl AES-256 | Еженедельно + **немедленно после первой инициализации** и после ротации ключа | Защищённый носитель (сейф/менеджер паролей), отдельно от дампов БД |
| TLS-сертификаты OpenBao | tar | При каждой (ре)генерации | Защищённый носитель |
| Репозиторий + `.env` | `git bundle --all` + копия `.env` | При каждом изменении конфигурации | Git remote + внешний носитель |
| Образ eUPF (опционально) | `docker save` | При обновлении образа | Внешний носитель (для offline-восстановления) |

> **Парольная фраза openssl** для зашифрованных бэкапов хранится ОТДЕЛЬНО от самих бэкапов (менеджер паролей / запечатанный конверт). Потеря фразы = потеря бэкапа.

Каталог `backups/` уже в `.gitignore` — бэкапы не попадут в git.

### 5.2 Логический бэкап БД (mongodump)

Дамп создаётся **расшифрованным**, поэтому: не пишем его в `/data/db`, выгружаем через `/tmp` контейнера и **сразу шифруем**:

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p backups

# 1. Дамп внутри контейнера (tmpfs/слой контейнера, не в /data/db!)
docker compose exec -T mongodb sh -c 'rm -rf /tmp/dump && mongodump --out=/tmp/dump'

# 2. Выгрузка на хост
docker compose cp mongodb:/tmp/dump "backups/dump-${STAMP}"
docker compose exec -T -u 0 mongodb rm -rf /tmp/dump

# 3. Шифрование и удаление plaintext-копии
tar czf - -C backups "dump-${STAMP}" \
  | openssl enc -aes-256-cbc -pbkdf2 -out "backups/mongodump-${STAMP}.tar.enc"
rm -rf "backups/dump-${STAMP}"
ls -lh "backups/mongodump-${STAMP}.tar.enc"
```

Проверка бэкапа (не расшифровывая на диск надолго):

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in "backups/mongodump-${STAMP}.tar.enc" \
  | tar tzf - | head    # должен показать dump/open5gs/...
```

### 5.3 Физический бэкап БД (зашифрованные .wt)

Файлы уже зашифрованы на диске (AES-256 WiredTiger), но для консистентности **mongod должен быть остановлен** (или `db.fsyncLock()` — вариант без остановки, но требует последующего `fsyncUnlock`):

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)

docker compose stop mongodb
sudo cp -a .deploy/docker/local-data/mongodb "backups/mongodb-physical-${STAMP}"
docker compose start mongodb
```

> Физический бэкап **пригоден только вместе с бэкапом OpenBao** (тот же KEK) — см. раздел 4. Дополнительно шифровать openssl не обязательно (данные уже зашифрованы), но рекомендуется для защиты метаданных.

### 5.4 Ключи и состояние OpenBao (КРИТИЧНО)

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)

# data/ (содержит KEK) + secrets/ (unseal-key, root-token) — неразделимая пара
sudo tar czf - -C .deploy/docker/local-data openbao \
  | openssl enc -aes-256-cbc -pbkdf2 -out "backups/openbao-${STAMP}.tar.enc"
sudo chown "$USER" "backups/openbao-${STAMP}.tar.enc"

# Контроль: внутри должны быть openbao/data/... и openbao/secrets/{unseal-key,root-token,vault-token}
openssl enc -d -aes-256-cbc -pbkdf2 -in "backups/openbao-${STAMP}.tar.enc" | tar tzf - | head
```

> ⚠️ **Потеря `unseal-key` и этого бэкапа одновременно = невосстановимая потеря всех зашифрованных данных.** Хранить минимум в двух местах, одно — физически отдельно (offsite).

### 5.5 TLS-сертификаты OpenBao

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)
tar czf "backups/openbao-tls-${STAMP}.tar.gz" -C .deploy/docker/openbao tls
```

Включает `ca.key` (нужен для подписи будущих сертификатов). Сертификаты можно и сгенерировать заново (раздел 6.6), но тогда подпись CA изменится — старый бэкап предпочтительнее для идентичности окружения.

### 5.6 Конфигурация и код

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)

git bundle create "backups/repo-${STAMP}.bundle" --all
cp .env "backups/env-${STAMP}"

# Опционально: образы для offline-восстановления
docker save ghcr.io/edgecomllc/eupf-dev:feat-combined-dataplane \
  -o "backups/eupf-image-${STAMP}.tar"
```

### 5.7 Конфигурация хоста

Само содержимое (`4g5gcorebox.service`, `4g5gcorebox-init.sh`, `affinity.sh`) — в git (раздел 5.6). Установка на хосте:

```bash
sudo cp 4g5gcorebox.service /etc/systemd/system/4g5gcorebox.service
sudo systemctl daemon-reload
sudo systemctl enable 4g5gcorebox.service
```

Проверить, что пути в юните соответствуют фактическим (`WorkingDirectory=/home/test1/open5gs-compose`, `AFFINITY_SCRIPT=/home/test1/open5gs-compose/affinity.sh`) — при другом пользователе/пути отредактировать и закоммитить.

### 5.8 Сетевая конфигурация хоста (netplan, стыки, docker-сеть)

Единственная сетевая настройка хоста, живущая **вне репозитория** — netplan (IP интерфейсов, маршруты). Снимок делается при каждом изменении и при ежемесячном контроле:

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p backups/host-net

# 1. Netplan (IP 192.168.0.9, 10.0.0.60, маршруты к КСПД/RAN, MTU)
sudo tar czf "backups/host-net/netplan-${STAMP}.tar.gz" /etc/netplan/

# 2. Фактическое состояние (контрольный снимок для сверки после восстановления)
ip -details addr show            > "backups/host-net/ip-addr-${STAMP}.txt"
ip route show table all          > "backups/host-net/ip-route-${STAMP}.txt"
ip rule show                     > "backups/host-net/ip-rule-${STAMP}.txt"
ip link show                     > "backups/host-net/ip-link-${STAMP}.txt"
sudo iptables-save               > "backups/host-net/iptables-${STAMP}.txt" 2>/dev/null || true
sudo ufw status verbose          > "backups/host-net/ufw-${STAMP}.txt" 2>/dev/null || true
sysctl net.ipv4.ip_forward net.ipv4.conf.all.forwarding \
                                 > "backups/host-net/sysctl-${STAMP}.txt"
for i in $(ls /sys/class/net | grep -v lo); do
  sudo ethtool -k "$i" > "backups/host-net/ethtool-offload-${i}-${STAMP}.txt" 2>/dev/null || true
done

# 3. Docker-сеть core-network (пересоздаётся compose автоматически — снимок для сверки)
docker network inspect open5gs-compose_core-network > "backups/host-net/docker-net-${STAMP}.json"
```

> Docker-сеть `core-network` (10.103.0.0/16) и статические IP контейнеров **бэкапа не требуют** — они полностью описаны в compose + `.env` и пересоздаются при `docker compose up -d`. Снимок в п.3 — только для контроля.

### 5.9 Сводный чеклист бэкапа (ежедневный)

```bash
cd ~/open5gs-compose && STAMP=$(date +%Y%m%d-%H%M%S) && mkdir -p backups

# БД (логический, шифрованный)
docker compose exec -T mongodb sh -c 'rm -rf /tmp/dump && mongodump --out=/tmp/dump'
docker compose cp mongodb:/tmp/dump "backups/dump-${STAMP}"
docker compose exec -T -u 0 mongodb rm -rf /tmp/dump
tar czf - -C backups "dump-${STAMP}" | openssl enc -aes-256-cbc -pbkdf2 -out "backups/mongodump-${STAMP}.tar.enc"
rm -rf "backups/dump-${STAMP}"

# OpenBao (шифрованный)
sudo tar czf - -C .deploy/docker/local-data openbao | openssl enc -aes-256-cbc -pbkdf2 -out "backups/openbao-${STAMP}.tar.enc"
sudo chown "$USER" "backups/openbao-${STAMP}.tar.enc"

# Конфигурация
git bundle create "backups/repo-${STAMP}.bundle" --all
cp .env "backups/env-${STAMP}"

# Сеть хоста (netplan — при изменениях; контрольный снимок — ежемесячно, раздел 5.8)
sudo tar czf "backups/host-net/netplan-${STAMP}.tar.gz" /etc/netplan/

# Выгрузить на внешний носитель: scp/rsync backups/*-<STAMP>.* <backup-server>:...
```

## 6. Сценарии восстановления

### 6.1 Матрица сценариев

| Сценарий | Что потеряно | Требуемые бэкапы | Результат / потери |
|---|---|---|---|
| **A** | Весь хост (диск, ОС) | repo bundle + `.env` + TLS + OpenBao + физический БД **или** логический БД | Полное восстановление; потери = RPO |
| **B** | `local-data/mongodb` (повреждение/удаление) | Логический mongodump (OpenBao цел) | Данные с точностью до последнего дампа |
| **C** | `local-data/openbao/data` | Бэкап OpenBao (data+secrets) + физический БД **или** логический | Без бэкапа OpenBao — только через реинициализацию + логический дамп |
| **D** | `openbao/secrets` (unseal-key/root-token) | Логический mongodump (физический БД и openbao/data больше непригодны) | Реинициализация OpenBao, новый KEK, restore из дампа |
| **E** | TLS-сертификаты | Не требуются (регенерация) | Без потерь, перезапуск openbao+mongodb |
| **F** | `.env` / конфигурация | Git remote или bundle | Без потерь данных |
| **G** | Штатная перезагрузка хоста | Ничего | Автовосстановление (systemd + auto-unseal) |
| **H** | Сетевая конфигурация хоста (netplan, IP/маршруты стыков, docker-сеть) | Бэкап netplan (5.8) + compose/`.env` (в git) | Без потерь данных; стыки КСПД/RAN восстанавливаются по 6.9 |

### 6.2 Сценарий A — полная потеря хоста

#### 6.2.1 Подготовка чистого хоста Ubuntu 24.04 (Noble)

**Базовые пакеты и Docker:**

```bash
# 1. Базовые пакеты (ethtool — для init-скрипта, bpftool — контроль XDP)
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl ethtool \
  linux-tools-common linux-tools-$(uname -r) 2>/dev/null || sudo apt-get install -y bpftool

# 2. Docker CE из официального репозитория (рекомендуется для 24.04/noble):
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu noble stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
# Альтернатива (без внешнего репозитория): sudo apt-get install -y docker.io docker-compose-v2

# 3. Пользователь для эксплуатации (без sudo для docker)
sudo usermod -aG docker "$USER" && newgrp docker
docker run --rm hello-world   # проверка
```

**Особенности Ubuntu 24.04, которые нужно предусмотреть:**

| Пункт | Действие | Причина |
|---|---|---|
| **ufw** | Проверить `sudo ufw status`; если `active` — разрешить стыки: `sudo ufw allow 36412/sctp`, `38412/sctp`, `2152/udp`, `2123/udp`, `8200/tcp`, `27018/tcp`, `9999/tcp`, `3000/tcp`, `9091/tcp`, `8081/tcp`, `9115/tcp` (или `sudo ufw disable`, если защита обеспечивается периметром) | По умолчанию в Ubuntu Server ufw неактивен, но после настройки его включение заблокирует SCTP/UDP стыки RAN |
| **eBPF/XDP** | Ядро 6.8 поддерживает XDP; после старта стека проверить: `sudo bpftool net show` (должен быть `xdp` на veth). eUPF требует `privileged` + `/sys/fs/bpf` — уже в compose | zeroentrypoint eUPF не заработает на драйвере без native XDP (проверить `ethtool -i <iface>` / версия драйвера) |
| **iptables → nftables** | Ничего не делать: Docker сам ставит правила через iptables-nft; внутри контейнеров (alpine) — свой legacy-iptables | В 24.04 `iptables` указывает на nft-бэкенд; конфликтов с compose-стеком нет |
| **netplan** | Настроить статические IP стыков (см. ниже) | Порты compose привязаны к `192.168.0.9` и `10.0.0.60` — без них стек не поднимется |
| **irqbalance** | Ничего не делать — init-скрипт останавливает его при старте сервиса | Конфликт affinity с irqbalance |
| **unattended-upgrades** | Отключить авто-перезагрузку: `sudo sed -i 's/Unattended-Upgrade::Automatic-Reboot "true"/"false"/' /etc/apt/apt.conf.d/50unattended-upgrades` (проверить) | Незапланированный ребут стенда |
| **NTP** | Включить синхронизацию: `timedatectl set-ntp true`; проверить `timedatectl` | SCTP/диаметр/GTP чувствительны к рассинхрону времени |
| **swap/виртуализация** | Не критично; eUPF требует `ulimits memlock: -1` — уже в compose | — |

**Восстановление сетевой конфигурации хоста (стыки с КСПД/RAN):**

```bash
# 1. Восстановить netplan из бэкапа (раздел 5.8) и применить
sudo tar xzf backups/host-net/netplan-<STAMP>.tar.gz -C /
sudo netplan apply
# ВНИМАНИЕ: применять только с консоли хоста (не по SSH) — риск потерять связь!

# 2. Проверить стыковые IP и маршруты (сверить с backups/host-net/ip-addr-*.txt):
ip addr show    # должны быть 192.168.0.9 (управление/N2/N3) и 10.0.0.60 (S1-U)
ip route show   # маршруты к 11.131.0.0/16 и 10.0.0.0/24 (GTP-пилоты КСПД/RAN)

# 3. Проверить доступность GTP-пилотов (если они должны отвечать):
ping -c 3 11.131.226.141; ping -c 3 11.131.218.66; ping -c 3 10.0.0.150
```

**Доступ к приватному реестру eUPF:**

```bash
docker login ghcr.io   # учётные данные edgecom
# или без реестра: docker load -i backups/eupf-image-<STAMP>.tar
```

**Восстановление проекта и данных:**

```bash
# 3. Репозиторий: из remote...
git clone -b fix-mongodb-openbao <repo-url> ~/open5gs-compose
# ...или из bundle:
git clone backups/repo-<STAMP>.bundle -b fix-mongodb-openbao ~/open5gs-compose
cd ~/open5gs-compose

# 4. .env
cp backups/env-<STAMP> .env

# 5. TLS-сертификаты
tar xzf backups/openbao-tls-<STAMP>.tar.gz -C .deploy/docker/openbao

# 6. OpenBao (data + secrets — неразделимая пара)
mkdir -p .deploy/docker/local-data
sudo tar xzf backups/openbao-<STAMP>.tar.gz -C .deploy/docker/local-data  # если бэкап не шифровали
# (для шифрованного: openssl enc -d -aes-256-cbc -pbkdf2 -in backups/openbao-<STAMP>.tar.enc | sudo tar xzf - -C .deploy/docker/local-data)

# 7. MongoDB — вариант 7a (физический бэкап, потери = 0 на момент снятия):
sudo cp -a backups/mongodb-physical-<STAMP> .deploy/docker/local-data/mongodb
docker run --rm --user 0:0 --entrypoint "" \
  -v "$PWD/.deploy/docker/local-data/mongodb:/data/db" \
  percona/percona-server-mongodb:5.0 chown -R 1001:1001 /data/db
```

**Вариант 7b (нет физического бэкапа — восстановление из логического дампа):**

```bash
# Чистый dbPath (enableEncryption действует только на пустом хранилище!)
mkdir -p .deploy/docker/local-data/mongodb
docker run --rm --user 0:0 --entrypoint "" \
  -v "$PWD/.deploy/docker/local-data/mongodb:/data/db" \
  percona/percona-server-mongodb:5.0 chown 1001:1001 /data/db

docker compose up -d openbao mongodb
# дождаться healthy (см. docker compose ps), затем:
openssl enc -d -aes-256-cbc -pbkdf2 -in backups/mongodump-<STAMP>.tar.enc | tar xzf - -C backups
docker compose cp backups/dump-<STAMP> mongodb:/tmp/dump
docker compose exec -T mongodb mongorestore /tmp/dump
docker compose exec -T -u 0 mongodb rm -rf /tmp/dump
docker compose exec -T mongodb mongo --quiet /opt/init/init.js   # admin-аккаунт WebUI
rm -rf backups/dump-<STAMP>   # удалить plaintext-дамп!
```

**Запуск стека и хост-конфигурация:**

```bash
# 8. Запуск (профили берутся из .env: 4g-core,5g-core,monitoring)
docker compose up -d

# 9. systemd-юнит (проверить пути внутри! — раздел 5.7)
sudo cp 4g5gcorebox.service /etc/systemd/system/4g5gcorebox.service
sudo systemctl daemon-reload
sudo systemctl enable 4g5gcorebox.service

# 10. Верификация — раздел 7
```

> Если OpenBao восстанавливается из бэкапа (шаг 6), entrypoint при старте сам: расшифрует storage по `unseal-key`, пересоздаст `vault-token` (chown 1001:1001), проверит наличие мастер-ключа (не регенерирует). Данные `.wt` расшифруются тем же KEK.

### 6.3 Сценарий B — повреждение/потеря данных MongoDB (OpenBao цел)

KEK не меняется, поэтому достаточно чистого dbPath + `mongorestore`:

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)

# 1. Остановить зависимые от БД сервисы и mongod
docker compose stop mongodb   # зависимые (webui/hss/pcrf/...) упадут в restart-loop — это нормально

# 2. Повреждённые данные — в сторону (не удалять сразу!)
sudo mv .deploy/docker/local-data/mongodb ".deploy/docker/local-data/mongodb-corrupt-${STAMP}"

# 3. Чистый dbPath с правильным владельцем (UID 1001 mongod)
mkdir -p .deploy/docker/local-data/mongodb
docker run --rm --user 0:0 --entrypoint "" \
  -v "$PWD/.deploy/docker/local-data/mongodb:/data/db" \
  percona/percona-server-mongodb:5.0 chown 1001:1001 /data/db

# 4. Запустить OpenBao+PSMDB, дождаться healthy
docker compose up -d openbao mongodb
watch docker compose ps openbao mongodb   # до healthy, затем Ctrl+C

# 5. Restore из логического дампа
openssl enc -d -aes-256-cbc -pbkdf2 -in backups/mongodump-<STAMP>.tar.enc | tar xzf - -C backups
docker compose cp backups/dump-<STAMP> mongodb:/tmp/dump
docker compose exec -T mongodb mongorestore /tmp/dump
docker compose exec -T -u 0 mongodb rm -rf /tmp/dump
docker compose exec -T mongodb mongo --quiet /opt/init/init.js
rm -rf backups/dump-<STAMP>

# 6. Поднять весь стек
docker compose up -d

# 7. После проверки (раздел 7) удалить повреждённые данные:
# sudo rm -rf .deploy/docker/local-data/mongodb-corrupt-${STAMP}
```

> Альтернатива при наличии физического бэкапа: вместо шагов 3–5 просто
> `sudo cp -a backups/mongodb-physical-<STAMP> .deploy/docker/local-data/mongodb` + chown (как в 6.2 шаг 7a) — быстрее и без потерь RPO дампа.

### 6.4 Сценарий C — потеря состояния OpenBao (`openbao/data`)

`openbao/data` содержит мастер-ключ KEK. Без него OpenBao при старте **реинициализируется и сгенерирует НОВЫЙ KEK** ⇒ существующие зашифрованные `.wt` станут нечитаемыми.

**Вариант C1 — есть бэкап OpenBao (data+secrets):**

```bash
cd ~/open5gs-compose
docker compose down

# Восстановить openbao целиком (data + secrets)
sudo rm -rf .deploy/docker/local-data/openbao
sudo tar xzf backups/openbao-<STAMP>.tar.gz -C .deploy/docker/local-data
# (шифрованный: openssl enc -d ... | sudo tar xzf - -C .deploy/docker/local-data)

docker compose up -d   # auto-unseal по unseal-key из secrets/, KEK сохранён
# Верификация — раздел 7. Если .wt не читаются (бэкап OpenBao старше физического
# бэкапа БД и KEK уже другой) — перейти на вариант C2.
```

**Вариант C2 — бэкапа OpenBao нет (или KEK не совпадает):**

Реинициализация OpenBao + восстановление БД из логического дампа. Физический бэкап БД и `openbao/data` больше **непригодны**:

```bash
cd ~/open5gs-compose
STAMP=$(date +%Y%m%d-%H%M%S)
docker compose down

# 1. Старый OpenBao — в сторону, БД (нечитаемая со старым KEK) — тоже
sudo mv .deploy/docker/local-data/openbao ".deploy/docker/local-data/openbao-dead-${STAMP}"
sudo mv .deploy/docker/local-data/mongodb ".deploy/docker/local-data/mongodb-dead-${STAMP}"

# 2. Чистые каталоги (OpenBao пересоздаст secrets при init, dbPath — с владельцем 1001)
mkdir -p .deploy/docker/local-data/openbao .deploy/docker/local-data/mongodb
docker run --rm --user 0:0 --entrypoint "" \
  -v "$PWD/.deploy/docker/local-data/mongodb:/data/db" \
  percona/percona-server-mongodb:5.0 chown 1001:1001 /data/db

# 3. Поднять OpenBao+PSMDB (OpenBao инициализируется: новый unseal-key, root-token, KEK)
docker compose up -d openbao mongodb
watch docker compose ps openbao mongodb   # до healthy

# 4. НЕМЕДЛЕННО сделать бэкап новых ключей (раздел 5.4) — пока не потеряли!

# 5. Restore из логического дампа (как в 6.3 шаг 5) и поднятие стека
docker compose up -d
```

### 6.5 Сценарий D — потеря ключей OpenBao (`openbao/secrets`)

**D1: потерян `root-token`, `unseal-key` цел.**
OpenBao продолжит работать и auto-unseal'иться, но управлять им (читать/ротировать секреты) нельзя. Варианты:

- выпустить новый root-token процедурой `bao operator generate-root` (key-threshold=1, выполняется в контейнере openbao через loopback CLI);
- либо проще — реинициализация по варианту C2 (данные БД восстановятся из логического дампа).

**D2: потерян `unseal-key`** (или весь `secrets/`).

`openbao/data` расшифровать невозможно — **никогда**. Единственный путь — вариант C2 (реинициализация + логический дамп). Если логического дампа нет — данные потеряны безвозвратно; впредь бэкапить `secrets/` немедленно после каждой инициализации (раздел 5.4).

> Именно поэтому регламент (5.1) требует хранить бэкап OpenBao отдельно и минимум в двух местах.

### 6.6 Сценарий E — потеря TLS-сертификатов OpenBao

Сертификаты не связаны с данными — просто регенерируем:

```bash
cd ~/open5gs-compose
bash .deploy/scripts/generate-certs.sh   # создаст .deploy/docker/openbao/tls/{ca,server}.{crt,key}
docker compose restart openbao mongodb   # mongod подхватит новый ca.crt
```

Проверка: раздел 7, пункт TLS (`Verify return code: 0`). Сохранить новые сертификаты (раздел 5.5).

### 6.7 Сценарий F — потеря `.env` / конфигурации репозитория

```bash
cd ~/open5gs-compose
git checkout fix-mongodb-openbao -- .env        # из git
# или из бэкапа:
cp backups/env-<STAMP> .env

# при полной потере каталога — как в 6.2 шаги 3–4 (clone + .env), данные не трогать
docker compose up -d --force-recreate   # пересоздать контейнеры с новыми переменными
```

После восстановления сверить ключевые значения: `MONGO_EXT_PORT=27018`, `WEBUI_EXT_PORT=9999`, `MME_IP=10.103.255.254`, `SGWU_IP=10.103.255.248`, `UPF_IP=10.103.255.249`, `SMF_IP=10.103.255.247`, `UPF_UE_SUBNET=10.167.71.0/24`, `COMPOSE_PROFILES=4g-core,5g-core,monitoring`.

### 6.8 Сценарий G — штатная перезагрузка хоста (справочно)

Ничего делать не нужно: `4g5gcorebox.service` поднимет стек (`docker compose up -d`), выполнит тюнинг хоста (`4g5gcorebox-init.sh`: CPU governor performance, стоп irqbalance, ethtool rings/offload, affinity), OpenBao auto-unseal'ится по `unseal-key`, PSMDB получит KEK и откроет зашифрованное хранилище.

Проверка после перезагрузки:

```bash
systemctl status 4g5gcorebox.service --no-pager
docker compose ps
bash .deploy/scripts/verify-encrypted-stack.sh
```

Если юнит не установлен/не включён — стек поднимется только вручную `docker compose up -d` (раздел 5.7).

### 6.9 Сценарий H — потеря сетевой конфигурации хоста (netplan, стыки, docker-сеть)

**Признаки:** `docker compose up` падает с `Error starting userland proxy: cannot assign requested address` (на хосте нет IP `192.168.0.9`/`10.0.0.60`); контейнеры с пробросом портов в restart-loop; нет SSH/WebUI по `192.168.0.9`; GTP-стыки с КСПД/RAN недоступны; пропали VLAN-интерфейсы (`*.301`, `*.2202`, `*.2209` — проверить `ip link show`).

Данные (БД, OpenBao, TLS) при этом **не страдают** — восстанавливается только связность.

**H1 — есть бэкап netplan (раздел 5.8):**

```bash
# 0. ВНИМАНИЕ: работать С КОНСОЛИ хоста (монитор/клавиатура или IPMI/iDRAC)!
#    netplan apply по SSH может оборвать сессию и доступ к хосту.
sudo tar xzf backups/host-net/netplan-<STAMP>.tar.gz -C /
sudo netplan try     # безопасно: автооткат через 120 сек, если не подтвердить
# (или sudo netplan apply — если доступ к консоли гарантирован)

# 1. Сверить фактическое состояние с контрольными снимками (5.8):
ip addr show    # 192.168.0.9 (управление), 10.0.0.60 (S1), 192.168.10.100 (SGI),
                # 11.131.226.142/30 и 11.131.226.162/30 (N3), 192.168.2.17 (OAM VLAN 33)
ip route show   # default via 192.168.10.1 (metric 150); точечные маршруты
                # 11.131.226.132/30, 11.131.226.156/30, 11.131.218.64/30 via 11.131.226.141;
                # 10.0.0.150/32 via 11.131.226.161
ip rule show    # правила для 10.167.71.0/24 (UE-подсеть), если были в снимке

# 2. Переподнять стек: контейнеры с портами, привязанными к IP хоста,
#    при отсутствии IP уходят в restart-loop — после появления IP перезапустить:
docker compose up -d --force-recreate
```

**H2 — бэкапа нет: ручное восстановление по таблице 3.2 и контрольным снимкам.**

Создать `/etc/netplan/00-config.yaml` (права `600`) по таблице раздела 3.2 и, если есть, снимкам `backups/host-net/ip-*.txt`. Типовой шаблон (имена интерфейсов/VLAN-теги **сверить с `ip link show` конкретного стенда**):

```yaml
network:
  version: 2
  ethernets:
    enp88s0: {}                    # OAM: управление (IP 192.168.0.9 — см. примечание)
    enp87s0:
      addresses: [10.0.0.60/24]    # S1 (4G RAN) — GTP-U SGWU/eUPF
    enp2s0f0np0: {}                # физический порт SGI
    enp2s0f1np1: {}                # физический порт N3
  vlans:
    vlan301:                       # SGI/N6 — выход UE в интернет
      id: 301
      link: enp2s0f0np0
      addresses: [192.168.10.100/24]
      routes:
        - to: default
          via: 192.168.10.1
          metric: 150
      nameservers:
        addresses: [8.8.8.8]
    vlan2202:                      # N3 (КСПД)
      id: 2202
      link: enp2s0f1np1
      addresses: [11.131.226.142/30]
      routes:
        - to: 11.131.226.132/30
          via: 11.131.226.141
        - to: 11.131.226.156/30
          via: 11.131.226.141
        - to: 11.131.218.64/30
          via: 11.131.226.141
    vlan2209:                      # N3 — оборудование Huawei (КСПД)
      id: 2209
      link: enp2s0f1np1
      addresses: [11.131.226.162/30]
      routes:
        - to: 10.0.0.150/32
          via: 11.131.226.161
```

> **Примечание:** IP управления, к которому привязаны порты compose (`192.168.0.9` на стенде), должен присутствовать на одном из интерфейсов (в лаборатории — обычно основной интерфейс с DHCP или статикой; на стенде также VLAN 33 `192.168.2.17/24`). Без `192.168.0.9` и `10.0.0.60` стек не поднимется. Применять только с консоли: `sudo netplan try`.

**Docker-сеть `core-network`** ручного восстановления не требует — она полностью описана в compose + `.env` и пересоздаётся при `docker compose up -d` (подсеть `10.103.0.0/16`, статические IP контейнеров). Если сеть повреждена вручную (удалена/изменена):

```bash
docker compose down
docker network rm open5gs-compose_core-network 2>/dev/null || true
docker compose up -d      # сеть и контейнеры пересоздадутся со статическими IP
```

**Проверка стыков после восстановления:**

```bash
# GTP-пилоты (КСПД/RAN):
ping -c 3 11.131.226.141; ping -c 3 11.131.218.66; ping -c 3 10.0.0.150
# SCTP-ассоциации S1/NGAP (MME/AMF ↔ eNB/gNB):
sudo ss -S | head -20
# N6/SGI (выход UE в интернет):
ip route show default      # via 192.168.10.1 dev <SGI-интерфейс>
# eBPF/XDP eUPF:
sudo bpftool net show
# ufw (если был активен — восстановить правила из backups/host-net/ufw-*.txt, см. 6.2.1):
sudo ufw status verbose
```

Затем — полная верификация по разделу 7 (включая п.6–8 чеклиста: core-network, NAT, eUPF).

## 7. Проверка после восстановления

### 7.1 Автоматическая верификация

```bash
cd ~/open5gs-compose
bash .deploy/scripts/verify-encrypted-stack.sh
```

Скрипт проверяет: статус контейнеров, список БД и коллекций (`subscribers`, `accounts`), строки шифрования в логе mongod, TLS до OpenBao (`Verify return code: 0`), наличие мастер-ключа в KV v2, отсутствие plaintext-IMSI в `/data/db`, HTTP-доступность WebUI.

### 7.2 Ручной чеклист

| # | Проверка | Команда | Ожидание |
|---|----------|---------|----------|
| 1 | Все сервисы healthy | `docker compose ps` | `openbao`, `mongodb`, `webui`, `mme`, `hss`, `pcrf`, `sgwc`, `sgwu`, `smf`, `upf`, `nat`, `nrf`, `amf` — Up/healthy |
| 2 | OpenBao unsealed | `docker compose exec -T openbao sh -c 'export BAO_ADDR=http://127.0.0.1:8201; bao status'` | `Sealed: false` |
| 3 | Данные БД | `docker compose exec -T mongodb mongo --quiet open5gs --eval 'print(db.subscribers.countDocuments({}))'` | Число абонентов как до аварии |
| 4 | WebUI | `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9999/` | `200` |
| 5 | TLS OpenBao | `echo \| openssl s_client -connect localhost:8200 -CAfile .deploy/docker/openbao/tls/ca.crt 2>/dev/null \| grep Verify` | `Verify return code: 0` |
| 6 | Сеть core-network | `docker network inspect open5gs-compose_core-network` | Подсеть `10.103.0.0/16`, статические IP на месте |
| 7 | NAT/маршрутизация | `docker compose exec -T nat ping -c 2 upf` и наоборот | 0% loss |
| 8 | eUPF | `curl -s http://localhost:8081/api/v1/health` | `OK`/`200` |
| 9 | Тюнинг хоста | `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` | `performance` |
| 10 | RAN (опционально) | `docker compose --profile 5g-ran up -d && docker compose logs ue \| tail` | Регистрация UE |

## 8. Хранение и защита резервных копий

- **Правило 3-2-1**: 3 копии, 2 разных носителя, 1 — вне стенда (offsite).
- Все бэкапы, кроме физического `.wt` (он уже зашифрован KEK), хранить **только в зашифрованном виде** (openssl AES-256-CBC + PBKDF2).
- Парольные фразы — в менеджере паролей / запечатанном конверте, **отдельно от носителей с бэкапами**.
- Бэкап OpenBao (`unseal-key` + KEK) и логические дампы БД хранить **в разных местах**: вместе они дают расшифровку всех данных.
- Ротация: хранить N ежедневных + M недельных копий; перед удалением старой копии убедиться, что новая проверена (`tar tzf`).
- После успешного восстановления и верификации — удалить plaintext-артефакты (распакованные `backups/dump-*`, `mongodb-*-dead-*`, `mongodb-corrupt-*`), как в «Очистке plaintext-артефактов» [PSMDB-ENCRYPTION.md](PSMDB-ENCRYPTION.md).

## 9. Известные особенности и подводные камни

### 9.1 Передача команд на стенд из Windows/PowerShell

**Известная проблема**: при работе через PowerShell символы (кавычки, `$`, `\`, переводы строк) в параметрах скриптов и inline-командах SSH искажаются. Правила:

1. **Не передавать** многострочные bash-блоки и команды с `$VAR` напрямую через `ssh ... "..."` из PowerShell.
2. Команды из этого документа **выполнять на сервере**: зайти `ssh -b 192.168.0.2 mazay@192.168.0.9`, открыть `bash` и вводить/вставлять команды в нём.
3. Для передачи файлов использовать `scp` (файлы не искажаются): `scp DISASTER-RECOVERY.md mazay@192.168.0.9:~/open5gs-compose/`.
4. Для запуска локального скрипта на сервере — из Git Bash/WSL: `ssh -b 192.168.0.2 mazay@192.168.0.9 'bash -s' < script.sh`.
5. Документ и скрипты репозитория попадают на стенд через git (pull) — предпочтительный способ.

### 9.2 Технические особенности

| Особенность | Следствие для DR |
|---|---|
| `enableEncryption` действует только на **пустом** dbPath | Перед restore всегда создавать чистый каталог (6.2/6.3/6.4), иначе mongod не стартует |
| Владелец данных `1001:1001` (UID mongod) | Docker создаёт каталоги `root:root` — всегда `chown` через helper-контейнер (команды в 6.2/6.3) |
| `vault-token` пересоздаётся entrypoint при каждом старте | Бэкапить не обязательно; достаточно `root-token` + `unseal-key` |
| Мастер-ключ никогда не регенерируется, если существует (`ensure_psmdb_key`) | Реинициализация OpenBao = новый KEK = старые `.wt` нечитаемы (раздел 4) |
| `mongodump` всегда plaintext | Немедленное шифрование и удаление исходного дампа (5.2) |
| Физический бэкап консистентен только при остановленном mongod | `docker compose stop mongodb` перед `cp -a` (5.3) |
| Образ eUPF — приватный реестр ghcr.io | Для восстановления нужен `docker login` или `docker save/load` (5.6) |
| Пути в `4g5gcorebox.service` захардкожены (`/home/test1/...`) | Проверить/поправить при восстановлении под другим пользователем (5.7) |
| `COMPOSE_PROFILES` задаётся в `.env` | Без корректного `.env` поднимутся не все сервисы (6.7) |
| Проект compose = имя каталога (`open5gs-compose`) | Имена контейнеров/сети/томов (`open5gs-compose_core-network`, `open5gs-compose_prometheus_data`) привязаны к имени каталога — при восстановлении в другой каталог сохранить то же имя |

## 10. План тестирования DR на стенде (192.168.0.9)

После согласования документа выполнить на стенде (в порядке возрастания риска):

| # | Тест | Сценарий | Критерий успеха |
|---|------|----------|-----------------|
| 1 | Бэкап | 5.8 (полный чеклист) | Все архивы созданы, `tar tzf` проходит, plaintext удалён |
| 2 | Штатная перезагрузка | 6.8: `sudo reboot` | Стек поднялся systemd-юнитом, verify-encrypted-stack.sh — без ошибок |
| 3 | TLS | 6.6: удалить `tls/`, регенерация | OpenBao+mongodb healthy, TLS verify OK |
| 4 | Restore БД | 6.3 (на тестовой копии каталога) | `subscribers` совпадает с дампом, WebUI 200 |
| 5 | Restore OpenBao | 6.4 C1 (на тестовой копии) | KEK сохранён, `.wt` читаются |
| 6 | Полный DR (репетиция) | 6.2 вариант 7b в отдельном каталоге/ВМ | Стек поднят с нуля из бэкапов, чеклист 7.2 пройден |
| 7 | Сеть хоста | 6.9 H1: `sudo netplan try` с текущим (восстановленным из бэкапа 5.8) конфигом | `netplan try` подтверждён (связь не потеряна), `ip addr`/`ip route` совпадают со снимком 5.8, `docker compose up -d --force-recreate` — все порты поднялись |

> Тесты 4–5 выполнять на **копиях** каталогов (не на живых данных), с предварительным полным бэкапом (тест 1). Тест 7 — только при доступе к консоли хоста (IPMI/iDRAC/монитор): `netplan try` сам откатит изменения за 120 сек, если не подтвердить.

---

## Приложение: экспресс-карточка

```
ЕЖЕДНЕВНЫЙ БЭКАП (на сервере, ~/open5gs-compose):
  mongodump -> /tmp -> docker compose cp -> tar | openssl enc -> backups/*.tar.enc
  openbao data+secrets -> tar | openssl enc -> backups/openbao-*.tar.enc
  git bundle --all + cp .env -> backups/

ПОТЕРЯЛ...
  ...данные БД    -> 6.3: чистый dbPath (chown 1001) + mongorestore
  ...openbao/data -> 6.4 C1 (есть бэкап) / C2 (нет: реinit + дамп)
  ...unseal-key   -> 6.5 D2: только реinit + логический дамп
  ...TLS          -> 6.6: generate-certs.sh + restart
  ...сеть хоста   -> 6.9 H1: netplan из бэкапа + netplan try (С КОНСОЛИ!) + up --force-recreate
  ...весь хост    -> 6.2: ОС -> netplan -> repo+.env -> TLS -> openbao -> mongodb -> up

ГЛАВНОЕ ПРАВИЛО: unseal-key + openbao/data inseparable; mongodump = plaintext.
```





