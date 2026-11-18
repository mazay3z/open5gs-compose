# Архитектурный анализ: реализация GSMA FS.28 в open5gs-compose

> **Документ:** Security Guidelines for Exchange of UICC Credentials (FS.28 v1.0)  
> **Проект:** open5gs-compose (pLTE_in_Box)  
> **Версия:** 1.0  
> **Дата:** 2026-10-27

---

## Содержание

1. [Резюме](#1-резюме)
2. [Текущее состояние (As-Is)](#2-текущее-состояние-as-is)
3. [Gap Analysis: сопоставление с FS.28](#3-gap-analysis-сопоставление-с-fs28)
4. [Архитектурное решение (To-Be)](#4-архитектурное-решение-to-be)
5. [Конкретные шаги внедрения](#5-конкретные-шаги-внедрения)
6. [Архитектурная диаграмма целевого решения](#6-архитектурная-диаграмма-целевого-решения)
7. [Риски и ограничения](#7-риски-и-ограничения)
8. [Приоритеты и дорожная карта](#8-приоритеты-и-дорожная-карта)
9. [Заключение](#9-заключение)

---

## 1. Резюме

Настоящий документ содержит архитектурный анализ соответствия проекта **open5gs-compose** (ветка `fix-mongodb-openbao`, pLTE_in_Box) требованиям **GSMA FS.28** — «Security Guidelines for Exchange of UICC Credentials».

Проект уже обладает **продвинутой инфраструктурой защиты данных**: Percona Server for MongoDB (PSMDB) с шифрованием Data-at-Rest на уровне WiredTiger и внешним KMS OpenBao. Однако ключевые аутентификационные параметры абонентов (Ki/OP) хранятся и обрабатываются в **открытом виде**, что создаёт критический разрыв с требованиями FS.28 по генерации, защите и управлению жизненным циклом UICC credentials.

Документ предлагает **трёхуровневую стратегию** реализации, от software-based решения для текущего тестового стенда до production-grade архитектуры с аппаратным HSM и SAS-UP аккредитацией.

---

## 2. Текущее состояние (As-Is)

Проект `open5gs-compose` — это docker-compose стек мобильного ядра Open5GS 2.7.7 (4G EPC + 5GC), включающий MME/HSS/PCRF, AMF/SMF/UPF, WebUI, мониторинг (Prometheus/Grafana) и симуляторы RAN.

### 2.1. Существующие механизмы безопасности

| Компонент | Реализация | Оценка |
|-----------|-----------|--------|
| **Хранилище данных** | Percona Server for MongoDB 5.0 с Data-at-Rest Encryption (WiredTiger + OpenBao KMS) | ✅ Рекомендуется |
| **KMS** | OpenBao 2.0 (Vault-совместимый), auto-unseal, TLS 1.2+, RSA-4096 CA | ✅ Рекомендуется |
| **Бэкапы** | `mongodump` + `openssl enc -aes-256-cbc`, проверка на plaintext IMSI | ✅ Рекомендуется |
| **TLS инфраструктура** | Самоподписанные сертификаты для OpenBao (RSA-4096 CA, RSA-2048 server) | ⚠️ Acceptable |

### 2.2. Выявленные пробелы (Critical Gaps)

| Компонент | Текущее состояние | Уровень риска |
|-----------|-------------------|---------------|
| **Аутентификация UE (Ki/OP)** | Хранятся в **plaintext**: `.env` (`UE1_KI`, `UE1_OP`), `ue.list`, MongoDB `subscribers` | 🔴 Критично |
| **Генерация ключей** | Ki/OP — **захардкожены**, не генерируются программно, нет RNG | 🔴 Критично |
| **Record Protection** | Нет индивидуального шифрования credential (Ki/OP) на уровне записи | 🔴 Критично |
| **File Protection** | `ue.list` — plaintext CSV, ZIP без шифрования | 🔴 Критично |
| **Transport Protection (DB)** | MongoDB внутри Docker-сети **без TLS** (`mongodb://mongodb/open5gs`) | 🟡 Средне |
| **ZMK / Key Shares** | Не реализовано разделение знаний (split knowledge) | 🔴 Критично |
| **Key Lifecycle** | Нет ротации, срока жизни, разделения по вендорам | 🔴 Критично |
| **Data Retention** | Процедуры DR есть, но не автоматизированы для UICC-данных | 🟡 Средне |

### 2.3. Локализация plaintext credentials

```
.env:
  UE1_OP=E8ED289DEBA952E4283B54E88E6183CA
  UE1_KI=465B5CE8B199B49FAA5F0A2EE238A6BC

.deploy/docker/ue.list:
  999990000000001,465B5CE8B199B49FAA5F0A2EE238A6BC,E8ED289DEBA952E4283B54E88E6183CA
  999991234567896,465B5CE8B199B49FAA5F0A2EE238A6BC,E8ED289DEBA952E4283B54E88E6183CA

docker-compose.yaml (populate):
  while IFS=, read -r imsi ki op; do
    open5gs-dbctl add_ue_with_slice $$imsi $$ki $$op internet 1 ffffff
  done < /opt/open5gs/ue.list
```

> **Примечание:** PSMDB шифрует данные **на диске**, но при чтении через MongoDB-протокол данные возвращаются в plaintext. Любой администратор с доступом к MongoDB может прочитать Ki/OP.

---

## 3. Gap Analysis: сопоставление с FS.28

### 3.1. Generation of UICC Credentials (§3.1 FS.28)

| Требование FS.28 | Текущее состояние | Gap |
|-----------------|-------------------|-----|
| **UICC Unique Credentials** — деривация в HSM из мастер-ключа с использованием diversification input | Ki/OP захардкожены в `ue.list` | Полное отсутствие генерации |
| **Мастер-ключ** — в HSM, RNG NIST SP 800-90A / AIS-31 | Нет мастер-ключа для Ki/OP | Нет HSM, нет аппаратного RNG |
| **Алгоритмы деривации** — AES-256 (recommended), AES-128/192 (acceptable), 3DES deprecated | Нет деривации | Не применимо |
| **UICC Common Credentials** — split knowledge, ≥2 custodians | Нет общих credentials | Не реализовано |

### 3.2. Secure Data Exchange (§3.2 FS.28)

| Уровень | Требование FS.28 | Текущее состояние | Gap |
|---------|-----------------|-------------------|-----|
| **Record Protection** | Каждый Ki/OP зашифрован transport key (AES-256), один TK на тип credential и вендора | Ki/OP в plaintext в БД и в файле | Нет шифрования записей |
| **File Protection** | PGP RSA ≥4096 / ECC order ≥256 или AES-256 | `ue.list` — plaintext CSV | Нет PGP-шифрования файлов |
| **Transport Protection** | TLS 1.2+, FTPS/SFTP/HTTPS между MNO и vendor | Внутренняя Docker-сеть без TLS к MongoDB | Нет защиты канала |

### 3.3. ZMK Establishment (§3.3 FS.28)

| Требование | Текущее состояние |
|------------|-------------------|
| Zone Master Key из key shares (XOR или Hash, ≥2 shares) | Не реализовано |
| ≥2 key custodians, split knowledge | Не реализовано (OpenBao init: 1 share, threshold 1) |
| KCV (Key Check Value) verification | Не реализовано |
| Physical / Digital transmission с проверкой целостности | Не реализовано |

### 3.4. Key Management (§3.5 FS.28)

| Требование | Текущее состояние |
|------------|-------------------|
| Finite lifespan (renewal каждые 3 года) | Нет |
| One keyset per UICC vendor | Нет |
| No reuse across customers | Нет (тестовые ключи reused) |
| Monitor key usage and algorithm efficacy | Нет |

---

## 4. Архитектурное решение (To-Be)

Предлагается **трёхуровневая** стратегия, учитывающая статус проекта как тестового/лабораторного стенда, но с чётким путём эволюции к production.

| Уровень | Назначение | HSM / RNG | Соответствие FS.28 |
|---------|-----------|-----------|-------------------|
| **1. Software-Based** | Текущий стенд, разработка, CI/CD | Software RNG (`/dev/urandom`) | Acceptable для lab |
| **2. Hybrid** | Pre-production, демо, пилот | SoftHSMv2 / TPM 2.0 / Intel SGX | Acceptable для pilot |
| **3. Production-Grade** | Коммерческая эксплуатация | Аппаратный HSM (Thales, Utimaco) | Recommended |

---

### 4.1. Уровень 1: Software-Based Security

#### 4.1.1. Secure Credential Generation

**Принцип:** заменить захардкоженные Ki/OP на программную деривацию из мастер-ключа с уникальным salt на UE.

**Мастер-ключ для UICC** (`uicc-master-key`) хранится в OpenBao (KV v2), **отдельно** от PSMDB master key.

**Схема деривации (KDF2 / HMAC-based):**

```
Ki_i = HMAC-SHA256(Master_Ki, IMSI || "Ki" || salt_i)
OP_i = HMAC-SHA256(Master_OP, IMSI || "OP" || salt_i)
```

или через PBKDF2 (PKCS#5) с 10 000 итераций:

```
Ki_i = PBKDF2(HMAC-SHA256, Master_Ki, IMSI || salt_i, 10000, 128)
```

**Компонент: `uicc-key-service`** (новый микросервис в стеке):

```yaml
services:
  uicc-key-service:
    image: open5gs-uicc-kms:latest
    profiles: [key-management]
    environment:
      - BAO_ADDR=https://openbao:8200
      - BAO_TOKEN_FILE=/run/secrets/bao-token
      - KEY_DERIVATION_ALGO=AES-256-CTR-HMAC-SHA256
      - MASTER_KEY_PATH=secret/data/uicc-master-key
    secrets:
      - bao-token
    networks:
      - core-network
    volumes:
      - ./uicc-policies:/etc/uicc-policies:ro
```

**Преимущества:**
- Ki/OP больше не хранятся в plaintext
- Восстановление возможно только при наличии Master Key в OpenBao
- Можно перегенерировать все Ki/OP при ротации мастер-ключа
- Salt — уникальный на UE, хранится в MongoDB в открытом виде (не является секретом по FS.28)

#### 4.1.2. Record Protection — OpenBao Transit Engine

Open5GS (на базе MongoDB) не поддерживает Client-Side Field Level Encryption (CSFLE) из коробки. Рекомендуется использовать OpenBao как **encryption-as-a-service**.

**Архитектура:**

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  HSS / UDM  │────►│  OpenBao     │────►│  MongoDB    │
│  (Open5GS)  │     │  Transit     │     │  (PSMDB)    │
│             │     │  (Ki/OP ENC) │     │  Ki_enc,    │
│  IMSI ──────┼────►│              │     │  OP_enc     │
│             │◄────│  vault:v1:.. │◄────│             │
└─────────────┘     └──────────────┘     └─────────────┘
```

**Настройка OpenBao:**

```bash
# Включить Transit engine
bao secrets enable transit
bao write -f transit/keys/uicc-credentials

# Шифрование Ki перед записью в БД
bao write transit/encrypt/uicc-credentials \
  plaintext=$(base64 <<< "465B5CE8B199B49FAA5F0A2EE238A6BC")
# Ответ: ciphertext = vault:v1:abcd...

# Дешифрование при аутентификации
bao write transit/decrypt/uicc-credentials \
  ciphertext=vault:v1:abcd...
```

**Интеграция с Open5GS:**
- Создать `uicc-populate.sh` — обёртка над `open5gs-dbctl`
- При добавлении UE: шифровать Ki/OP через OpenBao Transit, сохранять `Ki_enc`, `OP_enc`
- При аутентификации: HSS/UDM расшифровывает через OpenBao перед вычислением RES/XRES

#### 4.1.3. File Protection (замена `ue.list`)

**Текущее состояние:** `ue.list` — plaintext CSV с Ki/OP.

**Целевое состояние:**

1. **Удалить `ue.list` из репозитория** (git filter-branch + .gitignore)
2. **Заменить на PGP-шифрованный файл** `ue.list.pgp` (AES-256, RSA-4096)
3. **Расшифровка в runtime** через init-container:

```yaml
services:
  uicc-decrypt:
    image: alpine
    profiles: [populate]
    volumes:
      - ./ue.list.pgp:/input/ue.list.pgp:ro
      - uicc-plain:/output
    command: >
      sh -c "apk add gnupg &&
             gpg --batch --passphrase-file /run/secrets/pgp-passphrase
                 -d /input/ue.list.pgp > /output/ue.list"
    secrets:
      - pgp-passphrase

  populate:
    depends_on:
      uicc-decrypt:
        condition: service_completed_successfully
    volumes:
      - uicc-plain:/opt/open5gs/ue.list:ro
```

#### 4.1.4. Transport Protection — MongoDB TLS

**Текущее состояние:** `DB_URI: mongodb://mongodb/open5gs` (plaintext TCP).

**Целевое состояние:** `DB_URI: mongodb://mongodb:27017/open5gs?tls=true`.

**Изменения в `mongod.conf` (PSMDB):**

```yaml
net:
  port: 27017
  bindIp: 0.0.0.0
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/mongodb-tls/server.pem
    CAFile: /etc/mongodb-tls/ca.crt
```

**Дополнение `generate-certs.sh`:**

```bash
openssl req -newkey rsa:4096 -nodes -keyout mongodb-server.key -out mongodb-server.csr \
  -subj "/CN=mongodb/O=pLTE-in-Box"
openssl x509 -req -in mongodb-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out mongodb-server.crt -days 825 -sha256
cat mongodb-server.crt mongodb-server.key > mongodb-server.pem
```

**Обновление `DB_URI` в Open5GS сервисах:**

```yaml
x-open5gs-svc-envs: &open5gs_svc_envs
  DB_URI: >-
    mongodb://mongodb:27017/open5gs?
    tls=true&
    tlsCAFile=/etc/open5gs/tls/ca.crt&
    tlsCertificateKeyFile=/etc/open5gs/tls/client.pem
```

#### 4.1.5. ZMK — Software Emulation

Для тестового стенда — эмуляция split knowledge через Shamir's Secret Sharing в OpenBao.

**Изменение `entrypoint.sh`:**

```bash
# Вместо: bao operator init -key-shares=1 -key-threshold=1
# Использовать: -key-shares=3 -key-threshold=2
INIT_OUTPUT=$(bao operator init -key-shares=3 -key-threshold=2 -format=json)
# Key shares распределяются между 3 custodians:
#   - MNO Security Administrator
#   - MNO Operations Officer
#   - Backup / DR Custodian
```

**ZMK между MNO и UICC Vendor:**

```bash
# Transit engine для ZMK
bao secrets enable -path=zmk transit
bao write -f zmk/keys/mno-vendor-alpha

# Key wrapping: ZMK шифрует Transport Keys
bao write zmk/encrypt/mno-vendor-alpha \
  plaintext=$(base64 <<< "$TRANSPORT_KEY")
```

---

### 4.2. Уровень 2: Hybrid (SoftHSM / TPM 2.0)

Для демонстрации аппаратного корня доверия без покупки дорогого HSM.

#### 4.2.1. SoftHSMv2

```yaml
services:
  softhsm:
    image: softhsm2:latest
    volumes:
      - softhsm-tokens:/var/lib/softhsm/tokens
      - ./hsm-init.sh:/hsm-init.sh
    command: /hsm-init.sh
```

- Мастер-ключ для UICC хранится в SoftHSM (PKCS#11)
- OpenBao получает ключ через PKCS#11 provider
- Архитектурно готово к замене на аппаратный HSM

#### 4.2.2. TPM 2.0

- Seal OpenBao unseal keys в TPM хоста
- При перезагрузке — auto-unseal через TPM, а не через файл на диске
- Исключает кражу unseal key при компрометации файловой системы

---

### 4.3. Уровень 3: Production-Grade (HSM + SAS-UP)

| Компонент | Production-решение |
|-----------|-------------------|
| **HSM** | Thales Luna 7, Utimaco CryptoServer, AWS CloudHSM, Azure Dedicated HSM |
| **SAS-UP** | Аккредитация производственной площадки UICC vendor (GSMA SAS) |
| **Key Ceremony** | Физическая церемония генерации ZMK с 2+ custodians, видеозапись, dual control |
| **Record Protection** | HSM выполняет деривацию Ki/OP, ключи никогда не покидают HSM |
| **Transport** | SFTP over TLS 1.3, S/MIME с PGP RSA-4096 |
| **Key Lifecycle** | Автоматическая ротация каждые 3 года, мониторинг через SIEM |
| **RNG** | Аппаратный TRNG, сертифицированный AIS-31 / NIST SP 800-90A |

---

## 5. Конкретные шаги внедрения

### Этап 1: Быстрый выигрыш (1–2 дня)

| # | Задача | Результат |
|---|--------|-----------|
| 1.1 | Удалить plaintext Ki/OP из репозитория (`git filter-branch`, `.gitignore`) | Исключена утечка через git history |
| 1.2 | PGP-шифрование `ue.list` (AES-256, RSA-4096) | File Protection |
| 1.3 | Добавить init-container для расшифровки `ue.list.pgp` | Runtime-only plaintext |
| 1.4 | Включить TLS для MongoDB (server + client certs) | Transport Protection |

### Этап 2: Application-Level Encryption (1 неделя)

| # | Задача | Результат |
|---|--------|-----------|
| 2.1 | Включить OpenBao Transit Engine (`uicc-credentials`) | Encryption-as-a-Service |
| 2.2 | Создать `uicc-populate.sh` — шифрует Ki/OP перед записью в БД | Record Protection |
| 2.3 | Модифицировать HSS/UDM или создать прокси для расшифровки | Прозрачная интеграция |
| 2.4 | Хранить в MongoDB: `{imsi, ki_enc, op_enc, salt, alg_version}` | Структурированные данные |

### Этап 3: Key Management (1–2 недели)

| # | Задача | Результат |
|---|--------|-----------|
| 3.1 | Реализовать Shamir Secret Sharing (3-of-2) для OpenBao | Split knowledge |
| 3.2 | Создать `uicc-master-key` в OpenBao (отдельно от PSMDB KEK) | Мастер-ключ для деривации |
| 3.3 | Реализовать деривацию Ki/OP из IMSI + salt + master key | Credential Generation |
| 3.4 | Скрипт ротации `uicc-master-key` с перешифрованием | Key Lifecycle |
| 3.5 | Data retention: cron для удаления plaintext дампов старше 7 мес | §3.4 FS.28 |

### Этап 4: Мониторинг и аудит (1 неделя)

| # | Задача | Результат |
|---|--------|-----------|
| 4.1 | Включить OpenBao Audit Log (file / syslog) | Аудит доступа к ключам |
| 4.2 | Интеграция audit log с SIEM / Prometheus Alertmanager | Оперативное обнаружение |
| 4.3 | Алерты на несанкционированный доступ к `uicc-credentials` | Безопасность |
| 4.4 | Документирование key ceremony процедуры | Соответствие FS.28 |

---

## 6. Архитектурная диаграмма целевого решения

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EXTERNAL: UICC VENDOR (SAS-UP)                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Secure File Exchange: SFTP/TLS 1.3 + PGP RSA-4096 / S/MIME        │    │
│  │  ZMK Shares: Physical (tamper-evident bags) or Digital (PGP+KCV)   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    ▲                                        │
│                                    │ ZMK-protected Transport Keys           │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┼────────────────────────────────────────┐
│                              MNO: pLTE_in_Box                               │
│  ┌─────────────┐  ┌─────────────┐  │  ┌─────────────┐  ┌─────────────────┐  │
│  │   ZMK       │  │  Key        │  │  │  OpenBao    │  │   Percona Server│  │
│  │  Ceremony   │◄─┤  Custodians │◄─┘  │   (KMS)     │  │   for MongoDB   │  │
│  │  (3-of-2)   │  │  (>=2)      │     │             │  │   5.0 (PSMDB)   │  │
│  └─────────────┘  └─────────────┘     │  ├─ PSMDB KEK│  │                 │  │
│                                       │  ├─ UICC MK  │  │  ┌───────────┐  │  │
│  ┌─────────────────────────────────┐  │  ├─ Transit  │  │  │subscribers│  │  │
│  │  uicc-key-service               │  │  │   Engine  │  │  │{ki_enc,  │  │  │
│  │  ├─ Derive Ki/OP from Master Key│◄─┘  └───────────┘  │  │ op_enc,   │  │  │
│  │  ├─ RNG (software / HSM)        │       ▲            │  │ salt}     │  │  │
│  │  └─ Salt generation             │       │ TLS :8200  │  └───────────┘  │  │
│  └─────────────────────────────────┘       │            │       ▲         │  │
│                                            │            │       │ TLS     │  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐    │      ┌─────┴───────┐         │  │
│  │   HSS   │  │   UDM   │  │  AUSF   │◄───┘      │  HSS/UDM/   │         │  │
│  │ (4G)    │  │ (5G)    │  │ (5G)    │           │  AUSF       │         │  │
│  └────┬────┘  └────┬────┘  └────┬────┘           │  (Open5GS)  │         │  │
│       │            │            │                └─────────────┘         │  │
│       └────────────┴────────────┘                      ▲                  │  │
│                    │                                   │ Decrypt via     │  │
│                    │ Diameter / SBI                    │ Transit API     │  │
│                    ▼                                   │                 │  │
│              ┌─────────┐                               │                 │  │
│              │   UE    │                               │                 │  │
│              └─────────┘                               │                 │  │
│                                                        │                 │  │
│  ┌─────────────────────────────────────────────────────┘                 │  │
│  │  Monitoring: Prometheus + Grafana + Vault Audit Log + Alertmanager    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Риски и ограничения

| Риск | Вероятность | Влияние | Митигация |
|------|------------|---------|-----------|
| **Open5GS не поддерживает шифрованные Ki/OP из коробки** | Высокая | Высокое | Патч ядра Open5GS или прокси-сервис для расшифровки перед вычислением RES/XRES |
| **Производительность** — латентность OpenBao Transit при аутентификации | Средняя | Среднее | Кэширование DEK в HSS/UDM (в памяти, не на диске); локальный кэш с TTL |
| **Software RNG не соответствует FS.28 strictly** | Низкая | Среднее | Документировать как «test stand emulation»; для production заменить на HSM |
| **Сложность key ceremony** | Средняя | Среднее | Автоматизировать через скрипты, но требовать manual confirmation для каждого custodian |
| **Потеря OpenBao unseal keys** | Низкая | Критичное | Распределить shares по 3+ custodians; хранить в физическом сейфе; DR-процедура в DISASTER-RECOVERY.md |
| **Single point of failure: OpenBao** | Средняя | Высокое | Рассмотреть кластер OpenBao (Raft, 3 nodes); бэкап `openbao/data` |

---

## 8. Приоритеты и дорожная карта

| Приоритет | Задача | Этап | Сложность | Влияние на FS.28 | Срок (оценка) |
|-----------|--------|------|-----------|-------------------|---------------|
| **P0** | Удалить plaintext Ki/OP из репозитория, PGP-шифрование `ue.list` | 1.1–1.3 | Низкая | Высокое | 1 день |
| **P0** | Включить TLS для MongoDB | 1.4 | Низкая | Высокое | 1 день |
| **P1** | OpenBao Transit + шифрование Ki/OP в БД | 2.1–2.4 | Средняя | Критичное | 3–4 дня |
| **P1** | Мастер-ключ + деривация Ki/OP из IMSI | 3.1–3.3 | Средняя | Критичное | 3–4 дня |
| **P2** | ZMK с Shamir Secret Sharing (3-of-2) | 3.1 | Средняя | Высокое | 2–3 дня |
| **P2** | Key rotation (3 года) + data retention (7 мес) | 3.4–3.5 | Низкая | Среднее | 1–2 дня |
| **P2** | Мониторинг: OpenBao Audit Log + алерты | 4.1–4.3 | Средняя | Среднее | 2–3 дня |
| **P3** | SoftHSM/TPM интеграция | — | Высокая | Среднее (demo) | 1–2 недели |
| **P3** | SAS-UP vendor accreditation | — | Организационная | Критичное (production) | 6–12 месяцев |

---

## 9. Заключение

Текущий проект `open5gs-compose` обладает **сильной базой** в виде PSMDB + OpenBao с Data-at-Rest Encryption. Это позволяет строить дальнейшие механизмы защиты UICC credentials на уже существующей KMS-инфраструктуре.

Для соответствия **GSMA FS.28** необходимо закрыть 4 критических gap:

1. **Credential Generation** — заменить захардкоженные Ki/OP на деривацию из мастер-ключа с уникальным salt
2. **Record Protection** — добавить Application-Level Encryption (OpenBao Transit) для индивидуального шифрования Ki/OP
3. **Transport & File Protection** — PGP-шифрование для файлов обмена, TLS для всех каналов связи с БД
4. **Key Management** — ZMK с split knowledge, ротация ключей, data retention, аудит

Предложенное решение **масштабируемо**: начинается с software-based реализации для тестового стенда, но архитектурно готово к замене компонентов на аппаратный HSM и SAS-UP accredited processes для коммерческой эксплуатации.

> **Следующий шаг:** утверждение архитектуры и начало реализации Этапа 1 (PGP-шифрование `ue.list` + MongoDB TLS).

---

## Приложение А. Ссылки

| Ссылка | Описание |
|--------|----------|
| [GSMA FS.28 v1.0](https://infocentre2.gsma.com/) | Security Guidelines for Exchange of UICC Credentials |
| [PSMDB-ENCRYPTION.md](PSMDB-ENCRYPTION.md) | Архитектура шифрования PSMDB + OpenBao в проекте |
| [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) | Процедуры резервного копирования и восстановления |
| [OpenBao Docs](https://openbao.org/docs/) | Документация OpenBao KMS |
| [Percona PSMDB Encryption](https://docs.percona.com/percona-server-for-mongodb/5.0/vault.html) | Data-at-Rest Encryption в Percona Server for MongoDB |
| [NIST SP 800-90A Rev.1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) | Recommendation for Random Number Generation |
| [NIST SP 800-88 Rev.1](https://www.nist.gov/publications/nist-special-publication-800-88-revision-1-guidelines-media-sanitization) | Guidelines for Media Sanitization |

---

*Документ подготовлен в рамках архитектурного анализа проекта open5gs-compose для оценки соответствия требованиям GSMA FS.28.*

