# pLTE/p5G in the BOX — open5gs (docker compose)

Развёртывание 4G (EPC) и 5G (SA) ядер open5gs одним docker-compose: все
NF, UPF, MongoDB (PSMDB), KMS (OpenBao), WebUI, мониторинг и симуляторы
RAN. Целевой продукт — «LTE/5G core в коробке» (проект pLTE/p5G in BOX,
PLMN 999/99).

## Возможности

- **Единый стек 4G+5G**: HSS/MME/SGW-C/PCRF (EPC) и AMF/SMF/UDM/UDR/AUSF/
  NSSF/NRF/BSF/PCF (5GC) из одного набора compose-файлов; eUPF
  (edgecom) для user plane.
- **Безопасность данных (PLTEBOX-137, GSMA FS.28 «Acceptable»)**:
  - шифрование БД на диске: PSMDB 5.0 + OpenBao (KV v2) — мастер-ключ
    вычитается из KMS при старте `mongod` (data-at-rest);
  - TLS на канале NF↔MongoDB (`docker-compose.dbtls.yaml`, `requireTLS`);
  - **прописка SIM-профилей по EKI и транспортному ключу (TK)**: ключи
    абонентов в загрузочных файлах зашифрованы (`E_KI = AES-128-ECB(TK, Ki)`),
    TK живёт только в OpenBao, файл безопасно коммитится;
  - менеджер профилей `profile-mgmt.py` — все параметры абонента
    (APN/QoS/AMBR/slice/MSISDN/ограничения/статусы), одиночное и массовое
    редактирование, бэкап/restore, маскирование ключей;
  - секретов (мастер-ключи, Ki/OP, приватные ключи TLS) нет в git —
    см. `.gitignore` и раздел «Секреты».
- **WebUI** (open5gs-webui) + **мониторинг** (Prometheus, Grafana,
  node-exporter, blackbox-exporter).
- **Симуляторы RAN** (профиль `5g-ran`: ueransim gNB/UE; 4G — srsRAN)
  для приёмки: attach/роуминг/PDU-сессии без реального оборудования.
- **Эксплуатационные скрипты**: деплой, верификация, бэкап/восстановление,
  генерация сертификатов, ротация ключей — всё в `.deploy/scripts/`.

## Состав стека (из `docker-compose.yaml` и оверлеев)

| Группа | Сервисы |
|---|---|
| EPC (4G) | `hss`, `mme`, `sgwc`, `sgwu`, `pcrf` |
| 5GC | `amf`, `smf`, `udm`, `udr`, `ausf`, `nssf`, `nrf`, `bsf`, `pcf` |
| User plane | `upf` (eUPF, edgecom), `upf-init` |
| Данные | `mongodb` (PSMDB 5.0), `populate` (разовый импорт `ue.list`) |
| KMS | `openbao` (TLS :8200, loopback :8201) |
| Управление | `webui` (:9999) |
| Мониторинг | `prometheus`, `grafana` (:3000), `node_exporter`, `blackbox_exporter`, `nat` |
| RAN-симуляция (профиль `5g-ran`) | `gnb`, `ue` (ueransim 3.2.6) |

Открытые на хосте порты (стандартное состояние): 27017 (mongo), 8200
(openbao), 9999 (webui), 3000 (grafana), 36412/udp (S1AP), 38412/udp
(NGAP), 2152/udp (GTP-U).

## Compose-файлы

| Файл | Назначение |
|---|---|
| `docker-compose.yaml` | базовый стек (все NF, UPF, mongo, webui, мониторинг) |
| `docker-compose.override.yaml` | локальные правки по умолчанию (auto-load) |
| `docker-compose.encryption.yaml` | PSMDB data-at-rest + OpenBao (KMS) |
| `docker-compose.dbtls.yaml` | TLS на канале NF↔MongoDB (`requireTLS`, CA, healthcheck) |

Активный набор задаётся `COMPOSE_FILE` в `.env`:
`docker-compose.yaml:docker-compose.override.yaml:docker-compose.encryption.yaml:docker-compose.dbtls.yaml`.

## Быстрый старт

```bash
# 1) окружение: .env уже содержит COMPOSE_FILE/COMPOSE_PROFILES/порты
# 2) поднять стек
docker compose up -d
# 3) проверить состояние (только чтение)
bash .deploy/scripts/verify-encrypted-stack.sh
```

Профили запуска (`COMPOSE_PROFILES`): `4g-core`, `5g-core`, `monitoring`,
`5g-ran` (симуляторы), `edgecom`.

### Прописка профилей абонентов (SIM)

Ключевые потоки — в отдельных документах:

- **через EKI/TK** (производственный, без plaintext-ключей):
  `tk-mgmt.sh` → `sim-kpdh.sh` → `import-profiles.sh` —
  см. [`PROFILE-LOADING-INSTRUCTIONS.md`](PROFILE-LOADING-INSTRUCTIONS.md)
  и [`EKI-TK-ENCRYPTION.md`](EKI-TK-ENCRYPTION.md);
- **управление уже прописанными профилями** (APN, QoS, AMBR, slice,
  MSISDN, barring, отзыв, удаление, массовое редактирование, restore):
  `python3 .deploy/scripts/profile-mgmt.py --help` —
  см. [`.deploy/profiles/README.md`](.deploy/profiles/README.md).

## Структура репозитория

```
docker-compose*.yaml      — стек и оверлеи (см. таблицу выше)
.env                      — COMPOSE_FILE, COMPOSE_PROFILES, порты (без секретов)
4g5gcorebox-*.sh/.service — интеграция с хостом (systemd, XDP/eBPF, affinity)
.deploy/docker/           — конфиги NF (amf.yaml, hss.conf, mongod.conf, …),
                            сертификаты (только публичные), openbao.hcl
.deploy/scripts/          — эксплуатационные скрипты:
                            deploy-encrypted.sh, verify-encrypted-stack.sh,
                            inspect-stand.sh, generate-{certs,mongodb-tls,diameter-tls}.sh,
                            tk-mgmt.sh, sim-kpdh.sh, import-profiles.sh,
                            profile-mgmt.py, network-op-set.sh, redump-from-backup.sh
.deploy/profiles/         — загрузочные файлы профилей (eKi — безопасно для git)
PSMDB-ENCRYPTION.md       — data-at-rest (PSMDB + OpenBao)
EKI-TK-ENCRYPTION.md      — шифрование по EKI/TK: архитектура, ADR, процедуры, риски
PROFILE-LOADING-INSTRUCTIONS.md — инструкция для сотрудников ИБ
DISASTER-RECOVERY*.md     — бэкап/восстановление
FS28-ARCHITECTURE-ANALYSIS.md — анализ требований GSMA FS.28
```

## Секреты

Не попадают в git (`.gitignore`): мастер-ключ PSMDB, root-token OpenBao,
TK по EKI, OP сети, `ue.env` (ключи RAN-симуляторов), `ue.list`
(заменён на `ue.list.example` с публичными тест-ключами open5gs),
приватные TLS-ключи (регенерация: `generate-mongodb-tls.sh`,
`generate-diameter-tls.sh`), бэкапы `.deploy/backups/` (содержат ключи —
хранить как секрет).

## Ветки

- `fix-mongodb-openbao` — рабочая ветка стенда (PSMDB+OpenBao, EKI-TK);
- `feature/eki-tk-profile-mgmt` — текущая: EKI-TK + менеджер профилей
  (+squash-зеркало истории стенда).

## Ограничения прототипа

Ki/OPc в БД остаются plaintext (record protection по FS.28 требует
изменений в ядре open5gs — см. roadmap в `EKI-TK-ENCRYPTION.md` §11);
HMAC-контроль загрузочных файлов — опционален (функционал под вопросом).