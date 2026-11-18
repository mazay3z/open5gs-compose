# EKI-TK: шифрование данных SIM при прописывании профилей (транспортный ключ)

> **Статус:** прототип (PLTEBOX-137, «Сделать прототип шифрования для БД с
> данными SIM карт»), GSMA FS.28 уровень «Acceptable» для лабораторного стенда.
> **Стенд:** 192.168.0.9, ветка `fix-mongodb-openbao`.
> **Ограничение:** ни одна строка исходного кода open5gs не изменена — всё
> решение живёт в слое развёртывания (compose-оверлеи, скрипты, KMS, документация).

---

## 1. Цель и требования (из PLTEBOX-137)

Ответ отдела ИБ (Кондратьев И.Е., 02.11.2026) зафиксировал базовые требования
прототипа:

- генерация USIM-данных в МТС выполняется через КПХД; требования к транспортным
  ключам берутся из КПХД: **транспортный ключ HLR — AES-128-ECB**: выгрузка KI в
  зашифрованном виде для импорта в HLR/AuC, расшифрование KI непосредственно на
  сетевом узле (в production — в HSM-AuC);
- формат файла загрузки в AUC — **произвольный** (пример: `AGSUI:IMSI=…,
  EKI=…, KIND=1, A3A8IND=2, A4IND=1`);
- уровень соответствия — GSMA FS.28 «Acceptable».

Комментарий исполнителя (13.11.2026): «минимальные требования это **шифрование
БД** и **прописывание профилей с использованием транспортного ключа**».

Что закрывает этот прототип:

| Требование | Механизм | Статус |
|---|---|---|
| Шифрование БД (data-at-rest) | PSMDB 5.0 + OpenBao (WiredTiger, KEK в KMS) | уже реализовано (ветка `fix-mongodb-openbao`, `docker-compose.encryption.yaml`) |
| Транспорт до БД (FS.28 Transport Protection) | MongoDB TLS `requireTLS` | **реализовано** (`docker-compose.dbtls.yaml`) |
| Прописывание профилей с TK | файл с eKi + EKI → импортёр расшифровывает TK из KMS | **реализовано** (`.deploy/scripts/{sim-kpdh,import-profiles,tk-mgmt}.sh`) |
| Расшифрование «на сетевом узле в HSM-AuC» | программное расшифрование на узле импорта (эмуляция HSM) | реализовано как эмуляция; HSM — roadmap |
| Record Protection FS.28 (Ki_enc в БД, расшифрование HSS/UDM в рантайме) | **невозможно без изменения кода ядра** | roadmap (форк open5gs) — §9 |

## 2. Архитектура

```
        «КПХД» (симулятор на стенде)                 СЕТЬ (pLTE-in-BOX)
 ┌──────────────────────────┐        ┌────────────────────────────────────────────┐
 │ sim-kpdh.sh              │        │  import-profiles.sh                        │
 │  RNG → Ki                │ файл   │  1) EKI → TK из OpenBao (fail-closed)      │
 │  eKi = AES128ECB(TK, Ki) │ ─────► │  2) проверка HMAC                          │
 │  HMAC = HMAC256(HK, …)   │ CSV    │  3) eKi → Ki                               │
 └──────────────┬───────────┘(eKi)   │  4) OPc = AES128(OP_сети, Ki)              │
                │                    │  5) запись в subscribers (mongo TLS)      │
                │ TK (совместный)    └───────────────┬────────────────────────────┘
                ▼                                    ▼
 ┌────────────────────────────── OpenBao (KMS) ──────────────────────────────────┐
 │ secret/transport-keys/eki-<N>  (TK, AES-128, KV v2, версионирование)         │
 │ secret/network/milenage-op     (OP сети)                                     │
 │ secret/psmdb-encryption        (KEK data-at-rest, было ранее)                │
 └───────────────────────────────────────────────────────────────────────────────┘
                                   ▼
        PSMDB (WiredTiger data-at-rest + net.tls requireTLS)  ←  HSS/UDM/UDR/PCRF/WebUI
                                   ▼
        Ranтайм ядра: HSS/UDM читают security.k из БД и считают AV (MILENAGE) —
        к KMS в рантайме НЕ обращаются (патч ядра для этого не требуется).
```

Свойство, важное для отказов: **KMS нужна только (а) при импорте профилей и
(б) при старте PSMDB**. Работающее ядро не останавливается при отказе OpenBao.

## 3. Иерархия ключей

```
OpenBao unseal (shamir 1/1 — см. §9)  + root token (оператор)
└── KV v2
    ├── psmdb-encryption        KEK data-at-rest (DEK в RAM mongod)
    ├── transport-keys/eki-N    TK (AES-128): шифруют Ki при провисининге (eKi)
    │                            N = EKI: индекс/версия ключа в файле загрузки
    └── network/milenage-op     OP сети (для вывода OPc)
        └── eKi = AES128ECB(TK_N, Ki)   (на уровне файла)
            └── Ki (на уровне абонента, в БД AUC)
                └── AV (RAND/SRES/XRES) — штатный рантайм ядра
```

- **Выбор ключа по EKI:** строка файла несёт `EKI=N` → импортёр берёт TK с пути
  `secret/transport-keys/eki-N`. EKI — индекс, не значение ключа (ключ не
  покидает KMS, в файлах/git/логах не присутствует).
- **Ротация:** `tk-mgmt.sh create N+1` → новые файлы генерируются с `EKI=N+1` →
  импорт → (опционально) `tk-mgmt.sh revoke N`. Ротация не требует перезапуска
  ядра и не меняет данные в БД (Ki абонентов уже раскрыты в AUC).
- **Отказ EKI/KMS — fail-closed:** неизвестный/отозванный EKI, недоступный KMS,
  несовпадающий HMAC — импорт **прерывается целиком**, в БД ничего не пишется.
  Работу ядра это не затрагивает (KMS в рантайме не используется). Выбран
  fail-closed (а не fail-open): цель прототипа — гарантировать, что профиль с
  ключами попадает в AUC только с проверенной целостностью.

## 4. Формат файла загрузки

Спецификация и примеры — в `.deploy/profiles/README.md`. Кратко:
`IMSI,EKI,E_KI,AMF[,HMAC]`, где `E_KI = AES-128-ECB(TK_EKI, Ki)` (32 hex);
5-й столбец `HMAC` — **опционален (функционал под вопросом)**: по умолчанию не
генерируется (`sim-kpdh.sh --hmac` — включить), импортёр проверяет его только при
наличии; обязательный режим — `IMPORT_REQUIRE_HMAC=1`. Формула — `HMAC-SHA256(HK,`
`IMSI|EKI|E_KI|AMF`)` с ключом `HK = SHA256(TK_EKI || "pLTE-inBOX-EKI-MAC")`.
OPc в файл не включается — сеть выводит `OPc = AES128(OP, Ki)` (TS 35.208 Annex C)
при импорте. Файлы с eKi **безопасно коммитятся** (plaintext-ключей не содержат).

## 5. Состав компонентов (только deployment-слой)

| Артефакт | Назначение |
|---|---|
| `docker-compose.dbtls.yaml` | оверлей: `requireTLS` на PSMDB + TLS-URI и CA-монтаж у hss/pcrf/pcf/udr/webui/populate + TLS-healthcheck |
| `.deploy/docker/psmdb/mongod-tls.conf` | mongod.conf с `net.tls` (CAFile обязателен: SERVER-72839) |
| `.deploy/scripts/generate-mongodb-tls.sh` | CA + leaf-сертификат mongod (SAN: mongodb, 127.0.0.1), `server.pem` |
| `.deploy/scripts/lib-bao.sh` | общее чтение секретов из OpenBao (KV v2, TLS, токен в tmp-файле 600; fail-closed) |
| `.deploy/scripts/tk-mgmt.sh` | `create/import/meta/revoke` TK по EKI (import — внешний ключ от поставщика/КПХД по файлу; revoke = gitignored-бэкап + удаление из KMS) |
| `.deploy/scripts/network-op-set.sh` | хранение OP сети в KMS |
| `.deploy/scripts/sim-kpdh.sh` | симулятор КПХД: генерация/перешифровка строк файла (`--gen`/`--rekey`; `--hmac` — опциональный 5-й столбец) |
| `.deploy/scripts/import-profiles.sh` | импортёр: EKI→TK→(HMAC при наличии)→eKi→Ki→OPc→AUC; fail-closed, идемпотентен (replay-safe); DB_URI берёт из окружения работающего hss |
| `.deploy/scripts/profile-mgmt.py` | менеджер профилей: все параметры абонента (msisdn/imeisv/apn/qos/arp/ambr/slice/status/barring/access/nam/tau/purge/mme_host…); одиночное (`add/update/revoke/purge/del/show/list`) и массовое (`edit <csv|json>`, пустое поле = не менять); бэкап перед изменением + `restore`; числа пишутся BSON int32 (`NumberInt`) — читатели open5gs требуют INT32 |
| `.deploy/scripts/verify-encrypted-stack.sh` | расширен (секции 0, 9, 10): авто-детект TLS-оверлея, статус EKI, файлы профилей; секция 6 — только факт читаемости мастер-ключа (значение не печатается) |
| `.deploy/profiles/*.csv` | демо-файлы (eKi, безопасны для git) |
| `.deploy/scripts/generate-diameter-tls.sh` | регенерация diameter-сертификатов (старые ключи удалены из дерева) |
| `.deploy/secrets/` (gitignored) | `bao-root-token` (операторская копия), `ue.env` (RAN-ключи), `revoked/` (бэкапы при отзыве) |

## 6. ADR: принятые решения

**D1. Где расшифровывается eKi→Ki.** Варианты: (a) импортёр на сетевом узле
(скрипт, программное расшифрование) — **принято** (прототип, «HSM-AuC в
software-эмуляции»); (b) аппаратный HSM-AuC — production-путь, недоступен на
стенде; (c) расшифрование HSS/UDM в рантайме из Ki_enc в БД — **требует форка
ядра** (HSS передаёт `auth_info.k` прямо в `milenage_generate()`,
`src/hss/hss-s6a-path.c:173,258` в v2.7.7 — внешнего хука нет). Зафиксировано
как ограничение, roadmap §11.

**D2. Защита канала NF↔БД.** Варианты: (a) **MongoDB TLS (принято)** — штатный
`net.tls requireTLS`, закрывает FS.28 gap «Transport Protection (DB)», только
compose-оверлей, без патчей; (b) IPsec/XFRM между контейнерами — не требуется
задачей, высокая эксплуатационная сложность (strongswan на стенде не
установлен), не встраивается в иерархию EKI; (c) WireGuard-оверлей — модуль не
загружен, та же проблема применимости; (d) TLS-прокси перед mongod — лишний
компонент при штатном TLS в PSMDB. S6a (Diameter) TLS — P2 (скрипт
регенерации сертификатов есть; `No_TLS` в конфигах остаётся), SBI-TLS в
open5gs 2.7.7 — требует проверки/форка ядра.

**D3. Режим шифрования.** AES-128-ECB — по практике КПХД (требование ИБ, R3).
ECB не аутентифицирован → добавлен HMAC-SHA256-контроль строки (Q8), ключ
контроля `HK = SHA256(TK || "pLTE-inBOX-EKI-MAC")` (отделение функций). В
production: AES-GCM/HSM-алгоритмы — roadmap.

**D4. EKI — индекс версии TK** (KV-путь `transport-keys/eki-N`), а не
мастер-ключ деривации. Совпадает с примером AGSUI из JIRA (поле `EKI=` в файле)
и даёт версионирование/отзыв средствами KV v2.

**D5. OPc выводится сетью** (`AES128(OP_сети, Ki)`, TS 35.208 Annex C) — как в
реальном потоке («раскрытие eKi → Ki, расчёт OPC» на сетевом узле, контекст
проекта Белый Раст в JIRA).

## 7. Процедуры (кратко)

```bash
cd ~/open5gs-compose

# Первичная настройка (один раз)
bash .deploy/scripts/network-op-set.sh <OP_сети 32hex>     # OP = как у действующих абонентов, иначе OPc будут другие
bash .deploy/scripts/tk-mgmt.sh create 1                    # TK для EKI=1
#   (или, если TK получен от поставщика профилей: bash .deploy/scripts/tk-mgmt.sh import 1 <файл-32hex>)
bash .deploy/scripts/generate-mongodb-tls.sh                # TLS-сертификаты PSMDB (если overlay не включался)
bash .deploy/scripts/generate-diameter-tls.sh               # (fresh deploy) TLS_Cred-файлы, которые freeDiameter читает при парсинге hss/mme/pcrf/smf
# COMPOSE_FILE в .env содержит docker-compose.dbtls.yaml; docker compose up -d

# Новый профиль (симуляция КПХД)
bash .deploy/scripts/sim-kpdh.sh --gen 1 <IMSI>
bash .deploy/scripts/import-profiles.sh .deploy/profiles/profiles-eki-1.csv

# Миграция plaintext-строки ue.list
bash .deploy/scripts/sim-kpdh.sh --rekey 1 <IMSI> --ki <32hex>
bash .deploy/scripts/import-profiles.sh <file>

# Ротация EKI 1 → 2
bash .deploy/scripts/tk-mgmt.sh create 2
bash .deploy/scripts/sim-kpdh.sh --gen 2 <IMSI> --out .deploy/profiles/profiles-eki-2.csv
bash .deploy/scripts/import-profiles.sh .deploy/profiles/profiles-eki-2.csv
bash .deploy/scripts/tk-mgmt.sh revoke 1        # бэкап TK в .deploy/secrets/revoked/ (gitignored) + удаление из KMS

# Проверка стека
bash .deploy/scripts/verify-encrypted-stack.sh
```

## 8. Проверка на стенде (фактические результаты, 17.11.2026)

- **Импорт (создание):** `999990000000101` создан через EKI=1; документ
  `subscribers` штатной формы (security.k 32 hex, security.opc, security.amf,
  slice) — `[row 1] imsi=999990000000101 eki=1: subscriber created`.
- **Аутентификация (5G):** ueransim UE (IMSI 999990000000101, ключи из
  импорта) + gNB: `NG Setup procedure is successful`, `Initial Registration is
  successful`, `PDU Session establishment is successful PSI[1]`.
- **Idempotency/replay:** повторный импорт того же файла → `nochange`, дубликатов нет.
- **Неверный EKI (99):** `FAIL: TK for EKI=99 not available … ABORTED (fail-closed)`, в БД — 0 записей.
- **Коррупция файла:** смена 1 hex в E_KI → `HMAC mismatch … ABORTED`; подмена
  IMSI в готовой строке → `HMAC mismatch … ABORTED`.
- **Отказ KMS:** `docker compose stop openbao` → импорт `ABORTED`; hss/udm/udr/
  mongodb при этом работают (`Up … healthy`); после `start openbao` импорт проходит.
- **Ротация:** EKI=2 создан, профиль импортирован (`security keys updated`);
  EKI=3 (throwaway) отозван — повторный импорт файла EKI=3 отклонён, TK-бэкап в
  `.deploy/secrets/revoked/`.
- **MongoDB TLS:** plaintext-клиенты отклоняются (network error), healthcheck по
  TLS зелёный, HSS/UDR в логах: `MongoDB URI: 'mongodb://mongodb:27017/open5gs?tls=true&…'`;
  tcpdump на bridge во время импорта: 800 кадров, TLS-записи, **0 совпадений**
  по plaintext-IMSI и имени коллекции в pcap (полезная нагрузка не читается).
- **Репетиция отката TLS off→on:** снятие/возврат `docker-compose.dbtls.yaml` из `COMPOSE_FILE`
  — оба направления проверены (healthchecks, логи URI, plaintext/TLS-пинги, импорт, verify);
  авто-детект режима в скриптах читает конфиг работающего mongod (репетиция показала, что
  детект по файлам на диске недостоверен).
- **Тесты стабильности:** `restart mongodb` (x2, в т.ч. после `restart openbao` — «Master
  encryption key has been read from the key management facility» при старте); 6 повторных
  импортов (nochange); полный цикл `docker compose down`/`up -d` — стек восстановился,
  повторный 5G-attach импортированного абонента успешен. Выявлены и закрыты 2 бага:
  (1) удаление diameter-ключей из дерева ломало запуск hss/mme/pcrf/smf — `TLS_Cred` в
  .conf читается при парсинге (фикс: `generate-diameter-tls.sh`, ключи 644 — freeDiameter
  в контейнере non-root, CA синхронизируется в `<node>/ca.crt` для `TLS_CA`); (2) pcf не был
  в TLS-оверлее (упал на requireTLS) — добавлен.
- **Baseline-сохранность:** `verify-encrypted-stack.sh` — все секции OK
  (data-at-rest: «Master encryption key has been read from the key management
  facility», version 2; plaintext-IMSI в /data/db отсутствуют; webui HTTP 200).

- **Менеджер профилей `profile-mgmt.py` (18.11):** проверены show/list (ключи
  маскируются), одиночное `update` (MSISDN как E.212 BCD, access-restriction, tau),
  массовое `edit` CSV (2 строки: MSISDN + APN/QoS/AMBR/UE-AMBR/TAU/STATUS) и JSON
  (2 сессии в slice, mme_host/mme_realm/imeisv, очистка MSISDN через `""`),
  `revoke`/re-grant, `add`/`del`/`restore` (ключ после restore — byte-identical),
  негативы fail-closed: неизвестное поле, несуществующий IMSI, `add` без ключей,
  `k` без `opc`, не-цифровой MSISDN, `--dry-run` (БД не меняется).
  **Найденный и закрытый баг:** PSMDB-5.0 shell не имеет `EJSON`, и JSON-раундтрип
  превращал BSON int32 в double — ридеры open5gs требуют INT32
  (`lib/dbi/subscription.c:484` `BSON_ITER_HOLDS_INT32`) → UDR «No SST»,
  UDM «No AccessAndMobilitySubscriptionData», attach падал
  `FIVEG_SERVICES_NOT_ALLOWED`. Фикс: все числа в `updateOne $set`/`replaceOne`
  генерируются как `NumberInt(...)`, `_id` — как `ObjectId(...)`
  (`js_literal()` в profile-mgmt.py); после фиксации 5G-attach успешен.
- **Уроки 5G-attach (18.11):** gNB one-off должен совпадать с TAI/слайсами AMF
  (стенд: `TAC=15099`, `SD=0xffffff` — в `docker-compose.yaml` у сервиса gnb
  `TAC=009`/`SD=0x111111`, для attach использовался одноразовый контейнер,
  коммит-конфиги не менялись); ключи UE берутся из AUC именно того IMSI
  (ue.env — это UE1=999991234567896, не демо-абоненты); SQN-resync
  (Authentication Failure → повторный Auth Request) — штатное поведение.

## 9. Ограничения и остаточные риски (приняты)

1. **Ki в БД — plaintext** (читается ядром без KMS): data-at-rest + TLS-канал
   закрывают канал утечки «с диска» и «по сети до БД», но не «через
   MongoDB-протокол». Полное закрытие (Ki_enc в БД) — только форк ядра (§11).
2. **dbctl-аргументы:** при создании нового абонента Ki/OPc передаются CLI-аргументами
   в одноразовый контейнер `gradiant/open5gs-dbctl` (видимы в process list хоста
   на время записи). Обход (mongo-вставка «с нуля») отвергнут: формат документа
   создаёт dbctl, ручная сборка рискованна. Полное закрытие — форк ядра.
3. **ECB без аутентификации** (требование КПХД) — опциональный HMAC-контроль (функционал под вопросом, по умолчанию выключен);
   при наличии TK атакующий может подменить строку целиком (HMAC тоже считает) —
   доверие к каналу доставки файла (scp/SFTP) остаётся внешним; в production —
   PGP/S-MIME над файлом (FS.28 File Protection).
4. **mTLS отключён** (`allowConnectionsWithoutCertificates: true`): канал
   зашифрован, сервер аутентифицирован, клиент — нет (внутри docker-сети).
5. **OpenBao shamir 1/1**, root-token на диске, 27017/8200 опубликованы на хост —
   упрощения стенда; в production: 3/2, secret manager, firewall хоста.
6. **OP сети в KMS в plaintext** (нужен для вывода OPc) — при утечке KMS
   атакующий может выводить OPc из перехваченных eKi; риск принимается
   (прототип), в production OP — в HSM-AuC.
7. **История git** содержит удалённые plaintext-ключи (`ue.list`, `.env`,
   diameter-ключи): очистка истории (force-push/BFG) — отдельное решение.
8. S6a (Diameter) — `No_TLS`; SBI — plain HTTP: не требуются задачей, P2/форк.

## 10. Откат

Каждый элемент — новый обратимый артефакт:

```bash
# 1) выключить TLS до БД: убрать docker-compose.dbtls.yaml из COMPOSE_FILE (.env) и up -d
# 2) EKI-TK скрипты/файлы — просто удалить (не используются стеком); TK в KMS не
#    мешают (отдельные пути secret/transport-keys/*, secret/network/*)
# 3) данные: бэкап до изменений .deploy/dump-migration/pre-eki-tk-20261117-104443/
#    (mongodump + openbao + verify-baseline) — восстановление: mongorestore из dump
# 4) демо-абоненты 999990000000101/102 удалить: db.subscribers.remove({imsi:"…"})
```

## 11. Roadmap (за пределами прототипа)

| # | Пункт | Что закрывает |
|---|---|---|
| 1 | Форк open5gs: Ki_enc в БД + расшифрование HSS/UDM через KMS (HSM-AuC API) | Record Protection FS.28, остаточные риски 1–2 |
| 2 | Аппаратный HSM / SoftHSM (PKCS#11) для TK и OP | «HSM-AuC» в production, риск 6 |
| 3 | mTLS на MongoDB-канале (client certs) | риск 4 |
| 4 | OpenBao shamir 3/2, token management, audit log | риск 5, FS.28 key management |
| 5 | Diameter S6a TLS (конфиги + `generate-diameter-tls.sh` готовы к включению) | транспорт между NF 4G |
| 6 | PGP/S-MIME-обёртка над файлами загрузки (FS.28 File Protection) | риск 3 |
| 7 | Очистка git-истории от plaintext-ключей | риск 7 |
| 8 | ZMK/shares, key ceremony, retention-политика | FS.28 «Recommended» |
