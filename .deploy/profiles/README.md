# Файлы загрузки профилей UICC (поток EKI-TK)

Файлы в этом каталоге — **загрузочные файлы** для прописывания профилей
абонентов в AUC open5gs (коллекция `subscribers` MongoDB). Ключ абонента (Ki)
в файлах **не содержится в plaintext**: он зашифрован транспортным ключом (TK),
идентифицируемым по EKI (индексу ключа), по практике КПХД
(AES-128-ECB, уровень GSMA FS.28 «Acceptable»). Полная документация:
`EKI-TK-ENCRYPTION.md` в корне репозитория.

## Формат (v1)

```
# комментарии начинаются с '#'
IMSI,EKI,E_KI,AMF[,HMAC]
999990000000101,1,<32 hex>,8000
```

| Столбец | Значение |
|---|---|
| `IMSI` | 14–15 десятичных цифр |
| `EKI` | Индекс/версия транспортного ключа (целое > 0). Сам TK лежит в OpenBao по пути `secret/transport-keys/eki-<EKI>` и **никогда** не попадает в этот файл. |
| `E_KI` | `AES-128-ECB(TK_EKI, Ki)`, 32 hex. Ki — ровно 16 байт (без padding). |
| `AMF` | 5G-поле AMF, записывается в `security.amf` (по умолчанию `8000` — конвенция стека) |
| `HMAC` *(опционально, функционал под вопросом)* | Если столбец присутствует (5-й), импортёр проверяет `HMAC-SHA256(HK, "IMSI/EKI/E_KI/AMF")` (64 hex, `HK = SHA256(TK_EKI + "pLTE-inBOX-EKI-MAC")`). Контроль целостности: сам ECB не аутентифицирован. Включение: `sim-kpdh.sh --hmac` (генерация), `IMPORT_REQUIRE_HMAC=1` (обязательный режим импортёра). |

OPc в файл намеренно **не** включается: сеть выводит `OPc = AES128(OP, Ki)`
из своего сетевого OP при импорте (3GPP TS 35.208 Annex C, MILENAGE).

### Соответствие с примером Ericsson AGSUI (JIRA PLTEBOX-137)

`AGSUI:IMSI=…, EKI=…, KIND=1, A3A8IND=2, A4IND=1` — в этом прототипе
KIND/A3A8IND/A4IND фиксированы (MILENAGE, OPC-режим), поэтому поля AGSUI
сводятся в столбец `EKI`; зашифрованный ключ соответствует полю KI записи.
Формат файла — «произвольный» согласно ответу отдела ИБ от 02.11.2026.

## Утилиты (`.deploy/scripts/`)

```bash
# 1) одноразово: сохранить сетевой MILENAGE OP в OpenBao
bash .deploy/scripts/network-op-set.sh <32-hex OP>

# 2) создать транспортный ключ для EKI n
bash .deploy/scripts/tk-mgmt.sh create <n>
#    либо импортировать предоставленный поставщиком ключ (файл: 32 hex-символа)
bash .deploy/scripts/tk-mgmt.sh import <n> <файл-ключа>

# 3) симулятор КПХД: сгенерировать строку файла профиля (новый случайный Ki)
bash .deploy/scripts/sim-kpdh.sh --gen <n> <IMSI> [--amf AMF] [--out FILE] [--hmac]
#    либо перешифровать известные ключи (например, миграция plaintext-строки ue.list)
bash .deploy/scripts/sim-kpdh.sh --rekey <n> <IMSI> --ki <32-hex> [--amf AMF] [--out FILE] [--hmac]

# 4) импорт в AUC (fail-closed, идемпотентно)
bash .deploy/scripts/import-profiles.sh <FILE>

# ротация
bash .deploy/scripts/tk-mgmt.sh create <n+1>
bash .deploy/scripts/sim-kpdh.sh --gen <n+1> <IMSI> ...
bash .deploy/scripts/import-profiles.sh <FILE>
bash .deploy/scripts/tk-mgmt.sh revoke <n>     # бэкап TK в .deploy/secrets/revoked/ + удаление из KMS
```

## Менеджер профилей (`.deploy/scripts/profile-mgmt.py`)

Управление **всеми** параметрами абонента в AUC — одиночное и массовое
(на базе open5gs-utils, extended): просмотр, создание, редактирование,
отзыв, удаление, восстановление из бэкапа.

```bash
# просмотр (ключи маскируются) / список
python3 .deploy/scripts/profile-mgmt.py show <imsi>
python3 .deploy/scripts/profile-mgmt.py list

# одиночное: создать (dbctl-база + доп. параметры)
python3 .deploy/scripts/profile-mgmt.py add <imsi> --security-k <32hex> --security-opc <32hex> \
    --msisdn 79991234567 --apn internet --qos 9 --arp best-effort --ambr-d 500M \
    --access-restriction 32 --nam packet --status granted --tau 12
#   (для загрузки КЛЮЧЕЙ через EKI-TK используйте import-profiles.sh)

# одиночное: изменить (только указанные поля; создаёт не умеет)
python3 .deploy/scripts/profile-mgmt.py update <imsi> --ue-ambr 500M --barring "all ps barred"
python3 .deploy/scripts/profile-mgmt.py revoke <imsi>         # subscriber_status=1 (barring)
python3 .deploy/scripts/profile-mgmt.py purge <imsi>          # purge_flag=true
python3 .deploy/scripts/profile-mgmt.py del <imsi>            # удалить (с бэкапом)
python3 .deploy/scripts/profile-mgmt.py restore <backup> [imsi]

# массовое: CSV (шапка + строки; пустая ячейка = не трогать) или JSON
python3 .deploy/scripts/profile-mgmt.py edit <file.csv|file.json> [--dry-run]
```

CSV-шапка: `imsi,msisdn,imeisv,mme_host,mme_realm,apn,apn_type,qos,arp,ambr_d,ambr_u,sst,sd,ue_ambr_d,ue_ambr_u,ue_ambr,access_restriction,nam,status,barring,tau,purge,security_k,security_opc,create`.
JSON — список объектов тех же полей + `sessions` (полная замена slice) и
`security: {k, opc, amf}`. Имена флагов (`best-effort`, `voice`, `granted`,
`all ps barred` и т.п.) — в `--help`. Числа записываются в BSON int32
(ридеры open5gs требуют INT32), перед каждым изменением — бэкап в
`.deploy/backups/` (gitignored, chmod 600 — содержит ключи, хранить как секрет).


## Что можно коммитить

Файлы профилей в этом каталоге безопасно коммитить: в них только
eKi (и опциональный HMAC), без plaintext-ключей. Значения TK существуют **только** в OpenBao
(и в gitignored-каталоге `.deploy/secrets/revoked/` — бэкап при отзыве).
