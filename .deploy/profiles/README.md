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
IMSI,EKI,E_KI,E_OPC,AMF[,HMAC]
999990000000101,1,<32 hex>,<32 hex>,8000
```

Старый формат `IMSI,EKI,E_KI,AMF[,HMAC]` (без `E_OPC`) принимается без
изменений: разбор — по числу столбцов и длине 4-го (32 hex → `E_OPC`,
1–4 hex → `AMF`, иначе — ошибка).

Готовые образцы (все строки данных закомментированы — безопасны для
запуска «в лоб»): `example-load-file.csv` (для `import-profiles.sh`) и
`example-mgmt-edit.csv` (для `profile-mgmt.py edit`).

| Столбец | Значение |
|---|---|
| `IMSI` | 14–15 десятичных цифр |
| `EKI` | Индекс/версия транспортного ключа (целое > 0). Сам TK лежит в OpenBao по пути `secret/transport-keys/eki-<EKI>` и **никогда** не попадает в этот файл. |
| `E_KI` | `AES-128-ECB(TK_EKI, Ki)`, 32 hex. Ki — ровно 16 байт (без padding). |
| `E_OPC` *(опционально)* | `AES-128-ECB(TK_EKI, OPc)`, 32 hex — **тот же TK**, что и для Ki (связка «EKI ↔ OPc»). OPc предоставляет КПХД (он записывает его на UICC). При наличии — импортёр сохраняет переданный OPc; при отсутствии — сеть выводит `OPc = AES128(OP, Ki)` (TS 35.208 Annex C) из OP сети в KMS и печатает предупреждение по строке. |
| `AMF` | 5G-поле AMF, записывается в `security.amf` (по умолчанию `8000` — конвенция стека) |
| `HMAC` *(опционально, функционал под вопросом)* | Если столбец присутствует (последний), импортёр проверяет `HMAC-SHA256(HK, "IMSI/EKI/E_KI[/E_OPC]/AMF")` по фактически присутствующим столбцам (64 hex, `HK = SHA256(TK_EKI + "pLTE-inBOX-EKI-MAC")`). Контроль целостности: сам ECB не аутентифицирован. Включение: `sim-kpdh.sh --hmac` (генерация), `IMPORT_REQUIRE_HMAC=1` (обязательный режим импортёра). |

OPc в файл включается **опционально**, в зашифрованном виде (`E_OPC`): если
КПХД не передаёт E_OPC, сеть выводит `OPc = AES128(OP, Ki)` из своего сетевого OP
(3GPP TS 35.208 Annex C, MILENAGE) с предупреждением по строке.

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
#    (тестовый файл ключа для отработки потока: bash .deploy/scripts/gen-tk-file.sh <файл>)

# 3) симулятор КПХД: сгенерировать строку файла профиля (новый случайный Ki)
bash .deploy/scripts/sim-kpdh.sh --gen <n> <IMSI> [--amf AMF] [--out FILE] [--hmac] [--opc <32hex>|--opc-derive]
#    либо перешифровать известные ключи (например, миграция plaintext-строки ue.list)
bash .deploy/scripts/sim-kpdh.sh --rekey <n> <IMSI> --ki <32-hex> [--amf AMF] [--out FILE] [--hmac] [--opc <32hex>|--opc-derive]
#    --opc — OPc от «КПХД» (в файл уходит E_OPC); --opc-derive — OPc = AES128(OP_сети, Ki) из KMS

# 4) импорт в AUC (fail-closed, идемпотентно)
bash .deploy/scripts/import-profiles.sh <FILE>

# ротация
bash .deploy/scripts/tk-mgmt.sh create <n+1>
bash .deploy/scripts/sim-kpdh.sh --gen <n+1> <IMSI> ...
bash .deploy/scripts/import-profiles.sh <FILE>
bash .deploy/scripts/tk-mgmt.sh revoke <n>     # бэкап TK в .deploy/secrets/revoked/ + удаление из KMS
```

## Менеджер профилей (`.deploy/scripts/profile-mgmt.py`, v2)

Управление **всеми** параметрами абонента в AUC — одиночное и массовое:
несколько APN на абонента (до 4 сессий на slice, до 8 slice — лимиты
open5gs), **статический IP на каждый APN** (`session.ue.ipv4/ipv6`),
просмотр, создание, отзыв, удаление, восстановление.

```bash
# просмотр (ключи маскируются) / список (APN + статический IP)
python3 .deploy/scripts/profile-mgmt.py show <imsi>
python3 .deploy/scripts/profile-mgmt.py list

# одиночное: создать (dbctl-база + доп. параметры)
python3 .deploy/scripts/profile-mgmt.py add <imsi> --security-k <32hex> --security-opc <32hex> \
    --apn internet --qos 9 --ambr-d 500M --ipv4 10.167.71.200
#   (для загрузки КЛЮЧЕЙ через EKI-TK используйте import-profiles.sh)

# одиночное: изменить (только указанные поля; сессию upsert'ит по имени APN)
python3 .deploy/scripts/profile-mgmt.py update <imsi> --apn voip --apn-type dedicated --qos 5
python3 .deploy/scripts/profile-mgmt.py update <imsi> --apn internet --ipv4 ""   # снять статический IP
python3 .deploy/scripts/profile-mgmt.py revoke <imsi>         # subscriber_status=1 (barring)
python3 .deploy/scripts/profile-mgmt.py purge <imsi>          # purge_flag=true
python3 .deploy/scripts/profile-mgmt.py del <imsi>
python3 .deploy/scripts/profile-mgmt.py delete-all [--dry-run] [--yes] [--backup]  # стереть ВСЕХ
python3 .deploy/scripts/profile-mgmt.py restore <backup> [imsi]

# массовое: KV / CSV / JSON (автоопределение), двухфазно
python3 .deploy/scripts/profile-mgmt.py edit <file> [--dry-run] [--backup]
```

**Массовые форматы `edit` (автоопределение):**

1. **KV (рекомендуемый)** — только нужные поля; строка = «пакет изменений»:

   ```
   # одна строка = одна пачка изменений; не указанное не трогается
   imsi=999990000000101, apn=internet, qos=9, ambr_d=500M, ipv4=10.167.71.200
   imsi=999990000000101, apn=voip, apn_type=dedicated, qos=5, sst=1, sd=201111
   imsi=999990000000102, msisdn=79990000000102
   imsi=999990000000102, ipv4=                # пустое значение = ОЧИСТИТЬ
   ```

   - Несколько строк с одним IMSI **сливаются** (аддитивно); позже
     записанное поле побеждает.
   - Строка с `apn=` (или `qos`/`arp`/`ambr_d`/`ambr_u`/`ipv4`/`ipv6`)
     **upsert'ит одну сессию** в slice `(sst, sd)` (по умолчанию
     `1/ffffff`): сессия с тем же именем обновляется, новая добавляется;
     **остальные сессии и slice не трогается** (лимиты: 4 сессии/slice,
     8 slice — open5gs `OGS_MAX_NUM_OF_SESS`/`OGS_MAX_NUM_OF_SLICE`).
   - Значения с запятыми — в кавычках: `"arp=8,1,2"`.
   - Очистка пустым значением: `msisdn`, `imeisv`, `mme_host`,
     `mme_realm`, `ipv4`, `ipv6`.
2. **CSV** — позиционная таблица (шапка обязательна, первая колонка
   `imsi`), пустая ячейка = не трогать; повторяющиеся строки IMSI
   сливаются так же, как в KV. Очистка полей в CSV невозможна — KV/JSON.
3. **JSON** — список объектов тех же полей; `""` = очистить,
   `null`/отсутствует = не трогать; явный `sessions: [...]` — **полная
   замена slice** (не совместим с апсерт-строками в том же объекте);
   объект сессии принимает `ipv4`/`ipv6`.

`edit` **двухфазный**: фаза 1 — разбор и валидация всего файла
(форматы, лимиты, симуляция слияния) **до первой записи**; любая ошибка
прерывает файл целиком, в БД ничего не пишется. Фаза 2 — применение.
`--dry-run` = только фаза 1.

**Бэкап — по явному флагу `--backup`** (не по умолчанию): файл
`.deploy/backups/profile-mgmt-<ts>.json` (gitignored, chmod 600)
содержит **plaintext-ключи** — хранить как секрет, не выносить за
доверенный хост. Без `--backup` откат — повторной прогрузкой прежних
значений или из собственного дампа.

Справочник полей (в т.ч. `sst`/`sd`, `qos` «index» или
«index,pri,cap», `arp` по имени или «pri,cap,vuln», маски
`access_restriction`/`barring` по именам флагов, `ipv4`
`a.b.c.d[/32]`, `ipv6` `2001:db8::1[/128]`) — `profile-mgmt.py --help`
и `.deploy/scripts/README.md`. Числа записываются в BSON int32
(ридеры open5gs требуют INT32; `pre_emption_capability` — только 1/2,
иначе UDR падает по assert при чтении SM context).

Образцы (все строки данных закомментированы): `example-mgmt-edit.kv`
(основной), `example-mgmt-edit.csv`, `example-load-file.csv`
(для `import-profiles.sh`).


## Что можно коммитить

Файлы профилей в этом каталоге безопасно коммитить: в них только
eKi (и опциональный HMAC), без plaintext-ключей. Значения TK существуют **только** в OpenBao
(и в gitignored-каталоге `.deploy/secrets/revoked/` — бэкап при отзыве).
