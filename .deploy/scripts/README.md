# `.deploy/scripts` — эксплуатационные скрипты

Все скрипты запускаются **на хосте Docker** (например, стенд 192.168.0.9)
из каталога `~/open5gs-compose`. Каждый скрипт сам резолвит корень репозитория
(`cd "$(dirname "$0")/../.."`), поэтому путь вызова не важен.

Скрипты делятся на группы:

| Группа | Скрипты |
|---|---|
| EKI-TK: прописка профилей | `tk-mgmt.sh`, `network-op-set.sh`, `sim-kpdh.sh`, `import-profiles.sh`, `lib-bao.sh` |
| Менеджер профилей AUC | `profile-mgmt.py` |
| Деплой и сертификаты | `deploy-encrypted.sh`, `generate-certs.sh`, `generate-mongodb-tls.sh`, `generate-diameter-tls.sh`, `redump-from-backup.sh` |
| Проверка и инспекция | `verify-encrypted-stack.sh`, `inspect-stand.sh` |

Правила:

- `verify-*` и `inspect-*` — **только чтение**, безопасны в любой момент.
- Остальные меняют состояние (KMS, БД, сертификаты) — перед рискованными
  шагами делается бэкап (см. `DISASTER-RECOVERY.md`).
- Секретные значения (TK, OP, мастер-ключ) **никогда не выводятся** скриптами;
  токены KMS читаются из файлов `600` (`.deploy/secrets/` или `local-data`).
- Ключевые потоки описаны в `EKI-TK-ENCRYPTION.md` (архитектура) и
  `PROFILE-LOADING-INSTRUCTIONS.md` (инструкция для ИБ).

## EKI-TK: прописка профилей (транспортный ключ)

Поток: `network-op-set.sh` (раз) → `tk-mgmt.sh` (ключ) → `sim-kpdh.sh`
(файл с eKi) → `import-profiles.sh` (запись в AUC). Формат файла —
`.deploy/profiles/README.md`.

### `lib-bao.sh` — библиотека (source-ится другими)

Чтение секретов из OpenBao (KV v2, TLS, токен из файла 600). Fail-closed:
неизвестный/отозванный EKI, отсутствующий секрет или недоступный KMS →
непустой код выхода. Переменные окружения: `BAO_ADDR` (по умолчанию
`https://127.0.0.1:8200`), `BAO_CA_FILE`, `BAO_TOKEN_FILE` (по умолчанию
`.deploy/secrets/bao-root-token`, иначе копия в `local-data`). Сам по себе
не запускается.

### `tk-mgmt.sh` — жизненный цикл транспортного ключа (TK)

TK хранится в OpenBao: `secret/transport-keys/eki-<EKI>`. Значение ключа
никогда не выводится.

```bash
bash .deploy/scripts/tk-mgmt.sh create <EKI>            # сгенерировать TK (AES-128, 32 hex)
bash .deploy/scripts/tk-mgmt.sh import <EKI> <файл>     # TK, полученный от поставщика (КПХД);
                                                         # файл: 32 hex-символа; существующий EKI не перезаписывается
bash .deploy/scripts/tk-mgmt.sh meta   <EKI>            # метаданные KV (версии; без ключа)
bash .deploy/scripts/tk-mgmt.sh revoke <EKI>            # бэкап TK в .deploy/secrets/revoked/ + удаление из KMS
```

`create` идемпотентен: существующий EKI **не** перегенерируется (старые
файлы профилей перестали бы расшифровываться). `revoke` — последний шаг
ротации (сначала прогрузить файлы с новым EKI).

### `gen-tk-file.sh` — генератор тестового файла TK

Эмулирует «файл ключа от поставщика» для отработки боевого потока `import`:

```bash
bash .deploy/scripts/gen-tk-file.sh /tmp/test-eki-9.key          # 16 случайных байт, mode 600, значение не печатается
bash .deploy/scripts/tk-mgmt.sh import 9 /tmp/test-eki-9.key     # далее штатный поток
bash .deploy/scripts/tk-mgmt.sh revoke 9 && shred -u /tmp/test-eki-9.key
```

Флаг `--show` печатает значение (только для проверки тестовой оснастки);
существующий файл не перезаписывается.

### `network-op-set.sh` — сетевой MILENAGE OP

```bash
bash .deploy/scripts/network-op-set.sh <32-hex OP>
```

Хранит OP сети в `secret/network/milenage-op`. Нужен импортёру для вывода
`OPc = AES128(OP, Ki)` (TS 35.208 Annex C). Повторный запуск создаёт новую
версию KV (старые OPc в AUC остаются валидными до повторного импорта
затронутых абонентов).

### `sim-kpdh.sh` — симулятор КПХД

Генерирует строки загрузочного файла, где ключ зашифрован TK
(`E_KI = AES-128-ECB(TK_EKI, Ki)`, 32 hex). Plaintext Ki в файл, git и логи
не попадает.

```bash
bash .deploy/scripts/sim-kpdh.sh --gen   <EKI> <IMSI> [--amf AMF] [--out FILE] [--hmac]
bash .deploy/scripts/sim-kpdh.sh --rekey <EKI> <IMSI> --ki <32hex> [--amf AMF] [--out FILE] [--hmac]
```

- `--gen` — Ki генерируется из `/dev/urandom` (эмуляция персонализации КПХД);
- `--rekey` — перешифровка известных ключей (миграция plaintext-строки `ue.list`);
- `--out` — файл дописывается (по умолчанию `.deploy/profiles/load.csv`);
- `--hmac` — опциональный 5-й столбец HMAC (функционал под вопросом; по
  умолчанию 4-колоночный файл).

Fail-closed: KMS недоступен или EKI неизвестен — файл не пишется.

### `import-profiles.sh` — импорт файлов профилей в AUC

```bash
bash .deploy/scripts/import-profiles.sh <profiles-file.csv>
```

Построчно: EKI → TK из KMS → (HMAC, если 5-й столбец есть или
`IMPORT_REQUIRE_HMAC=1`) → eKi → Ki → OPc → запись в `subscribers`.
Любая ошибка прерывает импорт целиком (fail-closed, «тихо неверного
состояния» не возникает); повторная прогрузка идемпотентна (replay-safe).
Авто-детект TLS-оверлея до MongoDB (из конфига работающего mongod).
Переменные: `IMPORT_DB_URI` (по умолчанию — из env контейнера `hss`),
`IMPORT_REQUIRE_HMAC` (0/1), `BAO_*` (см. `lib-bao.sh`).

## Менеджер профилей AUC

### `profile-mgmt.py` — все параметры абонента (одиночное и массовое)

На базе `open5gs-utils` (ctrl-imsi-profile.py), расширен. Полный справочник
параметров и форматов массовых файлов — в `.deploy/profiles/README.md`.

```bash
# просмотр
python3 .deploy/scripts/profile-mgmt.py show <imsi>        # профиль; ключи маскируются
python3 .deploy/scripts/profile-mgmt.py list               # таблица всех абонентов

# создание / изменение / жизненный цикл
python3 .deploy/scripts/profile-mgmt.py add <imsi> --security-k <32hex> --security-opc <32hex> [--параметры…]
python3 .deploy/scripts/profile-mgmt.py update <imsi> [--параметры…]   # только указанные поля; создаёт не умеет
python3 .deploy/scripts/profile-mgmt.py revoke <imsi> [--barring …]    # subscriber_status=1
python3 .deploy/scripts/profile-mgmt.py purge  <imsi>                  # purge_flag=true
python3 .deploy/scripts/profile-mgmt.py del    <imsi>                  # удалить (с бэкапом)
python3 .deploy/scripts/profile-mgmt.py restore <backup> [imsi]        # вернуть из бэкапа

# массовое (CSV с шапкой или JSON; пустое поле = не менять)
python3 .deploy/scripts/profile-mgmt.py edit <file.csv|file.json> [--dry-run]
```

Ключевые параметры `add`/`update` (все — в `--help`): `--msisdn` (E.212 BCD),
`--imeisv`, `--mme-host/--mme-realm`, `--apn/--apn-type/--qos/--arp/
--ambr-d/--ambr-u/--sst/--sd` (замена slice), `--ue-ambr[-d/-u]`,
`--access-restriction`, `--nam`, `--status`, `--barring`, `--tau`,
`--purge`, `--security-k/--security-opc/--security-amf` (plaintext-ключи —
с громким предупреждением; для ключей предпочтителен EKI-TK-поток).

Валидные имена: `qos` — 1–9 (или `9,2,1`), `arp` — `best-effort|voice|…`
(или `8,1,2`), `ambr` — `1G|500M`, `status` — `granted|barring`, `nam` —
`packet|reserved|only-packet`, `access-restriction`/`barring` — битмаска
или имена флагов. Числа пишутся BSON int32 (ридеры open5gs требуют INT32).

Безопасность: перед каждым изменением — бэкап в `.deploy/backups/`
(gitignored, `chmod 600`, **содержит ключи**); `--dry-run` показывает план
без записи; неизвестные поля отклоняются (fail-closed).

## Деплой и сертификаты

### `deploy-encrypted.sh` — первичный деплой PSMDB + OpenBao

Запускается на сервере **один раз** при миграции с plain-MongoDB:
генерация TLS OpenBao → дамп старых данных → остановка стека →
ре-инициализация OpenBao (новый KV v2 + мастер-ключ) → PSMDB с
data-at-rest → восстановление дампа → старт стека → верификация.
**Внимание:** пересоздаёт состояние OpenBao (см. заголовок скрипта).
Подробности — `PSMDB-ENCRYPTION.md`.

### `generate-certs.sh` — TLS для OpenBao

CA + server-сертификат (`.deploy/docker/openbao/tls/`, gitignored);
монтируются в контейнеры `openbao` и `mongodb`.

### `generate-mongodb-tls.sh` — TLS для MongoDB (requireTLS)

CA + leaf (`SAN: mongodb, 127.0.0.1`) в `.deploy/docker/mongodb-tls/`:
`ca.crt` (публичная, в git), `server.crt/key`, `server.pem` (gitignored).
Используется оверлеем `docker-compose.dbtls.yaml`.

### `generate-diameter-tls.sh` — TLS-материал Diameter

Регенерация CA + leaf-сертификатов hss/mme/pcrf/smf
(`.deploy/docker/diameter/`). Приватные ключи gitignored; файлы
**обязаны существовать** — freeDiameter читает `TLS_Cred` при парсинге
конфига (сама S6a по-прежнему `No_TLS`, TLS-подключение — P2).

### `redump-from-backup.sh` — одноразовый helper

Создание миграционного дампа из backed-up plain-каталога MongoDB
временным контейнером mongod (после утери исходного дампа).
`bash .deploy/scripts/redump-from-backup.sh [backup-dir-name]`.

## Проверка и инспекция

### `verify-encrypted-stack.sh` — верификация развёртывания (только чтение)

```bash
bash .deploy/scripts/verify-encrypted-stack.sh
```

Секции: 0 — режим TLS-оверлея до БД (авто-детект); 1 — статус контейнеров;
2–3 — БД и коллекции (число subscribers); 4 — data-at-rest PSMDB
(«Master encryption key has been read…», версия ключа); 5 — TLS до OpenBao;
6 — читаемость мастер-ключа (значение не печатается); 7 — отсутствие
plaintext-IMSI в `/data/db`; 8 — webui (bootstrap + HTTP 200); 9 — TK по EKI
(только метаданные); 10 — файлы профилей. Переменные: `IMSI_PATTERN`,
`BAO_ADDR`, `WEBUI_URL`.

### `inspect-stand.sh` — инспекция фактического состояния

Где физически лежат данные mongodb/openbao (volumes, каталоги), версии,
ключевые пути — для подготовки пересоздания контейнеров. Только чтение.
