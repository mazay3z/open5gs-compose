# Принудительное завершение UE-сессий при переключении Active/Standby — план реализации

> **Тип документа:** технический план (дизайн-документ + план проверки).
> **Статус:** на согласовании. Реализация — после утверждения (Act mode).
> **Владелец:** open5gs-compose / pLTE in Box.
> **Связанные документы:** [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md), [DISASTER-RECOVERY-OVERVIEW.md](DISASTER-RECOVERY-OVERVIEW.md), `docker-compose.yaml`, `docker-compose.override.yaml`, `.env`.

## 1. Назначение и постановка задачи

**Проблема.** В двухузловой топологии (Node A — Active, Node B — Standby; Keepalived + VIP; на каждом узле свой стек Open5GS в Docker Compose — «Вариант Б») при переключении сервиса на Standby-хост PDU-сессии/беры, «заякоренные» на UPF/PGW-U узла A, остаются «висящими»: в Open5GS нет встроенной команды «оборвать сессию UE по команде». Необходимо принудительно завершать UE-сессии со стороны сети, чтобы gNB/UE переустановили их на новом узле — и при плановом переключении (drain), и после отказа узла A.

**Требования.**

- Не патчить исходники Open5GS (использовать образ `docker.io/gradiant/open5gs:2.7.7` как есть).
- Использовать только штатные интерфейсы: SBI, PFCP, NAS через gNB, CLI эмуляторов (UERANSIM `nr-cli`), REST API eUPF, MongoDB.
- Механизм инициируется со стороны сети (не требует действий на каждом UE).
- Минимум изменений в существующей инфраструктуре Docker Compose.

**Не входит в задачу.** Разработка нового сетевого элемента; модификация 3GPP-процедур; репликация состояния сессий между узлами (осознанно исключена архитектурой — см. DISASTER-RECOVERY-OVERVIEW.md §2, «active-active без репликации состояния сессий»).

## 2. Исходное состояние стенда (факты из репозитория)

| Компонент | Факт | Где посмотреть |
|---|---|---|
| Ядро 5G | Open5GS 2.7.7 (gradiant): NRF/AMF/SMF/UPF; профили `4g-core,5g-core,monitoring` | `docker-compose.yaml`, `.env` |
| Ядро 4G | MME/HSS/PCRF/SGWC (SGWU отключён: `sleep infinity`) | `docker-compose.override.yaml` |
| Пользовательский план | **eUPF** `ghcr.io/edgecomllc/eupf-dev:feat-combined-dataplane` (полностью заменяет `open5gs-upfd`): REST API `:8081` (healthcheck стека уже его использует), метрики `:9091` | `docker-compose.override.yaml` |
| RAN-эмуляция | UERANSIM 3.2.6: сервисы `gnb`, `ue` (профиль `5g-ran`, **не** входит в `COMPOSE_PROFILES` по умолчанию); healthcheck gnb сам вызывает `nr-cli` | `docker-compose.yaml` |
| БД | MongoDB 5.0.10 / PSMDB 5.0 (encryption overlay); `mongod.conf` **без replica set** → change streams невозможны | `docker-compose.encryption.yaml`, `.deploy/docker/psmdb/mongod.conf` |
| Абоненты | Сервис `populate` (open5gs-dbctl) загружает 3 IMSI из `.deploy/docker/ue.list` | `docker-compose.yaml` |
| Таймеры AMF | `t3512 = 540` (периодическая регистрация UE — 9 минут) | `.deploy/docker/amf.yaml` |
| Мониторинг | Prometheus скрейпит `mme/amf/smf/pcf:9090`, `upf:9091`; Grafana с дашбордами | `.deploy/docker/monitoring/prometheus/prometheus.yml` |
| Конвенции | Скрипты стенда — bash, LF, живут в `.deploy/scripts/`; доставка с Windows — `deploy-from-windows.ps1` (LF-нормализация → scp → один ssh) | `.deploy/scripts/` |

**Ключевое следствие для DR-сценария:** состояние сессий не реплицируется; отказ/переключение узла = re-attach абонентов на живом узле. Задача настоящего механизма — сделать этот re-attach **управляемым и быстрым** (секунды), а не ждать таймеров UE (минуты — десятки минут).

## 3. Штатные механизмы завершения сессии в Open5GS 2.7.7 (анализ по исходникам v2.7.7)

### 3.1 Сводная таблица

| # | Механизм | Внешний триггер | Задействованные компоненты | Удаляет сессию в UPF? |
|---|---|---|---|---|
| 1 | UE-Initiated Deregistration (NAS, TS 24.501 §5.5.2) | UERANSIM: `nr-cli imsi-<IMSI> -e deregister` | UE → gNB → AMF → UDM/PCF/SMF → PFCP → eUPF | **Да** — полностью и штатно |
| 2 | UE-Initiated PDU Session Release (NAS 5GSM) | `nr-cli imsi-<IMSI> -e ps-release-all` | UE → AMF → SMF → PFCP → eUPF | **Да** (UE остаётся REGISTERED) |
| 3 | AN Release / NGAP UE Context Release | `nr-cli UERANSIM-gnb-999-99-16 -e ue-release <ue-id>`; реальный gNB — сам при сбое RRC/SCTP | gNB ↔ AMF (N2), RRC Release | **Нет** — освобождается только N2/RRC, UE → CM-IDLE, PFCP-сессия остаётся |
| 4 | Network-Initiated (Implicit) Deregistration | Недоступность UE (обрыв RRC/N2) + ожидание таймеров AMF (~17 мин при `t3512=540`) | AMF (таймеры) → UDM → SMF → PFCP → eUPF | **Да** — но медленно; работает с реальным RAN |
| 5 | AMF SBI (namf-comm / namf-oam / namf-evex) | — (триггера нет) | — | **Нет** внешней операции «release/deregister UE» |
| 6 | UDM/UDR-уведомления (5G) | — (триггера нет) | — | **Нет**: в 2.7.7 UDR/UDM не следят за БД |
| 7 | HSS Cancel Location (4G, S6a CLR) через MongoDB change stream | `db.subscribers.updateOne({imsi:"..."},{$set:{request_cancel_location:true}})` | MongoDB → HSS → MME (Detach) → SGWC/SMF → PFCP → eUPF | **Да** — полностью; работает с реальным eNB. ⚠️ требует replica set |
| 8 | eUPF REST API (не 3GPP; штатный интерфейс UPF) | `DELETE :8081/api/v1/pfcp_sessions?imsi=...` | eUPF напрямую | **Да, только в дата-плейне** — SMF не уведомляется |

### 3.2 UE-Initiated Deregistration (5G) — рекомендуемый основной путь для эмуляции

UE посылает NAS Deregistration Request → gNB (N2) → AMF. В Open5GS 2.7.7 это единственный путь, который штатно проходит **полную** цепочку очистки (виден в комментариях к коду `src/amf/gmm-sm.c`):

```
UDM_SDM_Unsubscribe → UDM_UECM_Deregistration → AM_Policy_Termination
→ Nsmf_PDUSession_ReleaseSMContext (по каждой сессии)
→ UEContextReleaseCommand/Complete (к gNB)
```

SMF по ReleaseSMContext отправляет **PFCP Session Deletion Request** в eUPF → удаляются PDR/FAR/QER, освобождаются TEID и UE-IP.

- **Внешний триггер:** `docker compose exec -T ue nr-cli imsi-<IMSI> -e deregister`.
- **Результат:** UE → RM-DEREGISTERED; сессий в SMF/eUPF нет. UERANSIM-UE после этого может зарегистрироваться заново (на новом узле — после переноса VIP).
- **Ограничение:** применимо только к эмулируемым UE (UERANSIM).

### 3.3 UE-Initiated PDU Session Release (5G) — «мягкий» вариант

`nr-cli imsi-<IMSI> -e ps-release-all` (или `ps-release <psi>` для конкретной сессии) — NAS PDU Session Release Request → SMF → PFCP Session Deletion → eUPF. UE **остаётся REGISTERED**. Полезно, когда нужно только «снять якорь» сессий с узла A: после переноса VIP новая сессия установится на узле B по Service Request / `ps-establish` без полной перерегистрации.

### 3.4 AN Release / NGAP UE Context Release (5G) — недостаточно, но полезно

gNB → AMF: UE CONTEXT RELEASE REQUEST (в UERANSIM — команда `nr-cli <имя-gnb> -e ue-release <ue-id>`, cause=`RadioNetwork_unspecified`; проверено по `src/gnb/app/cmd_handler.cpp`). AMF отвечает UEContextReleaseCommand, gNB делает RRC Release, UE → CM-IDLE. **SM-контексты и PFCP-сессии в UPF сохраняются** (N3 активен). Само по себе задачу не решает; пригодится как «подталкивание» UE к Service Request после переключения.

### 3.5 Network-Initiated (Implicit) Deregistration (5G) — пассивная страховка

AMF-таймеры: mobile reachable (≈ `t3512` + 240 с) → implicit deregistration (≈ ещё +240 с; значения по умолчанию 2.7.x — точные подтвердить по логам AMF на учениях). При текущем `t3512: 540` полный цикл ≈ **17 минут** с момента недоступности UE. По исходнику `gmm-sm.c` путь `AMF_NETWORK_INITIATED_IMPLICIT_DE_REGISTERED` действительно освобождает сессии: `Implicit Timer Expiration → UDM_SDM_Unsubscribe → UDM_UECM_Deregistration → PDU session release → …`.

- **Внешний триггер:** сделать UE недоступным (остановить gNB-контейнер, сбросить SCTP-ассоциацию N2) и ждать таймеров.
- **Работает с реальным RAN** (gNB при потере SCTP-ассоциации сам освобождает UE).
- **Управляемая настройка:** уменьшение `t3512` в `.deploy/docker/amf.yaml` (например, до 120–180 с) сокращает окно пере-регистрации IDLE-UE ценой периодических Registration Update.

### 3.6 AMF SBI (Namf_Communication / Namf_OAM / Namf_EventExposure) — внешнего триггера НЕТ

Проверено по исходникам v2.7.7 (`src/amf/amf-sm.c`, `src/amf/namf-oam.h`):

- `namf-comm`: N1N2MessageTransfer, UEContextTransfer, RegistrationStatusUpdate — потребители SMF/SMSF; операции «release UE context / deregister UE» **отсутствуют**.
- `namf-oam` (кастомный API): только CRUD PLMN/slices (добавлен для WebUI).
- `namf-evex`: подписки на события — это уведомления, а не действия.

Теоретический хак — `POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages` с самодельным N1-NAS (PDU Session Release Command): недокументировано, требует корректного PTI/синхронизации с SM-контекстом, AMF ожидает транзакцию от SMF. **Не рекомендуется** (хрупко и не поддерживается).

### 3.7 UDM/UDR (5G) — уведомлений об изменении данных абонента нет

В 2.7.7 у UDR и UDM **нет** watcher'а MongoDB (проверено: `src/udr/udr-sm.c`, `src/udm/`) — аналога HSS-CLR (см. 3.8) для 5G не существует. Удаление/изменение абонента в БД никак не влияет на активные 5G-сессии.

### 3.8 HSS Cancel Location (4G, S6a CLR) через MongoDB change stream — единственный сетевой detach-триггер в стеке

В `src/hss/hss-context.c` (v2.7.7) HSS держит **change stream** на коллекции `subscribers`; `hss_handle_change_event()` парсит `updateDescription.updatedFields.request_cancel_location: true` → выставляет `send_clr_flag` → HSS отправляет **Cancel-Location-Request (CLR)** в MME. MME выполняет detach (Detach Request к UE через S1AP; при недоступном eNB — локальная очистка) → Delete Session/Bearer → SGWC/SMF → **PFCP Session Deletion** → eUPF. Абонент в БД **остаётся** → пере-attach на другом узле возможен.

- **Внешний триггер (mongo-shell):**
  ```bash
  docker compose exec -T mongodb mongo --quiet open5gs --eval \
    'db.subscribers.updateOne({imsi:"999990000000001"},{$set:{request_cancel_location:true}})'
  ```
- ⚠️ **Предусловие:** MongoDB должна работать в **replica set** (change streams не поддерживаются standalone-сервером). В текущем `.deploy/docker/psmdb/mongod.conf` секции `replication:` **нет** → на стенде механизм сейчас не работает. Требуется: добавить `replSetName` + однократный `rs.initiate()` (см. §6.2).
- **Идемпотентность:** повторное «включение» уже включённого флага не создаёт change-событие → скрипт перед повторным запуском должен выставить `false`, затем `true`.

### 3.9 eUPF REST API — точечная очистка пользовательского плана

Документация eUPF (`docs/api.md`, основная ветка): `GET /api/v1/health`, `GET|DELETE /api/v1/pfcp_sessions` (фильтры `?imsi=…&teid=…&msisdn=…`), `GET /api/v1/pfcp_associations[/full|/release]`, `GET|POST|DELETE /api/v1/subscriber_trace`, Swagger UI на `/swagger/index.html`.

- `DELETE /api/v1/pfcp_sessions?imsi=...` удаляет PFCP-сессию **только в eUPF** — SMF остаётся в неведении (десинхронизация состояний).
- Назначение: инвентаризация/верификация + «мусорная уборка» узла, который уже не обслуживает трафик (вывод из Active, восстановление после отказа).
- ⚠️ В dev-образе `feat-combined-dataplane` пути могут отличаться от основной ветки (v0.6.x использовали `/api/v1/sessions`, `/api/v1/session/{seid}`) → скрипт обязан пробовать оба варианта (см. §6.1).

### 3.10 Почему НЕ «open5gs-dbctl remove / удалить абонента»

Распространённое заблуждение, опровергнутое исходниками:

- HSS 2.7.7 обрабатывает только **update**-события change stream (требуется `fullDocument`); **delete**-события не триггерят CLR.
- AMF/SMF вообще не следят за БД → активные сессии не рвутся.
- Удаление абонента ломает re-attach (UE неизвестен) до возврата записи в БД.

**Вывод:** правильный триггер — `update` с `request_cancel_location: true`; абонента из БД **не удалять**.

## 4. Варианты реализации

### 4.1 Вариант A — «сигнальный» (через ядро сети: AMF SBI / HSS CLR)

**5G.** Прямого SBI-триггера нет (§3.6) → единственный сетевой путь — Implicit Deregistration: оборвать N2 (остановить gNB / сброс SCTP) и ждать таймеров (~17 мин при текущем `t3512`). Ускоряется уменьшением `t3512` в `.deploy/docker/amf.yaml` ценой периодических Registration Update.

**4G.** CLR-триггер через MongoDB change stream (§3.8) — единственный управляемый сетевой механизм, работает с реальным eNB.

**Затрагиваемые файлы/сервисы:**

- сервисы: `mongodb`, `hss`, `mme`, `sgwc`, `smf`, `upf` (eUPF);
- конфигурация (для 4G-ветки): `.deploy/docker/psmdb/mongod.conf` (+ `replication: replSetName: rs0` и разовый `rs.initiate()`);
- опционально: `.deploy/docker/amf.yaml` (сокращение `t3512`).

**Ключевая команда** — mongo-триггер CLR (см. §3.8).

**Риски варианта A:**

1. **MongoDB не в replica set** → change stream молча не работает (сейчас это так). Включение RS на PSMDB с шифрованием поддерживается, но требует рестарта mongod и проверки на стенде (в dbPath появится oplog). Это единственное инфраструктурное изменение варианта.
2. Управляемого 5G-механизма нет вообще — только пассивные таймеры (минуты) и регламентное ускорение через `t3512`.
3. Гонка при плановом переключении: UE после detach немедленно пере-attach'нется на тот же (ещё Active) узел, если VIP ещё не переехал — нужен правильный порядок операций (см. §7, шаг 5).

### 4.2 Вариант B — «скрипт-оркестратор» (внешние инструменты) — РЕКОМЕНДУЕМЫЙ

Один bash-скрипт `.deploy/scripts/ue-session-release.sh` в конвенциях проекта (bash, LF, запуск на стенде; compose-цепочка как в `inspect-stand.sh`: `-f docker-compose.yaml -f docker-compose.override.yaml -f docker-compose.encryption.yaml`). Режимы:

1. **`5g-dereg`** — полный teardown 5G-сессий через UERANSIM (для планового переключения на Active-узле):
   ```bash
   docker compose exec -T ue nr-cli imsi-999990000000001 -e deregister
   ```
   IMSI-лист — из `.deploy/docker/ue.list` (единый источник, тот же, что у `populate`); при нескольких контейнерах `ue` (`--scale ue=N`) — итерация по `docker compose ps -q ue`.
2. **`5g-psrelease`** — «мягкий» вариант: `nr-cli imsi-<IMSI> -e ps-release-all` (снять только сессии, UE остаётся REGISTERED).
3. **`4g-clr`** — CLR-триггер через MongoDB для 4G-абонентов (сетевой путь из варианта A; работает и с реальным eNB/srsRAN).
4. **`eupf-list` / `eupf-clean`** — инвентаризация и удаление PFCP-сессий eUPF через REST API (для узла, выводимого из работы, и для верификации):
   ```bash
   docker compose exec -T upf-init curl -s http://localhost:8081/api/v1/pfcp_sessions
   docker compose exec -T upf-init curl -s -X DELETE 'http://localhost:8081/api/v1/pfcp_sessions?imsi=999990000000001'
   ```
   (curl уже есть в `upf-init` — netshoot в host-сети; порт 8081 опубликован и на хосте.)
5. **`verify`** — снапшот состояния до/после (eUPF-сессии по IMSI, метрики, хвост логов SMF/AMF) — см. §7.

**Затрагиваемые файлы/сервисы:** только **новый** скрипт (+ опционально раздел в DISASTER-RECOVERY.md). Скрипт работает с существующими контейнерами (`ue`, `gnb`, `mongodb`, `upf-init`); compose-файлы не меняются. Для 4G-ветки — то же предусловие с replica set, что и в вариане A.

**Риски варианта B:**

1. `nr-cli` на время команды ставит на паузу задачи UE (nas/rrc/rls; механизм паузы в исходниках UERANSIM) — контрольный стоп на ~секунды, для лаборатории некритично.
2. После `deregister` UE уходит в RM-DEREGISTERED (в зависимости от опции UERANSIM может «выключиться») — возврат в service на новом узле требует `ps-establish` или рестарта контейнера `ue` (в отказном сценарии UE и так пере-регистрируются после потери gNB/AMF).
3. Эндпоинты dev-образа eUPF (`feat-combined-dataplane`) могут отличаться от основной ветки — скрипт на первом запуске пробует варианты + Swagger UI.
4. `eupf-clean` не уведомляет SMF — применять только к узлу, который уже не обслуживает трафик, либо затем рестартовать SMF этого узла.
5. Если профиль `5g-ran` не включён (текущий `COMPOSE_PROFILES=4g-core,5g-core,monitoring`), nr-cli-ветка неприменима — остаются `4g-clr` и пассивные таймеры.

## 5. Выбор и обоснование

**Выбран Вариант B, включающий CLR-механизм из варианта A (режим `4g-clr`).**

| Критерий | A | B |
|---|---|---|
| Покрытие 4G + 5G | 5G нет (только таймеры) | **Да**: nr-cli (5G) + CLR (4G) + eUPF API |
| Скорость | минуты (таймеры) | **секунды** (полная сигнальная цепочка) |
| Изменения инфраструктуры | mongod.conf + rs.initiate | **один новый скрипт** (+ те же опции RS для 4G-ветки) |
| Патчи Open5GS | нет | нет |
| Детерминизм/проверяемость | слабый (таймеры) | **высокий**: каждый шаг проверяется через eUPF API/логи/метрики |
| Применимость к реальному RAN | 4G — да (CLR); 5G — только таймеры | 4G — да (CLR); 5G — таймеры (задокументировано как ограничение) |

Почему не A в чистом виде: у A отсутствует управляемый 5G-механизм — а 5G-часть стека (AMF/SMF/eUPF) в данном проекте основная. Почему B безопасен: все зависимости локальны узлу (нет кросс-узловых вызовов в момент аварии), каждый режим — обёртка над штатными интерфейсами, уже присутствующими в стеке (nr-cli используется healthcheck'ом gnb, eUPF API — healthcheck'ом upf, ue.list — сервисом populate).

## 6. Состав работ в Act mode (deliverables)

### 6.1 Скрипт `.deploy/scripts/ue-session-release.sh` (основной артефакт)

Каркас использования (детали реализации — при переходе в Act mode):

```
Usage: ue-session-release.sh <mode> [options]

Режимы:
  5g-dereg       UE-initiated deregistration всех 5G UE (nr-cli deregister)
  5g-psrelease   только PDU Session Release (nr-cli ps-release-all), UE остаётся registered
  4g-clr         HSS Cancel Location через request_cancel_location в MongoDB
  eupf-list      список PFCP-сессий eUPF (инвентаризация)
  eupf-clean     удаление PFCP-сессий через REST API eUPF (узел вне трафика!)
  verify         снапшот: eUPF-сессии по IMSI, статус UE/gNB (nr-cli), логи AMF/SMF/HSS

Опции:
  --imsi all|<IMSI[,IMSI...]>   выбор абонентов (default: all из .deploy/docker/ue.list)
  --dry-run                     только показать, что будет сделано
  --eupf-api <url>              переопределить адрес API eUPF (default: http://localhost:8081)
```

Требования к реализации: авто-детект путей eUPF API (`/api/v1/pfcp_sessions` ↔ `/api/v1/sessions`); детект mongo-shell (`mongosh` || `mongo`); для `4g-clr` — сброс флага `false`→`true` (идемпотентность); `--dry-run` по умолчанию для `eupf-clean`-подобных разрушительных действий требует явного `--yes`; вывод машиночитаемого отчёта (до/после по каждому IMSI).

### 6.2 (Опционально, для режима `4g-clr`) включение replica set в MongoDB

- Правка `.deploy/docker/psmdb/mongod.conf`: добавить `replication: { replSetName: rs0 }` (и аналогично для нешифрованного варианта, если используется `mongo:5.0.10`).
- Разовый шаг после рестарта mongod: `rs.initiate()` (однократно; детект в скрипте: `rs.status()`).
- Проверить, что HSS начал читать change stream (в логах `hss` появятся записи о change-событиях), и что шифрование/KMS не пострадало.
- Откат: убрать `replSetName`, перезапустить mongod (oplog в dbPath остаётся — вреда нет).

### 6.3 (Опционально) Документирование в DISASTER-RECOVERY.md

Новый раздел «Принудительное завершение UE-сессий при переключении Active/Standby» с порядком операций: drain на Active (`5g-dereg`/`4g-clr`) → перенос VIP → контроль пере-регистрации на Standby → `eupf-clean` старого узла.

### 6.4 Доставка на стенд

Добавить новый скрипт в `$Files` в `.deploy/scripts/deploy-from-windows.ps1` (существующий паттерн LF-нормализация → scp → ssh).

## 7. Пошаговый план проверки (на стенде)

**Шаг 0 — подготовка/калибровка.**
- Включить `5g-ran` профиль (`COMPOSE_PROFILES=4g-core,5g-core,5g-ran,monitoring`), поднять стек, дождаться healthcheck gnb: `nr-cli UERANSIM-gnb-999-99-16 -e status` → `is-ngap-up: true`.
- Убедиться в регистрации UE: `nr-cli imsi-999990000000001 -e status` / `-e ps-list`.
- Проба eUPF API: `curl -s localhost:8081/api/v1/health`; `GET .../pfcp_sessions` (при 404 — `/api/v1/sessions`, Swagger `/swagger/index.html`).
- `docker compose exec -T mongodb mongo --quiet --eval 'rs.status()'` — если RS нет, зафиксировать: `4g-clr` будет пропущен (или включить RS по §6.2).

**Шаг 1 — базлайн.** Зафиксировать: список PFCP-сессий (`GET /api/v1/pfcp_sessions` — SEID/TEID/UE-IP по каждому IMSI), `docker compose logs --tail=50 smf amf`, метрики `smf:9090/metrics`, `amf:9090/metrics`, `upf:9091/metrics` (Prometheus/Grafana), ping с UE.

**Шаг 2 — 5G (nr-cli).** `ue-session-release.sh 5g-dereg --imsi all`, затем по очереди убедиться:
- UE: лог `De-registration accept`; `nr-cli imsi-... -e status` → `rm-state: RM-DEREGISTERED`;
- AMF (лог): Deregistration Request/Accept, удаление контекста UE;
- SMF (лог): `PDU session release`, исходящий **PFCP Session Deletion Request** и Response;
- **eUPF: `GET /api/v1/pfcp_sessions` — сессии по обработанным IMSI исчезли (ключевой критерий)**;
- ping с UE остановился; счётчики сессий в метриках упали.

**Шаг 3 — 4G (CLR).** При зарегистрированном 4G-UE (srsRAN): выполнить `ue-session-release.sh 4g-clr --imsi all` → проверить: HSS-лог (отправка CLR; метрика `s6a_tx_clr` в `hss:9090/metrics`), MME-лог (Detach Request/.Accept), SGWC/SMF (Delete Session), eUPF — сессия исчезла; UE пере-attach'нулся (если RAN доступен).

**Шаг 4 — eUPF API (eupf-clean).** Создать «висящую» сессию (например, остановить `smf` до teardown) → `DELETE /api/v1/pfcp_sessions?imsi=...` → сессия исчезла из eUPF; зафиксировать кейвэт: SMF о ней не знает (в документации).

**Шаг 5 — учения по основному сценарию.**
- *Плановое переключение:* на Node A — `5g-dereg`/`4g-clr` (drain) → перенос VIP (keepalived) → контроль пере-регистрации UE на Node B (логи AMF-B; `pfcp_sessions` eUPF-B; для статических IP — совпадение адреса) → на Node A — `eupf-clean` → итог: на A — 0 сессий, на B — полный набор.
- *Отказное переключение:* `docker compose stop` (стек Node A) → VIP уходит на B → UE пере-attach на B (UL-трафик или `ps-establish`); после восстановления A — `eupf-clean` на A. Заодно замерить фактическое время пере-регистрации (для сравнения с implicit-dereg ≈ 17 мин).

**Шаг 6 — регресс.** Обычные attach/detach после процедур; iperf/speedtest-профиль работает; повторный запуск скрипта идемпотентен (нет ложных срабатываний и ошибок).

## 8. Риски, допущения и ограничения (сводно)

| # | Риск/ограничение | Митигация |
|---|---|---|
| 1 | MongoDB без replica set → 4G CLR (change stream) не работает | §6.2: включить RS (опционально); до включения режим `4g-clr` честно сообщает об отсутствии RS и пропускается |
| 2 | Для реального (неэмулируемого) 5G RAN управляемого механизма нет | Задокументировано: implicit dereg (§3.5) + опция сокращения `t3512`; nr-cli применим только к UERANSIM |
| 3 | `eupf-clean` десинхронизирует SMF | Применять только к узлу вне трафика; ограничение зафиксировано в доке и в выводе скрипта |
| 4 | Гонка drain vs перенос VIP (UE пере-attach'нется на старый узел) | Регламент порядка операций (§7 шаг 5): drain → немедленный перенос VIP → контроль; при «мягком» `5g-psrelease` гонки нет (UE остаётся registered, сессии пересоздаются на B) |
| 5 | Эндпоинты dev-образа eUPF отличаются от документации main | Авто-детект в скрипте (`/pfcp_sessions` ↔ `/sessions`) + Swagger UI |
| 6 | `nr-cli` ставит задачи UE на паузу на время команды | Приемлемо для лаборатории (секунды); при недоступности UE — таймаут и продолжение по списку |
| 7 | После `deregister` UE-эмулятор может «выключиться» | Возврат: `ps-establish` или рестарт контейнера `ue`; в отказном сценарии не требуется (пере-attach сам) |
| 8 | Включение RS на PSMDB с шифрованием — непроверенный на стенде путь | Выполнять по §6.2 с проверкой KMS/шифрования; откат описан; до включения — `4g-clr` просто недоступен |

**Допущения:** UERANSIM 3.2.6 в проекте и команды CLI стабильны (проверено по исходникам master, команды `deregister`/`ps-release*`/`ue-release` присутствуют давно); точный синтаксис опций `deregister` (switch-off) и фактические таймеры implicit-dereg подтверждаются на стенде в шаге 0/2.

## 9. Открытые вопросы (нужны решения перед Act mode)

1. **Включать ли replica set в MongoDB** (предусловие режима `4g-clr`)? — рекомендация: да, если 4G-часть используется; иначе оставить режим отключённым.
2. **Добавлять ли `5g-ran` в `COMPOSE_PROFILES`** (нужно для проверок и для nr-cli-режимов)? — рекомендация: включить на тестовом стенде, не включать на «боевом» узле с реальным RAN.
3. **Писать ли раздел в DISASTER-RECOVERY.md** (§6.3) сразу или после успешных учений? — рекомендация: после учений, чтобы зафиксировать фактические тайминги.

## Приложение А. Проверенные источники (что и где подтверждено)

| Факт | Источник |
|---|---|
| namf-oam в AMF — только CRUD PLMN; внешней операции release/deregister нет | Open5GS v2.7.7: `src/amf/amf-sm.c`, `src/amf/namf-oam.h`, `src/amf/namf-oam.c` |
| Implicit Deregistration освобождает SM-контексты/PDU-сессии (UDM unsubscribe/dereg → PDU session release) | Open5GS v2.7.7: `src/amf/gmm-sm.c` (комментарии к `AMF_NETWORK_INITIATED_IMPLICIT_DE_REGISTERED`) |
| HSS: change stream + триггер `request_cancel_location: true` → CLR | Open5GS v2.7.7: `src/hss/hss-context.c` (`hss_handle_change_event()`, `mongoc_change_stream_*`) |
| UDR/UDM: change stream отсутствует (5G-аналога CLR нет) | Open5GS v2.7.7: `src/udr/udr-sm.c`, состав `src/udm/` |
| UERANSIM: UE-команды `deregister`, `ps-release`, `ps-release-all`, `ps-establish`, `ps-list`; gNB-команды `ue-list`, `ue-release <id>` (NGAP Context Release) | UERANSIM: `src/lib/app/cli_cmd.cpp`, `src/ue/app/cmd_handler.cpp`, `src/gnb/app/cmd_handler.cpp` |
| eUPF REST API: `GET/DELETE /api/v1/pfcp_sessions`, `pfcp_associations(/release)`, `health`, Swagger | eUPF: `docs/api.md` (ветка main); применимость к dev-образу — проверить на стенде |
| Состав стенда: eUPF вместо open5gs-upfd, профили, t3512=540, mongod.conf без RS, ue.list, Prometheus-таргеты | Репозиторий: `docker-compose.yaml`, `docker-compose.override.yaml`, `docker-compose.encryption.yaml`, `.env`, `.deploy/docker/*`, `prometheus.yml` |

## Приложение Б. Шпаргалка (команды и эндпоинты)

```bash
# --- UERANSIM (выполнять в контейнерах ue / gnb) ---
docker compose exec -T ue nr-cli imsi-999990000000001 -e status         # состояние UE (rm/mm/cm-state)
docker compose exec -T ue nr-cli imsi-999990000000001 -e ps-list        # PDU-сессии UE
docker compose exec -T ue nr-cli imsi-999990000000001 -e deregister     # де-регистрация (полный teardown)
docker compose exec -T ue nr-cli imsi-999990000000001 -e ps-release-all # только сессии (soft), UE остаётся registered
docker compose exec -T gnb nr-cli UERANSIM-gnb-999-99-16 -e ue-list     # UE на gNB
docker compose exec -T gnb nr-cli UERANSIM-gnb-999-99-16 -e ue-release 1 # NGAP Context Release (N2-only)

# --- eUPF REST API (:8081) ---
curl -s http://localhost:8081/api/v1/health
curl -s http://localhost:8081/api/v1/pfcp_sessions                       # все PFCP-сессии
curl -s 'http://localhost:8081/api/v1/pfcp_sessions?imsi=999990000000001'
curl -s -X DELETE 'http://localhost:8081/api/v1/pfcp_sessions?imsi=999990000000001'  # только для узла вне трафика!

# --- MongoDB: триггер HSS CLR (требует replica set) ---
docker compose exec -T mongodb mongo --quiet open5gs --eval \
  'db.subscribers.updateOne({imsi:"999990000000001"},{$set:{request_cancel_location:false}})'  # сброс (идемпотентность)
docker compose exec -T mongodb mongo --quiet open5gs --eval \
  'db.subscribers.updateOne({imsi:"999990000000001"},{$set:{request_cancel_location:true}})'   # CLR -> MME -> detach

# --- Наблюдение ---
docker compose logs --tail=100 -f amf smf hss mme
curl -s http://localhost:9092/metrics | grep -iE 'ue|session'   # SMF-метрики (порт 9092 опубликован на хост)
docker compose exec -T amf curl -s http://127.0.0.1:9090/metrics | grep -iE 'ue|rm-'   # AMF-метрики (порт не опубликован)
docker compose exec -T upf wget -qO- http://127.0.0.1:9091/metrics | grep -i pfcp      # eUPF-метрики (в контейнере)
# Prometheus UI/API на хосте: http://localhost:9091 (таргеты: amf/smf/mme:9090, upf:9091)
```

---

*Документ подготовлен по результатам анализа исходников Open5GS v2.7.7, UERANSIM и документации eUPF, а также конфигурации репозитория open5gs-compose. Утверждение плана → реализация (Act mode): §6.*