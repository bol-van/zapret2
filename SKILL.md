---
name: zapret2-nfqws2
description: Полный справочник по использованию zapret2 (nfqws2) на Linux/Keenetic/Entware/OpenWrt. Используется при разработке GUI-обёрток (роутеры Keenetic/OpenWrt), при написании стратегий обхода DPI, при работе с фаерволом (iptables/nftables), при работе с blockcheck2 и с Lua-стратегиями. Описывает архитектуру, формат командной строки, профили, фильтры, диапазоны, маркеры, payload-типы, библиотеку zapret-antidpi.lua, оркестраторов, систему запуска и скриптов в OpenWrt/Entware/systemd, а также особенности Keenetic.
---

# Skill: zapret2 / nfqws2

Этот файл — компактный справочник для работы с проектом **zapret2** (https://github.com/bol-van/zapret2) и его ядром **nfqws2**. Источник истины — `docs/manual.md` в репозитории zapret2; здесь сжатые рабочие знания: формат команд, типичные сборки стратегий, правила фаервола, работа с blockcheck2 и Lua-кодом.

## 1. Что такое zapret2

zapret2 — автономный пакетный манипулятор для обхода DPI. Главные отличия от zapret1:

- Ядро **nfqws2** (dvtws2 на BSD, winws2 на Windows) занимается только перехватом и диссекцией; «дурение» (стратегии) вынесено в Lua. Это даёт радикально большую гибкость.
- **Профили** (мультистратегии) и **хостлисты** сохранены, но логика автохостлиста изменена: профиль с автолистом захватывает только соединения с известным `hostname`; до его получения они проходят мимо.
- Параметры в стиле `--dpi-desync-*` заменены на:
  - **`--lua-desync=<function>[:arg1[=val1]:argN[=valN]]`** — вызов Lua-инстанса.
  - **`--lua-init=@file.lua | <lua_code>`** — однократная инициализация (несколько раз можно).
  - **`--blob=<name>:[+ofs]@file | 0xHEX`** — загрузка двоичных данных в Lua-переменную.
- Понятие **payload type** (типа данных в пакете) — `tls_client_hello`, `http_req`, `quic_initial` и т.д. — пришло на смену «протоколу соединения» в фильтрах.
- Десинхронизации больше не «фаза 1/фаза 2». Каждый `--lua-desync` — отдельный инстанс. Их в профиле может быть сколько угодно, можно вызывать одну функцию много раз с разными параметрами.
- Старые `start/cutoff` стали **диапазонами**: `--in-range` и `--out-range`.
- Серверный режим `--server` инвертирует трактовку направлений и фильтрации.
- Поддержка автоматической TCP-сегментации в `zapret-lib.lua`: размер не важен, всё нарезается по MSS.
- Поддержка **многопакетных пейлоадов** (kyber в tls_client_hello, многопакетный quic_initial) с автоматическим reasm и replay.

Lua-библиотеки в составе проекта:

- `lua/zapret-lib.lua` — хелперы (всегда подключать).
- `lua/zapret-antidpi.lua` — готовая библиотека стратегий-аналогов nfqws1 (`fake`, `multisplit`, `multidisorder`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `tcpseg`, `oob`, `wsize`, `wssize`, `syndata`, `rst`, `synack`, `synack_split`, `udplen`, `dht_dn`, http_*).
- `lua/zapret-auto.lua` — оркестраторы (`circular`, `repeater`, `condition`, `per_instance_condition`, `stopif`) и iff-функции (`cond_random`, `cond_payload_str`, `cond_lua`, ...).
- `lua/zapret-obfs.lua` — обфускаторы (`wgobfs`, `ippxor`, `udp2icmp`, `synhide`).
- `lua/zapret-pcap.lua` — запись pcap.
- `lua/zapret-tests.lua` — тесты C-функций.

## 2. Архитектура обработки пакета

```
ядро ОС
  └── iptables/nftables → NFQUEUE №X
        └── nfqws2
              ├── dissect (ip/ip6/tcp/udp/icmp + payload)
              ├── conntrack (счётчики, направления, MSS, scale, hostname)
              ├── распознавание payload type
              ├── reasm / decrypt (для tls_client_hello, quic_initial)
              ├── выбор профиля по фильтрам (1..N → default 0)
              ├── последовательно: Lua-инстансы (--lua-desync)
              │     каждый возвращает вердикт PASS / MODIFY / DROP
              │     (вердикты агрегируются: DROP > MODIFY > PASS)
              └── возврат пакета в ядро
```

Цикл выбора профиля повторяется при изменении L7-протокола и при получении hostname (макс. 2 «перескока»). Если все инстансы профиля вошли в cutoff или вышли за range — соединение помечается **lua cutoff** по направлению и больше не дёргает Lua.

## 3. Полный шаблон запуска

```bash
nfqws2 \
  --qnum=200 \                            # номер NFQUEUE (Linux)
  --debug=@/tmp/nfqws2.log \              # или 1 / syslog / @file
  --user=nobody \                         # сброс привилегий
  --bind-fix4 --bind-fix6 \               # для PBR/multi-WAN
  --lua-init=@/opt/zapret2/lua/zapret-lib.lua \
  --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua \
  --lua-init=@/opt/zapret2/lua/zapret-auto.lua \
  --blob=tls_google:@/opt/zapret2/files/fake/tls_clienthello_www_google_com.bin \
  \
  --filter-tcp=80 --filter-l7=http \
    --out-range=-d10 --payload=http_req \
      --lua-desync=fake:blob=fake_default_http:tcp_md5 \
      --lua-desync=multisplit:pos=method+2 \
    --new \
  --filter-tcp=443 --filter-l7=tls \
    --out-range=-d10 --payload=tls_client_hello \
      --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=6 \
      --lua-desync=multidisorder:pos=1,midsld \
    --new \
  --filter-udp=443 --filter-l7=quic \
    --payload=quic_initial \
      --lua-desync=fake:blob=fake_default_quic:repeats=6
```

Параметры можно загружать из файла: `nfqws2 @/path/config.conf` (остальные опции командной строки тогда игнорируются). Это используется systemd-юнитом `nfqws2@.service` (читает `/etc/zapret2/<instance>.conf`).

## 4. Полный список опций

### 4.1 Общие (для всех платформ)

```
@<config_file>                   читать опции из файла
--debug=0|1|syslog|android|@file журнал отладки
--version                        вывести версию и выйти
--dry-run                        проверить опции без запуска (Lua не проверяется)
--comment=<text>                 игнорируемая метка
--intercept=0|1                  0 = только запустить lua-init и выйти
--daemon                         отвязаться от консоли
--chdir[=path]                   сменить cwd (без пути — путь к exe)
--pidfile=<file>                 запись PID
--ctrack-timeouts=S:E:F[:U]      таймауты conntrack (SYN, ESTAB, FIN, udp)
--ctrack-disable[=1]             выключить conntrack
--payload-disable[=t1,t2]        отключить распознавание payload (без аргументов — все)
--reasm-disable[=t1,t2]          отключить сборку (tls_client_hello, quic_initial)
--server[=1]                     серверный режим (инверсия направлений)
--ipcache-lifetime=<sec>         время жизни IP-кэша (0 — без ограничений; default 7200)
--ipcache-hostname[=1]           кэшировать соответствие IP→hostname (для стратегий нулевой фазы)

DESYNC ENGINE INIT:
--writeable[=dir]                создать каталог с разрешением на запись для Lua (env WRITEABLE)
--blob=<name>:[+ofs]@file|0xHEX  загрузка двоичных данных в Lua-переменную
--lua-init=@file|<lua_code>      Lua-код при старте; @ перед именем — файл (поддерживается .gz)
--lua-gc=<sec>                   интервал GC Lua

MULTI-STRATEGY:
--new[=name]                     начать новый профиль (опционально имя)
--skip                           игнорировать профиль
--name=<name>                    имя профиля
--template[=name]                сделать профиль шаблоном
--cookie[=str]                   значение desync.cookie для всех инстансов профиля
--import=<name>                  импорт настроек из шаблона
--filter-l3=ipv4|ipv6            фильтр: версия IP
--filter-tcp=[~]p1[-p2]|*        фильтр: TCP-порты; ~ = инверсия
--filter-udp=[~]p1[-p2]|*
--filter-icmp=type[:code]|*
--filter-ipp=proto|*             номера raw IP-протоколов (не относится к tcp/udp/icmp — для них нужен свой filter)
--filter-l7=proto[,proto]        L7-протоколы потока: http,tls,xmpp,mtproto,bt,quic,wireguard,
                                 dht,utp_bt,discord,stun,dns,dtls; известные all/known
--ipset=<file>                   включающий IP-лист (ipv4+ipv6)
--ipset-ip=<list>                инлайн-список
--ipset-exclude=<file>           исключающий IP-лист
--ipset-exclude-ip=<list>
--hostlist=<file>                включающий хостлист (поддомены автоматически; ^ отключает; #комментарии)
--hostlist-domains=<d1,d2,...>   инлайн
--hostlist-exclude=<file>
--hostlist-exclude-domains=<...>
--hostlist-auto=<file>           автохостлист (заполняется автоматически)
--hostlist-auto-fail-threshold=N  (default 3)
--hostlist-auto-fail-time=SEC     (default 60)
--hostlist-auto-retrans-threshold=N (default 3)
--hostlist-auto-retrans-reset=0|1 посылать RST ретрансмиттеру (default 1)
--hostlist-auto-retrans-maxseq=N  (default 32768)
--hostlist-auto-incoming-maxseq=N (default 4096)
--hostlist-auto-udp-out=N         (default 4)
--hostlist-auto-udp-in=N          (default 1)
--hostlist-auto-debug=<logfile>

LUA PACKET PASS MODE (внутрипрофильные фильтры — действуют до переопределения):
--payload=t1[,t2]                фильтр пейлоадов для последующих инстансов (default: all)
--out-range=...                  диапазон по исходящему направлению (default: a)
--in-range=...                   диапазон по входящему направлению (default: x)

LUA DESYNC ACTION:
--lua-desync=<fn>[:p1[=v1]:p2[=v2]] вызов Lua-инстанса
```

### 4.2 Только nfqws2 (Linux)

```
--qnum=<n>                       номер NFQUEUE
--user=<name>                    или
--uid=<uid>[:gid1,gid2,...]      сменить идентификатор
--bind-fix4 / --bind-fix6        корректная маршрутизация генерируемых пакетов при PBR
--fwmark=<int|0xHEX>             бит против петли (default 0x40000000)
--filter-ssid=ssid1[,ssid2,...]  фильтр по WiFi SSID
```

### 4.3 Только winws2 (Windows)

```
--wf-iface=N[.N]                 номер интерфейса
--wf-l3=ipv4|ipv6
--wf-tcp-in / --wf-tcp-out       список TCP-портов перехвата по направлению
--wf-udp-in / --wf-udp-out
--wf-tcp-empty=[~]ports          перехват пустых TCP-ACK (default off — экономия CPU)
--wf-icmp-in / --wf-icmp-out     type[:code]
--wf-ipp-in / --wf-ipp-out       raw IP-протоколы
--wf-raw-part=<filter>|@file     частичный WinDivert-фильтр (OR; можно много)
--wf-raw-filter=<filter>|@file   частичный WinDivert-фильтр (AND; один)
--wf-filter-lan=0|1              фильтровать non-global IP (default 1)
--wf-raw=<filter>|@file          полный фильтр (замещает конструктор)
--wf-save=<file>                 сохранить итоговый фильтр
--ssid-filter=ssid1[,ssid2,...]
--nlm-filter=net1[,net2,...]
--nlm-list[=all]
```

## 5. Профили и фильтры (мультистратегия)

```
nfqws2 <глобальные>  <фильтр1> <стратегия1> --new
                     <фильтр2> <стратегия2> --new
                     ...
                     <фильтрN> <стратегияN>
```

**Правила**:

- Профили проверяются строго слева направо, побеждает первый подошедший.
- Профиль 0 (default) — пустой, никаких действий.
- Группы фильтров `tcp / udp / icmp / ipp` объединяются OR между собой. Указание любого из них блокирует остальные группы (нужно указывать `--filter-tcp=*` если хочешь tcp + ещё что-то).
- `filter-ipp` НЕ относится к tcp/udp/icmp. Чтобы оставить tcp+ipp, пиши `--filter-tcp=* --filter-ipp=6` явно.
- `icmp` автоматически включает `icmpv6`, но коды/типы у них разные.
- Хостлисты учитывают поддомены автоматически. `^` в начале строки выключает учёт поддоменов. `#` — комментарий.
- ipset-ы могут смешивать ipv4+ipv6.
- Без автохостлиста профиль с хостлистами не выбирается до получения hostname. Если хост в exclude — стратегия не применяется. Если есть автохостлист — профиль работает всегда при наличии hostname; счётчики неудач и попадание в autolist описаны в `--hostlist-auto-*`.

**Шаблоны**:

```
--template=tpl1 <baseparams> --new
--template=tpl2 --import=tpl1 <extra> --new
--import=tpl1 --name=prof1 <params>
```

Простые параметры замещаются, списочные (хостлисты, fitler-tcp, lua-desync) добавляются в конец.

## 6. Внутрипрофильные фильтры — диапазоны

Формат: `[mode<int>](-|<)[mode<int>]`

- `-` — верхняя граница включительная, `<` — исключительная.
- `mode`:
  - `a` — always (без числа)
  - `x` — never (без числа)
  - `n` — номер пакета
  - `d` — номер пакета с данными (рекомендуется на Windows из-за --wf-tcp-empty=0)
  - `b` — байт-позиция переданных данных
  - `s` — relative sequence (TCP) от начала пакета
  - `p` — relative sequence верхней границы пакета (s+payload)
- Defaults: `--in-range=x`, `--out-range=a`, `--payload=all`.

Примеры: `--out-range=-d10` (первые 10 пакетов с данными), `--in-range=-s5556`, `--out-range=s100-s1000`, `--in-range=s1<d1` (только до первого данных).

Фильтры действуют до **следующего переопределения того же типа или до конца профиля**. В новом профиле сбрасываются на default.

## 7. Распознаваемые пейлоады

| L7-протокол | L4 | Payload-типы |
|:----|:----|:----|
| http | tcp | http_req, http_reply |
| tls | tcp | tls_client_hello, tls_server_hello |
| xmpp | tcp | xmpp_stream, xmpp_starttls, xmpp_proceed, xmpp_features |
| mtproto | tcp | mtproto_initial |
| bt | tcp | bt_handshake |
| quic | udp | quic_initial |
| wireguard | udp | wireguard_initiation, wireguard_response, wireguard_cookie, wireguard_keepalive |
| dht | udp | dht |
| utp_bt | udp | utp_bt_handshake |
| discord | udp | discord_ip_discovery |
| stun | udp | stun |
| dns | udp | dns_query, dns_response |
| dtls | udp | dtls_client_hello, dtls_server_hello |
| icmp | * | ipv4, ipv6, icmp |

Спец-типы: `empty` (пустой), `unknown` (неизвестный). В фильтрах поддерживаются `all` и `known` (не empty/unknown).

**Стандартные блобы** (загружены автоматически):
- `fake_default_tls` — TLS ClientHello от Firefox без kyber, SNI = `www.microsoft.com`.
- `fake_default_http` — HTTP-запрос на `www.iana.org`.
- `fake_default_quic` — `0x40 + 619*0x00`.

## 8. Маркеры (для `pos` в split/disorder/tcpseg)

- Абсолютный положительный — число с начала пейлоада: `100`.
- Абсолютный отрицательный — от конца: `-1` — последний байт, `-10`.
- Относительный — относительно логических позиций в известных пейлоадах:
  - `method` — начало HTTP-метода
  - `host`, `endhost` — начало/конец имени хоста
  - `sld`, `endsld`, `midsld` — second-level domain
  - `sniext` — поле данных SNI extension в TLS
  - `extlen` — поле длины TLS extensions
- Можно с арифметикой: `method+2`, `endhost-2`, `sniext+1`.
- Список через запятую: `1,midsld,endhost-2,-10`.

## 9. Передача параметров в Lua-инстансы

```
--lua-desync=fn[:arg[=value]:arg=value:...]
```

- Каждый `arg` — строка. Если value не задано — пустая строка.
- Подстановки C-кода в значениях:
  - `%var` → значение `desync.var` (или global `var`).
  - `#var` → длина `desync.var` или global `var`.
  - Эскейп: `\:` `\%` `\#`.
- Десинхрон-функции получают `(ctx, desync)`. `desync.arg` содержит все аргументы.

## 10. Библиотека стратегий `zapret-antidpi.lua`

Каждая функция вызывается через `--lua-desync=fnname:...`. Список и ключевые аргументы:

### 10.1 Базовые
- **`drop`** — VERDICT_DROP. Аргументы: `dir` (in/out/any default any), `payload` (default all).
- **`send`** — отправить текущий диссект (без дропа оригинала). Аргументы: dir, fooling, ipid (default none), ipfrag, reconstruct, rawsend, `delay=ms`.
- **`pktmod`** — применить фулинг/ipid к текущему диссекту (без отсылки и без вердикта). dir + fooling + ipid.

### 10.2 Дурение HTTP
- `http_hostcase` — менять регистр заголовка `Host:` (arg: `spell` = "host").
- `http_domcase` — менять регистр имени домена в `Host:`.
- `http_methodeol` — `\r\n` перед методом (only nginx).
- `http_unixeol` — 0D0A→0A.

### 10.3 Window size (legacy)
- `wsize` — менять `tcp.th_win` и scale в SYN,ACK (только уменьшение). args: `wsize`, `scale`.
- `wssize` — то же по всем пакетам потока до cutoff. args: `dir`, `wsize`, `scale`, `forced_cutoff=<payloads>`. **Снижает скорость**. Стратегия нулевой фазы (с хостлистами — только при `--ipcache-hostname`).

### 10.4 Фейки
- **`fake`** — прямой фейк (отдельный пакет). args: dir, payload (default known), fooling, ipid, ipfrag, reconstruct, rawsend, **`blob=<name>`**, `optional`, `tls_mod=<mods>`. Сегментация автоматическая (для blob > MSS).
- `syndata` — добавить пейлоад в SYN. arg: `blob` (must fit MTU), `tls_mod`. После не-SYN пакета — instance_cutoff. Стратегия нулевой фазы.
- `rst` — отослать пустой RST (или RST+ACK при `rstack`). args: dir, payload, fooling, ipid, ipfrag, reconstruct, rawsend.
- `tls_client_hello_clone` — подготовить blob с модифицированным TLS ClientHello. args: `blob`, `fallback`, `sni_del_ext`, `sni_del`, `sni_snt`, `sni_snt_new`, `sni_first`, `sni_last`.

### 10.5 TCP-сегментация
- **`multisplit`** — нарезать пейлоад по списку маркеров. args: `pos=m1,m2,...` (default `2`), `seqovl=<int>`, `seqovl_pattern=<blob>`, `blob=<replace_payload>`, `optional`, `nodrop`. Поддерживает reasm.
- **`multidisorder`** — то же, но в обратном порядке отправки. seqovl может быть маркером. (Не работает с Windows-серверами.) Подходит для tls_client_hello с kyber и без.
- `multidisorder_legacy` — поведение из nfqws1.
- **`fakedsplit`** — split с замешиванием фейков. args: `pos`, `seqovl`, `seqovl_pattern`, `blob`, `optional`, `nodrop`, `nofake1..nofake4`, `pattern=<blob>`. Требует fooling.
- `fakeddisorder` — disorder с замешиванием фейков. Аналогично.
- `hostfakesplit` — спец-резатель для http_req/tls_client_hello вокруг имени хоста. args: `host=<random.template>`, `midhost=<marker>`, `disorder_after=<marker>`, `nofake`, `nofake2`, `blob`, `optional`, `nodrop`.
- `tcpseg` — отослать произвольную часть пейлоада/reasm/blob, ограниченную двумя маркерами. args: `pos=m1,m2`, `seqovl`, `seqovl_pattern`, `blob`, `optional`. Вердикт не выносит. Удобно с `drop:payload=known` для замещения.
- `oob` — вставить 1 OOB-байт в TCP handshake. args: `char` или `byte`, `urp=b|e`. Требует разрешения первых входящих (`--in-range=-s1`). Не сочетается с multi-split/disorder.

### 10.6 UDP
- `udplen` — раздуть/обрезать UDP-payload. args: dir, payload, `min`, `max`, `increment`, `pattern`, `pattern_offset`.
- `dht_dn` — заменить `d1`/`d2` в DHT на `dN`. arg: `dn`.

### 10.7 Прочее
- `synack` — отослать SYN,ACK до SYN (TCB turnaround). Ломает NAT, требует POSTNAT/nftables на роутере.
- `synack_split` — вариация.

### 10.8 Стандартные блоки опций (передаются как arg-ключи `--lua-desync=fn:opt=val`)

**fooling**: `ip_ttl`, `ip6_ttl`, `ip_autottl=<delta>,<min>-<max>`, `ip6_autottl=...`, `ip6_hopbyhop[=hex]`, `ip6_hopbyhop2`, `ip6_destopt`, `ip6_destopt2`, `ip6_routing`, `ip6_ah`, `tcp_seq=<+/-int>`, `tcp_ack=<+/-int>`, `tcp_ts=<+/-int>`, `tcp_md5[=16byte_hex]`, `tcp_flags_set=FIN,SYN,...`, `tcp_flags_unset=ack`, `tcp_ts_up`, `tcp_nop_del`, `fool=<custom_lua_fn>`.

**ipid**: `ip_id=seq|rnd|zero|none` (default `seq` для send-функций, `none` для send), `ip_id_conn=1`.

**ipfrag**: `ipfrag` (без значения = вкл. ipfrag2 default), `ipfrag_disorder`, `ipfrag_pos_udp=<mul8>` (default 8), `ipfrag_pos_tcp=<mul8>` (default 32), `ipfrag_next=<proto>`.

**reconstruct**: `keepsum`, `badsum`, `ip6_preserve_next`, `ip6_last_proto`.

**rawsend**: `repeats=N`, `fwmark=<int>`, `ifout=<name>`.

**tls_mod**: `rnd`, `dupsid`, `rndsni`, `sni=<domain>`, `padencap`. Список через запятую: `tls_mod=rnd,rndsni,dupsid`.

## 11. Оркестраторы `zapret-auto.lua`

- **`circular`** — крутит стратегии по кругу при неудачах. Аргументы:
  - `fails`, `retrans`, `maxseq` и др. (см. `automate_failure_check`).
  - Все последующие инстансы помечают аргументом `strategy=N` (с 1 непрерывно). `final` — финальная стратегия.
  - Требует входящих пакетов (`--in-range=-s5556` или больше — детектор успеха срабатывает на s4096).
- **`repeater`** — повторяет N последующих инстансов R раз. args: `instances=N`, `repeats=R`, `stop`, `clear`, `iff=<name>`, `neg`.
- **`condition`** — выполняет следующие инстансы только если `iff xor neg = true`. args: `iff`, `neg`, `instances=N`.
- **`per_instance_condition`** — каждый из следующих инстансов сам несёт `cond=<iff>`, `cond_neg`.
- **`stopif`** — очистить план при условии.
- **iff-функции**: `cond_true`, `cond_false`, `cond_random:percent=N`, `cond_payload_str:pattern=str`, `cond_tcp_has_ts`, `cond_lua:cond_code=<lua>`.

Пример `circular`:
```
--filter-tcp=80,443 --filter-l7=http,tls --out-range=-s34228 --in-range=-s5556
--lua-desync=circular
--in-range=x --payload=tls_client_hello
--lua-desync=fake:blob=fake_default_tls:badsum:strategy=1
--lua-desync=multidisorder:strategy=2
--payload=http_req
--lua-desync=fake:blob=fake_default_http:badsum:strategy=1
--lua-desync=multisplit:strategy=2
```

## 12. Перехват в Linux: nftables и iptables

### 12.1 nftables (предпочтительно)

POSTNAT-схема (захват после NAT, корректно работает с проходящим трафиком):

```bash
IFACE_WAN=wan
MAX_PKT_IN=15; MAX_PKT_OUT=15
FWMARK=0x40000000
PORTS_TCP=80,443; PORTS_UDP=443
QNUM=200

nft create table inet zapret2

nft add chain inet zapret2 postnat "{type filter hook postrouting priority srcnat+1;}"
nft add rule inet zapret2 postnat oifname $IFACE_WAN meta mark and $FWMARK == 0 \
    udp dport "{$PORTS_UDP}" ct original packets 1-$MAX_PKT_OUT queue num $QNUM bypass
nft add rule inet zapret2 postnat oifname $IFACE_WAN meta mark and $FWMARK == 0 \
    tcp dport "{$PORTS_TCP}" ct original packets 1-$MAX_PKT_OUT queue num $QNUM bypass
nft add rule inet zapret2 postnat oifname $IFACE_WAN meta mark and $FWMARK == 0 \
    tcp dport "{$PORTS_TCP}" tcp flags fin,rst queue num $QNUM bypass

nft add chain inet zapret2 pre "{type filter hook prerouting priority filter;}"
nft add rule inet zapret2 pre iifname $IFACE_WAN udp sport "{$PORTS_UDP}" \
    ct reply packets 1-$MAX_PKT_IN queue num $QNUM bypass
nft add rule inet zapret2 pre iifname $IFACE_WAN tcp sport "{$PORTS_TCP}" \
    ct reply packets 1-$MAX_PKT_IN queue num $QNUM bypass
nft add rule inet zapret2 pre iifname $IFACE_WAN tcp sport "{$PORTS_TCP}" \
    "tcp flags & (syn | ack) == (syn | ack)" queue num $QNUM bypass
nft add rule inet zapret2 pre iifname $IFACE_WAN tcp sport "{$PORTS_TCP}" tcp flags fin,rst queue num $QNUM bypass

# notrack для пакетов от nfqws (помечены fwmark), чтобы не ломал NAT
nft add chain inet zapret2 predefrag "{type filter hook output priority -401;}"
nft add rule inet zapret2 predefrag "mark & $FWMARK != 0x00000000 notrack"
```

Удалить: `nft delete table inet zapret2`.

### 12.2 iptables (PRENAT, legacy)

```bash
JNFQ="-j NFQUEUE --queue-num $QNUM --queue-bypass"
CHECKMARK="-m mark ! --mark $FWMARK/$FWMARK"
CB_ORIG="-m connbytes --connbytes-dir=original --connbytes-mode=packets"
CB_REPLY="-m connbytes --connbytes-dir=reply --connbytes-mode=packets"

for tables in iptables ip6tables; do
  $tables -t mangle -N ztest_post 2>/dev/null
  $tables -t mangle -F ztest_post
  $tables -t mangle -C POSTROUTING -j ztest_post 2>/dev/null || $tables -t mangle -A POSTROUTING -j ztest_post
  $tables -t mangle -I ztest_post -o $IFACE_WAN $CHECKMARK -p tcp -m multiport --dports $PORTS_TCP \
      $CB_ORIG --connbytes 1:$MAX_PKT_OUT $JNFQ
  # ... аналогично для FIN, RST, UDP, входящих
done
```

iptables не умеет POSTNAT-перехват для проходящего трафика, поэтому **некоторые техники (synack, манипуляции с IP/портами) не работают** на iptables в forwarded-сценарии. С Linux ≥ 5.15 и nft ≥ 1.0.1 всегда выбирай **nftables**.

### 12.3 Ключевые правила построения

1. **fwmark anti-loop**: пакеты, сгенерированные nfqws2, помечены `DESYNC_MARK` (default `0x40000000`). Все правила NFQUEUE-захвата должны исключать пакеты с этой меткой: `mark & 0x40000000 == 0`.
2. **conntrack ограничитель**: первые N пакетов через `ct original packets 1-N` (nft) или `--connbytes 1:N --connbytes-mode=packets` (iptables) — экономия CPU.
3. **Перехват SYN+ACK, FIN, RST** на входе нужен для корректной работы conntrack и autohostlist (детект RST-блока).
4. **notrack для пакетов с DESYNC_MARK** в output/predefrag — чтобы NAT не ломал нестандартные пакеты.
5. **Не указывать в фильтрах**: исключающий ipset (nozapret/nozapret6) — это делает основной код, и проверку `DESYNC_FWMARK`.

## 13. Серверный режим

`--server` инвертирует трактовку направлений: тот, кто шлёт первый SYN/UDP пакет — клиент, всё, что от него приходит — это **входящее** для сервера (`outgoing=false`). `--in-range`/`--out-range` и `desync.outgoing` инвертированы. ipset фильтрует адрес клиента, фильтр портов — порт сервера (для tcp/udp dport берётся как порт сервера).

Используется для серверной обфускации (`udp2icmp`, `wgobfs` со стороны сервера).

## 14. Сигналы

- `SIGHUP` — принудительно перечитать хостлисты и ipset-ы.
- `SIGUSR1` — дамп пула conntrack.
- `SIGUSR2` — дамп autohostlist-счётчиков и ipcache.

## 15. blockcheck2

Скрипт `blockcheck2.sh` в корне репозитория. POSIX-shell, модульная структура тестов: `blockcheck2.d/standard`, `blockcheck2.d/custom`. Тестирует стратегии через curl, выдаёт работающие конфигурации.

### 15.1 Запуск

Интерактивно: `/opt/zapret2/blockcheck2.sh` (задаст основные вопросы).

Пакетно (BATCH-режим):
```bash
BATCH=1 DOMAINS=bbc.com CURL_CMD=1 SKIP_DNSCHECK=1 /opt/zapret2/blockcheck2.sh | tee /tmp/blockcheck2.log
```

### 15.2 Ключевые переменные окружения

```
DOMAINS       — список доменов через пробел; поддерживается "rutracker.org/forum"
TEST          — имя теста: standard, custom, или своё (subdir в blockcheck2.d)
IPVS=4|6|46   — версии IP
ENABLE_HTTP, ENABLE_HTTPS_TLS12, ENABLE_HTTPS_TLS13, ENABLE_HTTP3 = 0|1
REPEATS=N     — попыток на стратегию
PARALLEL=0|1  — параллельные попытки (внимание: может вызвать rate-limit)
SCANLEVEL=quick|standard|force
BATCH=1       — без интерактива
HTTP_PORT/HTTPS_PORT/QUIC_PORT
SKIP_DNSCHECK=1
SKIP_IPBLOCK=1
CURL=<path>   — заменить системный curl (например, /tmp/curl со статическим build, чтобы был kyber/quic)
CURL_MAX_TIME / CURL_MAX_TIME_QUIC / CURL_MAX_TIME_DOH
CURL_CMD=1    — печатать команды curl
CURL_OPT      — доп. опции curl (-k, -v)
CURL_HTTPS_GET=1 — GET вместо HEAD (для теста 16K-блока)
PKTWS_EXTRA_PRE / PKTWS_EXTRA_POST  — доп. параметры nfqws/winws до/после стратегии
PKTWS_EXTRA_PRE_1..9 / PKTWS_EXTRA_POST_1..9
SECURE_DNS=0|1 — принудительно DoH или нет
DOH_SERVER=<url>
DOH_SERVERS="url1 url2"
DNSCHECK_DNS  — внешние DNS для теста подмены
DNSCHECK_DOM  — домены для теста подмены
UNBLOCKED_DOM — незаблокированный домен для IP-block теста
SIMULATE=1, SIM_SUCCESS_RATE=N — режим симуляции для отладки
```

### 15.3 Переменные standard-теста

`MIN_TTL`, `MAX_TTL`, `MIN_AUTOTTL_DELTA`, `MAX_AUTOTTL_DELTA`, `FAKE_REPEATS`, `FOOLINGS46_TCP`, `FOOLINGS6_TCP`, `FAKE_HTTP`/`FAKE_HTTPS`/`FAKE_QUIC`, `FAKED_PATTERN_HTTP/HTTPS`, `SEQOVL_PATTERN_HTTP/HTTPS`, `MULTIDISORDER=multidisorder_legacy`.

Отключатели тестов: `NOTEST_BASIC_HTTP`, `NOTEST_MISC_HTTP`, `NOTEST_MISC_HTTPS`, `NOTEST_MULTI_HTTP/HTTPS`, `NOTEST_SEQOVL_*`, `NOTEST_SYNDATA_*`, `NOTEST_FAKE_*`, `NOTEST_FAKED_*`, `NOTEST_HOSTFAKE_*`, `NOTEST_FAKE_MULTI_*`, `NOTEST_FAKE_FAKED_*`, `NOTEST_FAKE_HOSTFAKE_*`, `NOTEST_QUIC`.

### 15.4 Тест `custom`

Простой пробивщик по списку готовых стратегий из файлов:
- `blockcheck2.d/custom/list_http.txt`
- `blockcheck2.d/custom/list_https_tls12.txt`
- `blockcheck2.d/custom/list_https_tls13.txt`
- `blockcheck2.d/custom/list_quic.sh`

Каждая стратегия — одна строка (без переносов). Поддерживаются комментарии `#`. Параметры интерпретируются shell — нужно экранирование `<`, `>`, `(`, `)`, кавычек.

Рекомендация: создать копию `blockcheck2.d/custom` → `blockcheck2.d/mytest/` и в диалоге выбрать `mytest`.

### 15.5 Выдача

Summary в конце: успешные стратегии по каждому домену и пересечение (только если `SCANLEVEL=force`).

**Важно**: blockcheck2 проверяет один домен/URI/протокол. Браузер делает гораздо больше (DNS, ipv4/6, TLS1.2/1.3, QUIC, kyber, ECH, fingerprint). Поэтому Summary OK ≠ автоматически рабочий сайт. См. раздел «Почему не открывается» в manual.md.

## 16. Скрипты запуска (Linux)

Корни:
- OpenWrt: `init.d/openwrt/zapret2` + `init.d/openwrt/functions` + `90-zapret2` (hotplug) + `firewall.zapret2` (fw3).
- sysv (любой не-OpenWrt Linux): `init.d/sysv/zapret2`.
- systemd: `init.d/systemd/zapret2.service`, `nfqws2@.service`, list-update.{service,timer}.
- openrc: `init.d/openrc/zapret2`.

Команды `start | stop | restart | start_daemons | stop_daemons | restart_daemons | start_fw | stop_fw | restart_fw | reload_ifsets | list_ifsets | list_table`.

### 16.1 Файл `config` (в корне zapret2)

shell-include, основные переменные:

```
TMPDIR                  — переопределение /tmp при нехватке tmpfs
WS_USER                 — пользователь для nfqws2 (на Keenetic обязателен — см. ниже)
FWTYPE                  — iptables / nftables / ipfw (auto-detect если не указано)
SET_MAXELEM=522288
IPSET_OPT="hashsize 262144 maxelem $SET_MAXELEM"
IPSET_HOOK              — путь к скрипту-генератору доп. IP
IP2NET_OPT4 / IP2NET_OPT6
MDIG_THREADS=30 / MDIG_EAGAIN=10 / MDIG_EAGAIN_DELAY=500
AUTOHOSTLIST_*          — параметры автохостлиста
GZIP_LISTS=1            — gzip-сжатие генерируемых листов
DESYNC_MARK=0x40000000  — fwmark anti-loop
DESYNC_MARK_POSTNAT=0x20000000
FILTER_MARK             — если задано — захватывать только пакеты с этим mark (для PBR)
POSTNAT=1               — режим POSTNAT для nftables (default), 0 = PRENAT
NFQWS2_ENABLE=0|1
NFQWS2_PORTS_TCP=80,443
NFQWS2_PORTS_UDP=443
NFQWS2_TCP_PKT_OUT / _IN / NFQWS2_UDP_PKT_OUT / _IN  — connbytes лимиты
NFQWS2_PORTS_TCP_KEEPALIVE / _UDP_KEEPALIVE          — порты без лимитера original (для stateless DPI)
NFQWS2_OPT="..."        — командная строка стратегии (БЕЗ --qnum, --user, --lua-init — они добавятся сами)
                          поддерживаются маркеры <HOSTLIST>, <HOSTLIST_NOAUTO>, заменяемые в зависимости от MODE_FILTER
MODE_FILTER=none|ipset|hostlist|autohostlist
FLOWOFFLOAD=donttouch|none|software|hardware
OPENWRT_LAN="lan" / OPENWRT_WAN4 / OPENWRT_WAN6      — имена netifd-интерфейсов (НЕ Linux ifname!)
IFACE_LAN / IFACE_WAN / IFACE_WAN6                   — Linux ifname (sysv-вариант)
INIT_APPLY_FW=1                                      — должен ли zapret поднимать firewall при start
INIT_FW_PRE_UP_HOOK / INIT_FW_POST_UP_HOOK / INIT_FW_PRE_DOWN_HOOK / INIT_FW_POST_DOWN_HOOK
DISABLE_IPV4=1 / DISABLE_IPV6=1
FILTER_TTL_EXPIRED_ICMP=1
GETLIST=ipset/get_<name>.sh                          — какой скрипт ipset использовать в cron
```

**Важно**:
- В `NFQWS2_OPT` НЕ писать `--hostlist=` напрямую — используй `<HOSTLIST>` и `<HOSTLIST_NOAUTO>` — они подставляются из директории `ipset/` в зависимости от `MODE_FILTER` и фактически существующих файлов.
- В `OPENWRT_LAN/WAN4/WAN6` — имена из `/etc/config/network` (netifd), а не Linux-интерфейсы. Например, `lan`, а не `br-lan`.
- Свои файлы класть **вне** `/opt/zapret2`, чтобы их не снёс инсталлятор при обновлении.

### 16.2 custom-скрипты (init.d/*/custom.d/)

Shell-includes; запускаются в алфавитном порядке. Определяемые функции:

- `zapret_custom_daemons()` — `$1=1` старт, `0` стоп. Запуск nfqws2 через `do_nfqws $1 $dnum "$opt"`.
- `zapret_custom_firewall()` — iptables. `$1=1/0`.
- `zapret_custom_firewall_nft()` — nftables. Без stop (общая очистка делается основным кодом).
- `zapret_custom_firewall_nft_flush()` — для удаления собственных sets/chains.

Хелперы (из основного кода):

```sh
alloc_dnum VAR        # уникальный номер демона (вызывать вне функции!)
alloc_qnum VAR        # уникальный номер NFQUEUE
do_nfqws $1 $dnum "$opt"
filter_apply_hostlist_target VAR_NAME  # подставить <HOSTLIST>/<HOSTLIST_NOAUTO>
standard_mode_daemons $1
fw_nfqws_post $1 "$f_v4" "$f_v6" $qnum   # iptables, POSTROUTING
fw_nfqws_pre  $1 "$f_v4" "$f_v6" $qnum   # iptables, PREROUTING
nft_fw_nfqws_post "$f_v4" "$f_v6" $qnum  # nftables (выбор chain через POSTNAT)
nft_fw_nfqws_pre  "$f_v4" "$f_v6" $qnum
filter_apply_ipset_target / nft_filter_apply_ipset_target
ipt / ipta / ipt_del / ipt6 / ipta6 / ipt6_del / ipt_add_del / ...
ipt_first_packets <N|keepalive>  → "$CB --connbytes 1:N"
ipt_port_ipset <name> <ports>
nft_add_chain / nft_delete_chain / nft_create_set / nft_del_set / nft_flush_set
nft_add_set_element / nft_add_set_elements
nft_flush_chain / nft_add_rule / nft_insert_rule
nft_first_packets <N|keepalive>  → "ct original packets ..."
```

Пример минимального custom (discord-media):

```sh
NFQWS_OPT_DESYNC_DISCORD_MEDIA="${NFQWS_OPT_DESYNC_DISCORD_MEDIA:---payload=discord_ip_discovery --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2}"
DISCORD_MEDIA_PORT_RANGE="${DISCORD_MEDIA_PORT_RANGE:-50000-50099}"
alloc_dnum DNUM_DISCORD_MEDIA
alloc_qnum QNUM_DISCORD_MEDIA

zapret_custom_daemons() {
    local opt="--qnum=$QNUM_DISCORD_MEDIA $NFQWS_OPT_DESYNC_DISCORD_MEDIA"
    do_nfqws $1 $DNUM_DISCORD_MEDIA "$opt"
}
zapret_custom_firewall_nft() {
    local DISABLE_IPV6=1
    local f="udp dport $DISCORD_MEDIA_PORT_RANGE udp length == 82 @ih,0,32 0x00010046 ..."
    nft_fw_nfqws_post "$f" '' $QNUM_DISCORD_MEDIA
}
```

См. `init.d/custom.d.examples.linux/` для готовых примеров: `10-keenetic-udp-fix`, `20-fw-extra`, `40-webserver`, `50-dht4all`, `50-discord-media`, `50-nfqws-ipset`, `50-quic4all`, `50-stun4all`, `50-wg4all`, `80-dns-intercept`, `99-lan-filter`.

### 16.3 Система листов (ipset/)

Пользовательские (правятся вручную):
- `zapret-hosts-user.txt` (+ `zapret-ip-user.txt`, `zapret-ip-user6.txt`)
- `zapret-hosts-user-exclude.txt` (+ `zapret-ip-exclude.txt`, `...6`)
- `zapret-hosts-user-ipban.txt` (+ ...)

Генерируемые:
- `zapret-hosts.txt`, `zapret-ip.txt`, `zapret-ip6.txt`
- `zapret-hosts-auto.txt` (автохостлист)
- `zapret-ip-ipban.txt`, `zapret-ip-ipban6.txt`

Скрипты `ipset/get_*.sh`: `get_user.sh`, `get_ipban.sh`, `get_exclude.sh`, `get_config.sh` (диспетчер по `GETLIST`), `get_antifilter_*.sh`, `get_antizapret_domains.sh`, `get_refilter_*.sh`, `get_reestr_*.sh`. Создание сетов ядра: `create_ipset.sh [clear|no-update]`. Имена сетов: `zapret`, `zapret6`, `nozapret`, `nozapret6`, `ipban`, `ipban6`.

## 17. Установка на разные системы

### 17.1 OpenWrt

```sh
opkg install <prereqs>                # см. install_prereq.sh
ln -s /opt/zapret2/init.d/openwrt/zapret2 /etc/init.d
/etc/init.d/zapret2 enable
ln -s /opt/zapret2/init.d/openwrt/90-zapret2 /etc/hotplug.d/iface

# для fw3 (iptables):
ln -s /opt/zapret2/init.d/openwrt/firewall.zapret2 /etc/
uci add firewall include
uci set firewall.@include[-1].path="/etc/firewall.zapret2"
uci set firewall.@include[-1].reload=1
uci commit
```

Команды: `/etc/init.d/zapret2 {start|stop|restart|enable|disable|status}`.

### 17.2 systemd (классический Linux)

Основной вариант — `zapret2.service` (через скрипты zapret2). Альтернативный (только nfqws2, без листов и firewall):

```sh
cp /opt/zapret2/init.d/systemd/nfqws2@.service /lib/systemd/system
systemctl daemon-reload
mkdir /etc/zapret2
# написать /etc/zapret2/<INSTANCE>.conf с опциями
systemctl enable nfqws2@<INSTANCE>
systemctl start nfqws2@<INSTANCE>
```

Для `nfqws2@.service` бинарник должен быть собран как `make systemd` (для sd_notify). Firewall пишется и поднимается отдельно.

### 17.3 OpenRC

```sh
ln -s /opt/zapret2/init.d/openrc/zapret2 /etc/init.d
rc-update add zapret2
```

### 17.4 Entware (на Keenetic / Asus / ...)

Entware — репозиторий user-mode пакетов, ставится в `/opt`. nfqws2 — статический бинарник, запустится почти везде. Скрипты zapret2 опираются на стандартные shell-утилиты — на Entware их хватает, но:

- **Keenetic-specific нюансы**:
  - Из-за проприетарного `ndmmark` родная NAT-логика не masquerade'ит UDP-пакеты от nfqws → они уходят с LAN-IP и дропаются провайдером. Решение: custom-скрипт `10-keenetic-udp-fix` добавляет правило `iptables -t nat -A POSTROUTING -o $wanif -p udp -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j MASQUERADE`. Без этого UDP-стратегии (QUIC, DTLS, WireGuard) рассыпаются.
  - Часто срабатывает «слетание» (зависание/выход nfqws каждые пару минут). Это решается сторонними обёртками, например `zapret-keenetic` (не часть проекта).
- `--user` ищет пользователя в `/etc/passwd` (read-only, заводской), а entware кладёт `adduser` в `/opt/etc/passwd`. → в config обязательно задать `WS_USER=nobody` (он есть в `/etc/passwd`).
- Иногда нет cron — обновление листов придётся пихать в `crond` от entware или ndm-расписания.
- Если в прошивке нет `ipset` или `iptables-mod-conntrack-extra` (для `connbytes`), часть схем перехвата не сработает — выбирай минимальный вариант, либо ставь модули через entware/opkg.
- Хорошо иметь раздел r/w (`/opt` смонтирован с USB-флешки).

Для большинства Keenetic-сборок интеграцию проще всего делать через **готовый sysv-скрипт** + custom.d с `10-keenetic-udp-fix`. PATH должен включать `/opt/bin:/opt/sbin`.

### 17.5 Другие прошивки

Что нужно: shell-доступ, root, r/w раздел, cron, iptables/nftables с conntrack/NFQUEUE, базовые утилиты (`ipset`, `curl`, `awk`, `sed`). Modules ядра: `nfnetlink_queue`, `xt_NFQUEUE`/`nft_queue`, `xt_connbytes`/`nft_ct`. Опционально: для kyber-стратегий — ничего особого; для perf — отключаемый flow offload.

## 18. Стратегии: типовые сборки

Каждый профиль строится по схеме: **фильтр профиля** → **внутрипрофильные фильтры (range/payload)** → **последовательность инстансов**.

### 18.1 HTTP-only (порт 80)

```
--filter-tcp=80 --filter-l7=http
  --out-range=-d10 --payload=http_req
    --lua-desync=fake:blob=fake_default_http:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5
    --lua-desync=fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5
```

### 18.2 TLS 1.2/1.3 (порт 443) с фейком + multidisorder

```
--filter-tcp=443 --filter-l7=tls --hostlist=youtube.txt
  --out-range=-d10 --payload=tls_client_hello
    --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com
    --lua-desync=multidisorder:pos=1,midsld
```

### 18.3 TLS с seqovl (скрытый фейк, без фулинга)

```
--payload=tls_client_hello
  --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000
```

### 18.4 QUIC (UDP 443)

```
--filter-udp=443 --filter-l7=quic --hostlist=youtube.txt
  --payload=quic_initial
    --lua-desync=fake:blob=quic_google:repeats=11
```

`quic_google` предварительно загружен:
```
--blob=quic_google:@/opt/zapret2/files/fake/quic_initial_www_google_com.bin
```

### 18.5 WireGuard/STUN/Discord (UDP)

```
--filter-l7=wireguard,stun,discord
  --payload=wireguard_initiation,wireguard_cookie,stun,discord_ip_discovery
    --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2
```

### 18.6 Циклическая смена стратегий (с детектором неудач)

```
--filter-tcp=80,443 --filter-l7=http,tls
  --out-range=-s34228 --in-range=-s5556
  --lua-desync=circular
  --in-range=x
  --payload=tls_client_hello
    --lua-desync=fake:blob=fake_default_tls:badsum:strategy=1
    --lua-desync=multidisorder:strategy=2
  --payload=http_req
    --lua-desync=fake:blob=fake_default_http:badsum:strategy=1
    --lua-desync=multisplit:strategy=2
```

### 18.7 Кастомный фейк случайного размера (luaexec + tcpseg)

```
--lua-desync=luaexec:code='desync.rnd=brandom_az(math.random(5,10))'
--lua-desync=tcpseg:pos=0,-1:seqovl=#rnd:seqovl_pattern=rnd
--lua-desync=drop:payload=known
```

### 18.8 ICMP-обфускация UDP (для VPN через NAT)

Сервер (Linux):
```
nfqws2 --qnum=200 --server
 --lua-init=@/opt/zapret2/lua/zapret-lib.lua
 --lua-init=@/opt/zapret2/lua/zapret-obfs.lua
 --in-range=a
 --lua-desync=udp2icmp:ccode=199:scode=199
```

Клиент (винда):
```
winws2
 --wf-icmp-in=0:199 --wf-udp-out=5555
 --wf-raw-filter="ip.SrcAddr=1.2.3.4 or ip.DstAddr=1.2.3.4"
 --lua-init=@lua/zapret-lib.lua --lua-init=@lua/zapret-obfs.lua
 --in-range=a
 --lua-desync=udp2icmp:ccode=199:scode=199
```

## 19. Работа с Lua-кодом

### 19.1 Где исполняется Lua

1. **`--lua-init`** — при старте, один раз. Можно строкой или `@file`. Поддерживается `.gz`.
2. **`--lua-desync`** — на каждый пакет, проходящий профиль (после прохода фильтров C-кода).
3. **Таймеры** (`timer_set`).

### 19.2 Прототип desync-функции

```lua
function fnname(ctx, desync)
  -- ctx — для вызова C-функций (rawsend, instance_cutoff, ...)
  -- desync — таблица со всем:
  --   desync.dis        — диссект (.ip / .ip6 / .tcp / .udp / .icmp / .payload / .l4proto / ...)
  --   desync.arg        — аргументы инстанса (после подстановок %, #)
  --   desync.outgoing   — направление
  --   desync.l7payload  — payload type
  --   desync.l7proto    — protocol type
  --   desync.track      — conntrack (может отсутствовать!)
  --   desync.track.lua_state — для хранения состояния на поток
  --   desync.reasm_data — собранный многопакетный пейлоад
  --   desync.replay, desync.replay_piece, ...
  --   desync.tcp_mss    — есть всегда для TCP
  -- ...
  return VERDICT_PASS  -- или VERDICT_MODIFY / VERDICT_DROP (+ VERDICT_PRESERVE_NEXT)
end
```

### 19.3 Полезные C-функции (вызываемые из Lua)

- Лог: `DLOG(s)`, `DLOG_ERR(s)`, `DLOG_CONDUP(s)`.
- IP-конвертация: `ntop(raw)`, `pton(str)`.
- Битовые: `bitand`, `bitor`, `bitxor`, `bitnot`, `bitlshift`, `bitrshift`, `bitget`, `bitset`.
- Безз. числа: `u8/u16/u24/u32`, `bu8/bu16/...`, `swap16/swap32/...`, `u32add` и т.д.
- Случайные: `brandom(n)`, `bcryptorandom(n)`, `brandom_az(n)`.
- Парсинг: `parse_hex(s)`.
- Крипта: `aes`, `aes_gcm`, `aes_ctr`, `hkdf`, `hash`.
- Сжатие: `gzip(b)`, `gunzip(b)`.
- Системные: `uname()`, `clock_gettime()`, `getpid()`, `stat(path)`, `time()`.
- Диссекция: `dissect(raw)`, `reconstruct_dissect(dis, opts)`, `reconstruct_tcphdr`/`...iphdr`/`...ip6hdr`, `csum_*_fix`.
- conntrack: `conntrack_feed(dis_or_raw, opts)`.
- IP/iface: `get_source_ip(target)`, `get_ifaddrs()`.
- Отсылка: `rawsend(raw, opts)`, `rawsend_dissect(dis, opts, recopts)`.
- Управление: `instance_cutoff(ctx[, outgoing])`, `lua_cutoff(ctx[, outgoing])`, `execution_plan(ctx)`, `execution_plan_cancel(ctx)`.
- Таймеры: `timer_set(name, ms, fn, data)`, `timer_del(name)`, `timer_info(name)`, `timer_enum()`.
- Работа с пейлоадами: `resolve_pos(blob, payload_type, marker)`, `resolve_multi_pos`, `resolve_range`, `tls_mod(blob, modlist, payload)`.
- Файлы: `--writeable` создаст каталог, путь в `os.getenv("WRITEABLE")`. ВНИМАНИЕ: песочница — `os.execute`, `io.popen`, `package.loadlib`, модуль `debug` удалены.

### 19.4 Минимальный пример своей desync-функции

```lua
-- file: my-strategy.lua
function my_repeated_fake(ctx, desync)
  if not desync.dis.tcp then
    instance_cutoff_shim(ctx, desync)  -- удобный хелпер из zapret-lib
    return
  end
  -- Используем готовые блоки
  local rep = tonumber(desync.arg.repeats or "3")
  local dis = deepcopy(desync.dis)
  dis.payload = blob(desync, desync.arg.blob)
  apply_fooling(desync, dis)
  for i=1,rep do
    rawsend_dissect_segmented(desync, dis, desync.tcp_mss, desync.arg)
  end
  -- VERDICT_PASS — оригинал пройдёт следом
end
```

Подключаем:
```
--lua-init=@/opt/zapret2/lua/zapret-lib.lua
--lua-init=@/path/my-strategy.lua
--lua-desync=my_repeated_fake:blob=fake_default_tls:repeats=5:ip_autottl=-1,3-20
```

### 19.5 Передача блобов в Lua

```
--blob=mytls:@/etc/myfake.bin
--blob=mytls_with_offset:+12@/etc/myfake.bin
--blob=mytls_hex:0xDEADBEEF
```

После чего в Lua: `mytls` — Lua-переменная типа string (binary).

Подставлять в аргументы desync можно через имя блоба:
```
--lua-desync=fake:blob=mytls
--lua-desync=tcpseg:seqovl=#mytls:seqovl_pattern=mytls
```

`#mytls` развернётся в длину, `%mytls` — в содержимое (применяется на стороне C-кода до вызова Lua).

## 20. Отладка

- `--debug=1` — на консоль; `--debug=@file` — в файл (можно удалить — продолжит писать с нуля); `--debug=syslog`.
- `--dry-run` — проверка валидности параметров и доступности файлов без запуска (Lua-синтаксис НЕ проверяется).
- Сигналы `SIGUSR1`/`SIGUSR2` — дампы conntrack и autohostlist.
- `pktdebug` (`--lua-desync=pktdebug`), `argdebug`, `posdebug` (`zapret-lib.lua`) — отладочные функции, печатают структуру `desync`.
- `var_debug(t)` (Lua) — рекурсивная печать таблицы.

Принцип: при ошибке стратегии — включить debug, кинуть curl на тестовый домен и читать лог. Без `--debug` отладка крайне затруднительна.

## 21. Часто встречаемые проблемы

1. **NAT ломает технику** (synack, tcb-turnaround): нужно nftables + POSTNAT (`POSTNAT=1`). На iptables — не работает.
2. **Keenetic UDP не уходит**: см. `10-keenetic-udp-fix` (MASQUERADE с проверкой mark).
3. **`--user nobody` падает на entware**: указать пользователя из `/etc/passwd`.
4. **Стратегия работает один раз потом перестаёт**: возможно DPI «наказывает» — рассмотри ротацию (`circular`) или включи `--ipcache-hostname` если работаешь нулевой фазой.
5. **multidisorder не работает на Windows-сервере**: Windows не переписывает буфер сокета по seqovl. Используй multisplit.
6. **wssize режет скорость**: применяй только в крайних случаях, дублируй в отдельный профиль до получения hostname.
7. **Большие nft sets едят память**: для ~100K IP нужно 256–320 МБ; iptables ipset помещается в 64 МБ. На слабых роутерах — iptables или режим hostlist без ipset.
8. **autohostlist не наполняется**: нужно перехватывать достаточно входящих пакетов для детектора (`--in-range` пошире) и/или достаточно исходящих ретрансмиссий.
9. **VM не работает**: гипервизорный NAT (VMware, VirtualBox) ломает большинство техник; используй bridge.
10. **Профиль не выбирается до hostname**: если в нём есть `--hostlist=` без autolist — это нормально. Дублируй стратегию в профиль без хостлиста, если нужно действовать с первого пакета.

## 22. Что важно знать для GUI-обёртки

### 22.1 Файлы, которыми оперируешь

- **`/opt/zapret2/config`** — основные настройки (читается init-скриптами).
- **`/opt/zapret2/init.d/{openwrt,sysv,systemd,openrc}/custom.d/`** — пользовательские стратегии (несколько профилей).
- **`/opt/zapret2/ipset/zapret-hosts-user.txt`**, `...-exclude.txt`, `...-ipban.txt` — пользовательские хостлисты.
- **`/opt/zapret2/ipset/zapret-hosts-auto.txt`** — автохостлист (rw).
- **`/opt/zapret2/lua/*.lua`** — стандартные библиотеки (НЕ редактировать, можно докладывать новые .lua рядом).
- **`/opt/zapret2/files/fake/*.bin`** — стандартные фейк-блобы.
- **`/etc/zapret2/<instance>.conf`** — конфиги для `nfqws2@.service` на systemd.

### 22.2 Управление демоном

OpenWrt: `/etc/init.d/zapret2 {start|stop|restart|status|enable|disable}`.
sysv: `/etc/init.d/zapret2 ...`.
systemd: `systemctl ... zapret2` или `systemctl ... nfqws2@<INSTANCE>`.
openrc: `rc-service zapret2 ...`.

Для применения новой конфигурации `NFQWS2_OPT`/custom-скриптов нужен **restart** (не reload — config читается init-скриптом, не самим nfqws2).

Для перечитки только хостлистов: `kill -HUP $(cat <pidfile>)` или `SIGHUP` процессу nfqws2 → перечитает все хостлисты/ipset-ы без рестарта.

### 22.3 Что важно валидировать в UI

- **Уникальность qnum** (если своих демонов несколько).
- Балансы скобок и кавычек в `--lua-desync=fn:arg=val`.
- Что заданы все нужные blob-ы (`--blob=...`).
- Что `--filter-tcp/--filter-udp` указаны там, где есть `--payload` с tcp/udp-пейлоадами.
- Что между профилями есть `--new`.
- Что в `--lua-init` подключены `zapret-lib.lua`, `zapret-antidpi.lua` (а для оркестраторов — ещё и `zapret-auto.lua`).
- Что `MODE_FILTER` соответствует наличию листов.
- Что для Keenetic есть `WS_USER`, включён `10-keenetic-udp-fix` (если используется UDP).
- Что `OPENWRT_LAN/WAN*` — это netifd-имена, а `IFACE_*` — Linux-имена.

### 22.4 Тестирование стратегии перед сохранением

```sh
nfqws2 --dry-run <всё то же что для запуска>     # проверка опций
# либо запустить вживую с --debug=1 на свободном qnum и временной nft-таблице (см. ztest)
```

Для интеграции с blockcheck2: дать пользователю запустить `blockcheck2.sh` с его доменом и опциями (`BATCH=1 DOMAINS=... TEST=standard SCANLEVEL=quick`), получить лог, и предложить применить найденные стратегии.

### 22.5 Места, куда писать кастом без потери при апдейте

- `config` (сохраняется инсталлятором как `keep`).
- `init.d/*/custom.d/*` (сохраняется).
- `ipset/zapret-hosts-user*.txt` (сохраняется).
- `ipset/zapret-hosts-auto.txt` (сохраняется).

Свои .lua, .bin, .conf — **не** в `/opt/zapret2`, а в отдельный каталог (например `/opt/etc/zapret2-gui/`), и подключай через полные пути в `NFQWS2_OPT` или в custom-скриптах.

### 22.6 Поток данных GUI ⇄ zapret

Минимальный набор операций для обёртки:
1. Чтение/запись `config` (key=value shell).
2. Чтение/запись `custom.d/*` файлов (shell-includes — лучше шаблонизировать).
3. Управление файлами хостлистов в `ipset/`.
4. Команды `restart` / `restart_daemons` / `restart_fw` / `start_fw` / `stop_fw`.
5. Перечитка хостлистов: `kill -HUP` или вызвать инструмент через init-скрипт.
6. Просмотр лога (`--debug=@file`).
7. Запуск `blockcheck2.sh` (с захватом stdout).
8. Просмотр статуса службы.
9. (опционально) парсинг `--lua-desync=...` в структурированную форму и обратно — формат регулярен: `fn:k1[=v1]:k2[=v2]`, разделитель `:`, эскейп `\:`, значения — строки.

## 23. Ссылки на исходные документы

- `docs/manual.md` — полный мануал (Russian, ~5800 строк).
- `docs/manual.en.md` — English version.
- `docs/readme.md` — короткое введение/портирование стратегий nfqws1 → nfqws2.
- `docs/changes.txt`, `docs/changes_compat.txt` — история изменений.
- `lua/zapret-antidpi.lua` — комментарии перед каждой функцией описывают её аргументы. **Главный источник правды по стратегиям**.
- `lua/zapret-lib.lua` — хелперы (для написания своих desync).
- `lua/zapret-auto.lua` — оркестраторы.
- `init.d/custom.d.examples.linux/` — готовые рабочие custom-скрипты.
- `blockcheck2.d/standard/` — модули стандартного теста; `blockcheck2.d/custom/list_*.txt` — пресет-стратегии.
- `config.default` — дефолтный config с подробными комментариями.

## 24. Шпаргалка по командам

| Действие | Команда |
|:--|:--|
| Старт службы (OpenWrt) | `/etc/init.d/zapret2 start` |
| Стоп | `/etc/init.d/zapret2 stop` |
| Рестарт | `/etc/init.d/zapret2 restart` |
| Только демоны | `/etc/init.d/zapret2 restart_daemons` |
| Только firewall | `/etc/init.d/zapret2 restart_fw` |
| Список сетов (nft) | `/etc/init.d/zapret2 list_ifsets` |
| Дамп таблицы (nft) | `/etc/init.d/zapret2 list_table` |
| Перезагрузить листы | `kill -HUP <pid>` |
| Дамп conntrack | `kill -USR1 <pid>` |
| Дамп autohostlist | `kill -USR2 <pid>` |
| Обновить хостлисты | `/opt/zapret2/ipset/get_config.sh` |
| Создать ipset из листов | `/opt/zapret2/ipset/create_ipset.sh` |
| Очистить ipset | `/opt/zapret2/ipset/create_ipset.sh clear` |
| Удалить генерируемые листы | `/opt/zapret2/ipset/clear_lists.sh` |
| Запустить blockcheck | `/opt/zapret2/blockcheck2.sh` |
| Проверка опций | `nfqws2 --dry-run <opts>` |
| Версия | `nfqws2 --version` |

---

**Главное правило при работе со стратегией**: пиши `--debug=1`, дёргай curl-ом нужный домен, читай лог. Без debug — слепая работа.
