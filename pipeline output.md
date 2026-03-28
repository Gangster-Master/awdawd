
```yaml
output {

  # ── 1: Elasticsearch ga (barcha loglar) ──────────────
  elasticsearch {
    hosts    => ["https://elasticsearch:9200"]
    index    => "siem-events-%{+YYYY.MM.dd}"
    user     => "logstash_writer"
    password => "${ES_PASSWORD}"
  }

  # ── 2: Wazuh Manager ga (Syslog format) ──────────────
  # Wazuh tashqi log qabul qiladi — Syslog orqali
  syslog {
    host => "wazuh-manager"
    port => 514
    protocol => "tcp"
    # ECS maydonlardan Syslog format yasash
    codec => line {
      format => "<%{[log][level]}>%{[event][module]}: %{message}"
    }
  }
}
```


decoder

```xml
<!-- linux-auth decoder -->
<decoder name="linux-ssh-failed">
  <prematch>ssh-login-failed</prematch>
  <regex>src_ip=(\S+)</regex>
  <order>srcip</order>
</decoder>

<decoder name="linux-ssh-success">
  <prematch>ssh-login-success</prematch>
  <regex>src_ip=(\S+)</regex>
  <order>srcip</order>
</decoder>

<decoder name="postgres-auth-fail">
  <prematch>postgres-auth-failed</prematch>
  <regex>src_ip=(\S+)</regex>
  <order>srcip</order>
</decoder>

<decoder name="nginx-sqli">
  <prematch>sql-injection</prematch>
  <regex>src_ip=(\S+)</regex>
  <order>srcip</order>
</decoder>
```

```xml
<decoder name="...">
  <parent>...</parent>       ← Ixtiyoriy
  <prematch>...</prematch>   ← Birinchi filtr
  <regex>...</regex>         ← Maydon ajratish
  <order>...</order>         ← Maydon nomlari
</decoder>
```

Decoder uch bosqichda ishlaydi:
```
Log keldi
    │
    ▼
prematch: "Bu log menikimi?" → HA/YO'Q
    │
    ▼ HA
regex: "Maydonlarni ajrat"
    │
    ▼
order: "Ajratilgan maydonlarga nom ber"
```

1. linux-ssh-failed
```xml
<decoder name="linux-ssh-failed">
  <prematch>ssh-login-failed</prematch>
  <regex>src_ip=(\S+)</regex>
  <order>srcip</order>
</decoder>
```


**`name="linux-ssh-failed"`**

Decoder nomi. Qoidada `decoded_as` bilan ishlatiladi:

```xml
<rule>
  <decoded_as>linux-ssh-failed</decoded_as>
  ...
</rule>
```
Bu nom orqali qoida "faqat shu decoder parse qilgan eventlar uchun ishlash" deydi.

---

**`<prematch>ssh-login-failed</prematch>`**

Birinchi va eng tez filtr. Log matnida bu string bor-yo'qligini tekshiradi. Regex emas — oddiy string search. Juda tez ishlaydi.
```yaml
Log 1: "ssh-login-failed src_ip=45.92.X.X user=admin"
  prematch: "ssh-login-failed" bor? → HA → davom et

Log 2: "ssh-login-success src_ip=45.92.X.X"
  prematch: "ssh-login-failed" bor? → YO'Q → bu decoder o'tkazib yuboradi

Log 3: "postgres-auth-failed src_ip=45.92.X.X"
  prematch: "ssh-login-failed" bor? → YO'Q → o'tkazib yuboradi
```

Prematch muhim — barcha logni regex bilan tekshirish sekin. Prematch avval tez filtr qiladi, keyin regex ishlaydi.

---

**`<regex>src_ip=(\S+)</regex>`**

Prematch o'tgan logdan maydonlarni ajratadi. `(\S+)` — capturing group, bo'sh joy bo'lmagan belgilar ketma-ketligi.
```yml
Log: "ssh-login-failed src_ip=45.92.1.100 user=admin"

regex: src_ip=(\S+)
  src_ip=   → literal match (shu belgilar bo'lsin)
  (\S+)     → capturing group:
              \S = bo'sh joy emas (harf, raqam, nuqta, ...)
              +  = bir yoki ko'p marta
              () = shu qismni "ushlaydi"

Natija: "45.92.1.100" ushlandi
```

---

**`<order>srcip</order>`**

Ushlangan qiymatga nom beradi. `srcip` — Wazuh'ning standart maydon nomi. IP manzil uchun.
```yml
regex: src_ip=(\S+) → "45.92.1.100" ushlandi
order: srcip        → event.srcip = "45.92.1.100"

Endi qoidada:
  <same_source_ip /> → event.srcip ishlatadi
```

**Standart Wazuh maydon nomlari:**
```yml
srcip    → Source IP manzil
dstip    → Destination IP
user     → Foydalanuvchi nomi
url      → URL manzil
id       → Event ID
data     → Qo'shimcha ma'lumot
```

---

**To'liq ishlash misoli:**
```yml
Logstash dan Wazuh ga keldi:
  "ssh-login-failed src_ip=45.92.1.100 user=admin port=52341"

Decoder linux-ssh-failed:
  prematch: "ssh-login-failed" → HA ✅
  regex:    src_ip=(\S+)       → "45.92.1.100" ushlandi
  order:    srcip              → event.srcip = "45.92.1.100"

Natija — Wazuh event:
  decoder.name = "linux-ssh-failed"
  srcip        = "45.92.1.100"
  full_log     = original log
```

real-time detection + korrelyatsiya

```xml
<!-- Qadam 1: SSH fail -->
<rule id="100001" level="5">
  <decoded_as>linux-ssh-failed</decoded_as>
  <description>SSH Authentication Failure</description>
  <group>authentication_failure</group>
</rule>

<!-- Qadam 2: Brute force -->
<rule id="100002" level="10">
  <if_matched_sid>100001</if_matched_sid>
  <same_source_ip />
  <occurrence>5</occurrence>
  <timeframe>120</timeframe>
  <description>SSH Brute Force Detected</description>
  <group>brute_force,correlation</group>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>

<!-- Qadam 3: Brute force + success -->
<rule id="100003" level="15">
  <if_matched_sid>100002</if_matched_sid>
  <same_source_ip />
  <decoded_as>linux-ssh-success</decoded_as>
  <timeframe>300</timeframe>
  <description>
    CRITICAL: Brute Force then Successful Login
  </description>
  <group>attack_chain,correlation</group>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
  </mitre>
</rule>

<!-- Qadam 4: SQL injection -->
<rule id="100004" level="15">
  <if_matched_sid>100003</if_matched_sid>
  <same_source_ip />
  <decoded_as>nginx-sqli</decoded_as>
  <timeframe>600</timeframe>
  <description>
    CRITICAL: Full Attack Chain Confirmed
  </description>
  <group>attack_chain,critical</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>

<!-- PostgreSQL brute force -->
<rule id="100005" level="8">
  <decoded_as>postgres-auth-fail</decoded_as>
  <same_source_ip />
  <occurrence>3</occurrence>
  <timeframe>60</timeframe>
  <description>PostgreSQL Brute Force</description>
  <group>brute_force,database</group>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

2. linux-ssh-success
```xml
<decoder name="linux-ssh-success">
  <prematch>ssh-login-success</prematch>
  <regex>src_ip=(\S+)</regex>
  <order>srcip</order>
</decoder>
```

linux-ssh-failed bilan bir xil tuzilma — faqat prematch farqli.

**`<prematch>ssh-login-success</prematch>`**
```yml
Log: "ssh-login-success src_ip=45.92.1.100 user=admin"
  prematch: "ssh-login-success" bor? → HA ✅

Log: "ssh-login-failed src_ip=..."
  prematch: "ssh-login-success" bor? → YO'Q ❌
```


Bu decoder faqat muvaffaqiyatli loginlarni ushlaydi. Qoidada:
```xml
<rule id="100003" level="15">
  <if_matched_sid>100002</if_matched_sid>
  <decoded_as>linux-ssh-success</decoded_as>
  ...
</rule>
```

"Brute force bo'lgandan keyin, shu IP dan muvaffaqiyatli login keldi" — korrelyatsiya shu yerda.

1.
```yml
filter {
  if "nginx-proxy" in [tags] {

    grok {
      match => {
        "message" => '\[%{HTTPDATE:device_time}\] - %{NUMBER:upstream_status:int} %{NUMBER:response_code:int} - %{WORD:http_method} %{WORD:protocol} %{HOSTNAME:http_host} "%{DATA:uri}" \[Client %{IP:source_ip}\] \[Length %{NUMBER:response_bytes:int}\] \[Gzip %{DATA:gzip_status}\] \[Sent-to %{IP:backend_ip}\] "%{DATA:user_agent}" "%{DATA:referer}"'
      }
      tag_on_failure => ["_grokparsefailure_nginx_proxy"]
    }

    if !("_grokparsefailure_nginx_proxy" in [tags]) {

      date {
        match    => ["device_time", "dd/MMM/yyyy:HH:mm:ss Z"]
        target   => "@timestamp"
        timezone => "UTC"
      }

      mutate {
        rename => {
          "source_ip"      => "[source][ip]"
          "backend_ip"     => "[destination][ip]"
          "http_method"    => "[http][request][method]"
          "uri"            => "[url][path]"
          "http_host"      => "[url][domain]"
          "user_agent"     => "[user_agent][original]"
          "referer"        => "[http][request][referrer]"
          "response_code"  => "[http][response][status_code]"
          "response_bytes" => "[http][response][bytes]"
          "upstream_status"=> "[nginx][upstream_status]"
          "protocol"       => "[network][protocol]"
        }
        add_field => {
          "[event][module]"  => "nginx-proxy"
          "[event][dataset]" => "nginx.proxy_access"
          "[event][kind]"    => "event"
          "[ecs][version]"   => "8.11.0"
        }
        remove_field => ["device_time", "gzip_status"]
      }
    }
  }
}
```

2. Kategoriya ajratmasangiz Wazuh'ga **barcha maydonlarni** yuborasiz, Wazuh o'zi regex bilan ajratadi:
```yml
output {
  syslog {
    host     => "wazuh-manager"
    port     => 514
    protocol => "tcp"
    codec    => line {
      format => "nginx-proxy source.ip=%{[source][ip]} destination.ip=%{[destination][ip]} http.method=%{[http][request][method]} http.uri=%{[url][path]} http.status=%{[http][response][status_code]} host.name=%{[url][domain]} http.bytes=%{[http][response][bytes]} useragent=%{[user_agent][original]}"
    }
  }
}
```

Wazuh'ga yuboriladigan log:
```yml
nginx-proxy source.ip=10.227.214.17 destination.ip=10.1.27.111
  http.method=GET http.uri=/assets/index.bde10176.css
  http.status=200 host.name=doc.iiv.uz http.bytes=1284804
  useragent=Mozilla/5.0...
```

3. Decoder

```<!-- Ota decoder — barcha nginx-proxy loglar -->
<decoder name="nginx-proxy">
  <prematch>nginx-proxy</prematch>
</decoder>

<!-- Bola decoder — barcha maydonlar -->
<decoder name="nginx-proxy-access">
  <parent>nginx-proxy</parent>
  <regex>source\.ip=(\S+) destination\.ip=(\S+) http\.method=(\S+) http\.uri=(\S+) http\.status=(\d+) host\.name=(\S+) http\.bytes=(\d+)</regex>
  <order>srcip, dstip, http_method, url, status, hostname, extra_data</order>
</decoder>
```

**Muhim nuance:**

Siz yozgan `source.ip=(\S+)` da nuqta regex da **istalgan belgi** degani. Ekranlash kerak: `source\.ip=(\S+)`.

---

## 4. Alert kelganda analyst fieldlarni qayerdan oladi?

**Avtomatik biriktiriladi** — analyst hech narsa qilmaydi.

Qanday ishlaydi:
```
Log keldi:
  "nginx-proxy source.ip=10.227.214.17 destination.ip=10.1.27.111
   http.method=GET http.uri=/login http.status=401
   host.name=doc.iiv.uz http.bytes=512"
        │
        ▼
Decoder ishladi:
  srcip     = "10.227.214.17"
  dstip     = "10.1.27.111"
  http_method = "GET"
  url       = "/login"
  status    = "401"
  hostname  = "doc.iiv.uz"
  extra_data = "512"
        │
        ▼
Rule 110003 ishladi (401 → unauthorized)
        │
        ▼
Wazuh Alert yaratildi — ichida HAMMASI bor:
  {
    "rule": {
      "id": "110003",
      "level": 4,
      "description": "Nginx Proxy: Unauthorized Access",
      "groups": ["nginx", "authentication"],
      "mitre": {"id": ["T1110.001"]}
    },
    "decoder": {
      "name": "nginx-proxy-access"
    },
    "data": {
      "srcip":       "10.227.214.17",  ← decoder ajratdi
      "dstip":       "10.1.27.111",    ← decoder ajratdi
      "http_method": "GET",            ← decoder ajratdi
      "url":         "/login",         ← decoder ajratdi
      "status":      "401",            ← decoder ajratdi
      "hostname":    "doc.iiv.uz"      ← decoder ajratdi
    },
    "full_log": "nginx-proxy source.ip=...", ← original log
    "timestamp": "2026-03-09T14:00:36Z",
    "agent": {"name": "web-server-01"}
  }
```

Kibana'da analyst ko'radi:
```
Alert #110021 — Auth Brute Force
  Source IP:   10.227.214.17    ← data.srcip
  Destination: 10.1.27.111      ← data.dstip
  Method:      GET              ← data.http_method
  URI:         /login           ← data.url
  Status:      401              ← data.status
  Host:        doc.iiv.uz       ← data.hostname
  Count:       10 times         ← occurrence
  Timeframe:   2 minutes        ← timeframe
  MITRE:       T1110.001        ← rule.mitre
```

---

## 5. same_source_ip qanday ishlaydi


**Wazuh xotirada sliding window saqlaydi:**
```
Wazuh Manager xotirasida (RAM):

sid_cache = {
  "110003": {
    "10.227.214.17": [
      timestamp_1,   ← 14:00:01
      timestamp_2,   ← 14:00:15
      timestamp_3,   ← 14:00:31
      ...
    ],
    "45.92.1.100": [
      timestamp_1,
      timestamp_2,
    ]
  }
}
```

**Har event kelganda:**
```
1. Rule 110003 ishladi (401 keldi)
   srcip = "10.227.214.17"

2. sid_cache["110003"]["10.227.214.17"] ga timestamp qo'shildi

3. Eski timestamplar o'chirildi (timeframe=120 sek o'tganlar)

4. Soni tekshirildi:
   len(sid_cache["110003"]["10.227.214.17"]) >= occurrence(10)?
     8  → YO'Q → davom et
     9  → YO'Q → davom et
     10 → HA  → Rule 110021 ISHLADI!
```

**Aniq misol — vaqt bilan:**
```
14:00:01 → 401 keldi, srcip=10.227.214.17
  cache: [T1]         → count=1  < 10 → yo'q

14:00:15 → 401 keldi, srcip=10.227.214.17
  cache: [T1, T2]     → count=2  < 10 → yo'q

14:00:31 → 401 keldi, srcip=45.92.1.100  ← BOSHQA IP
  cache["10.227.214.17"]: [T1,T2] → o'zgarmadi
  cache["45.92.1.100"]:   [T3]    → alohida hisoblanadi

14:01:45 → 401 keldi, srcip=10.227.214.17
  T1 eskirdi (120 sek o'tdi, 14:00:01 → 14:01:45 = 104 sek)
  Hali eskirmagan: [T2...T9]
  count=9 < 10 → yo'q

14:01:58 → 401 keldi, srcip=10.227.214.17
  cache: [T2...T10]   → count=10 >= 10 → MATCH!
  Rule 110021 ISHLADI!
```




**Offense indeksi — siem-offenses:**

```
Wazuh alert keldi
      │
      ▼
Offense Manager tekshiradi:
  "Bu source IP uchun ochiq offense bormi?"
  "Timeframe ichidami? (masalan 1 soat)"
      │
      ├── BOR  → Mavjudga biriktir
      │         event_count++
      │         magnitude yangilа
      │         contributing_rules ga qo'sh
      │
      └── YO'Q → Yangi offense yarat
                 Elasticsearch ga yoz
```


```json
{
  "offense_id": "OFF-2026-001",
  "status": "OPEN",
  "source_ip": "45.92.1.100",
  "magnitude": 9,
  "event_count": 3,
  "start_time": "2026-03-28T14:00:00Z",
  "last_updated": "2026-03-28T14:08:00Z",
  "contributing_rules": [
    {"id": "110021", "name": "Auth Brute Force", "level": 10},
    {"id": "110030", "name": "Scanner + SQLi",   "level": 13},
    {"id": "110031", "name": "Dir scan + SQLi",  "level": 14}
  ],
  "mitre_tactics": ["T1110.001", "T1595", "T1190"],
  "timeline": [
    {"time": "14:00", "alert": "Auth Brute Force"},
    {"time": "14:05", "alert": "Scanner detected"},
    {"time": "14:08", "alert": "SQL Injection"}
  ]
}
```





---

## Offense Manager qaysi texnologiyada?
```
Variant 1: Python servis (sodda)
  Wazuh webhook → Python → ES offense index

Variant 2: Logstash pipeline (mavjud stack ichida)
  Wazuh alert → Logstash → Offense logic → ES

Variant 3: Go servis (tez)
  Wazuh webhook → Go → Redis (active offenses) → ES
```

**Eng mos:** Python yoki Go — chunki sliding window va IP asosida birlashtirish mantiqini kod bilan yozish kerak.

---

## Yangilangan arxitektura
```
Wazuh Alert yaratildi
      │
      ▼ webhook
Offense Manager
  ├── Redis: "45.92.1.100 uchun OFF-001 bor"
  ├── BOR   → ES offense yangilandi
  └── YO'Q  → ES offense yaratildi
      │
      ▼
siem-offenses-* (ES)
      │
      ▼
Kibana — Offense Dashboard
  OFF-001 | Magnitude: 9 | Events: 3 | OPEN
  └── Brute Force → Scanner → SQL Injection
```

---

## Magnitude hisoblash

QRadar'dagi kabi:
```
Har yangi alert kelganda:
  current_magnitude = max(contributing_rules levels)
  event_count       → magnitude oshiradi (+0.5 har 10 alertda)
  asset_weight      → kritik server bo'lsa +1
  
  Final magnitude = min(10, base + bonuses)
```

---

## Kibana da ko'rinishi
```
OFFENSE LIST:
┌─────────────────────────────────────────────────────┐
│ OFF-001 │ Mag:9 │ 45.92.1.100 │ 3 alerts │ OPEN    │
│ OFF-002 │ Mag:6 │ 192.168.1.5 │ 1 alert  │ OPEN    │
│ OFF-003 │ Mag:4 │ 10.0.0.55   │ 2 alerts │ CLOSED  │
└─────────────────────────────────────────────────────┘

OFF-001 detail:
  Timeline:
    14:00 → Brute Force (level 10)
    14:05 → Scanner (level 8)
    14:08 → SQL Injection (level 13) ← CRITICAL
  MITRE: T1110.001 → T1595 → T1190
  Status: OPEN → analyst yopadi
```

---

## Xulosa — nima o'zgardi
```
Oldin:
  3 alert → 3 alohida yozuv → analitik chalkashadi

Keyin (Offense Manager bilan):
  3 alert → 1 offense → to'liq attack chain
  Magistrate kabi birlashtirish
  Timeline ko'rinadi
  MITRE mapping to'planadi
  Magnitude o'sib boradi
  Analitik bitta joydan ko'radi

Qo'shimcha komponent:
  Offense Manager servis (Python/Go)
  Redis (active offense cache)
  siem-offenses-* index (ES)
  Offense dashboard (Kibana)
```

![[Pasted image 20260328092802.png]]






























```
<!-- ossec.conf da -->
<integration>
  <name>elasticsearch</name>
  <hook_url>https://elasticsearch:9200/siem-alerts/_doc</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

---

### 4. Elasticsearch — Storage
```
Uchta index:

siem-events-*    → Barcha normalize loglar
                   Logstash'dan keladi
                   Threat hunting uchun

siem-alerts-*    → Wazuh alertlari
                   Wazuh Manager'dan keladi
                   Real-time detection natijalari

siem-anomalies-* → ES|QL anomaliyalar
                   Watcher'dan keladi
                   Baseline og'ishlari
```

---

### 5. ES|QL Watcher — Anomaly Detection
```
Har 5 daqiqada ishlatiladi:
  "Bu IP odatdagidan ko'p so'rov yubormoqdami?"
  "Tun yarimida kim login qildi?"
  "DNS query hajmi baseline dan 200% oshdi?"

Natija → siem-anomalies-* ga yoziladi
```

---

### 6. Kibana — UI
```
Uchta ko'rinish:

Alerts Dashboard:
  siem-alerts-* dan
  Wazuh alertlarini ko'rsatadi
  Level, MITRE, source IP

Threat Hunting:
  siem-events-* dan
  KQL/ES|QL bilan manual qidiruv
  "Bu IP oxirgi 7 kunda nima qildi?"

Anomaly Dashboard:
  siem-anomalies-* dan
  ES|QL natijalarini ko'rsatadi
```

---

## Ma'lumot oqimi — to'liq
```
45.92.X.X → SSH brute force qilmoqda

Server:
  Auth log: "Failed password for admin from 45.92.X.X"
        │
        ▼
Sizning Agent:
  Log o'qidi → Logstash ga yubordi
        │
        ▼
Logstash Filter:
  Grok parse:
    event.action   = "ssh-login-failed"
    event.outcome  = "failure"
    source.ip      = "45.92.X.X"
    user.name      = "admin"
  ECS normalize qilindi
        │
        ├──────────────────────────────┐
        ▼                              ▼
Elasticsearch                   Wazuh Manager
siem-events-*                   Syslog format keldi
(threat hunting uchun)                 │
                                       ▼
                                Decoder: linux-ssh-failed
                                srcip = 45.92.X.X
                                       │
                                       ▼
                                Rules Engine:
                                  100001: level 5 ✅
                                  (1-fail, hali brute force emas)

[2 daqiqada 5 marta keldi]
                                       │
                                       ▼
                                Rules Engine:
                                  100002: 5x same IP
                                  120 sek ichida → MATCH!
                                  Level 10 Alert ✅
                                       │
                                       ▼
[Keyin muvaffaqiyatli login]
                                       │
                                       ▼
                                Rules Engine:
                                  100003: if_matched 100002
                                  same IP, ssh-success
                                  → Level 15 CRITICAL! ✅
                                       │
                                       ▼
                                Alert Manager:
                                  JSON alert yaratdi
                                  MITRE: T1110, T1078
                                       │
                                       ▼
                                Elasticsearch
                                siem-alerts-*
                                       │
                                       ▼
                                Kibana Dashboard
                                Email/Slack
```