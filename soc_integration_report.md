# Leak/OSINT + OpenCTI → SOC Integratsiya
## To'liq Texnik Arxitektura Hisoboti

**Tayyorlangan:** 2026-05-19  
**Loyiha:** leak_data / leak_UI → OpenCTI → SOC  
**Maqsad:** Milliy CERT/SOC infratuzilmasini to'liq ochiq manbali yechim bilan qurish

---

## MUNDARIJA

1. [Umumiy konsepsiya](#1-konsepsiya)
2. [SOC komponentlari](#2-komponentlar)
3. [To'liq arxitektura](#3-arxitektura)
4. [Ma'lumot oqimlari (Data Flows)](#4-data-flows)
5. [Integratsiya xaritasi](#5-integratsiya-xaritasi)
6. [Har bir komponent batafsil](#6-komponentlar-batafsil)
7. [Docker deployment rejasi](#7-deployment)
8. [Port va tarmoq rejasi](#8-tarmoq)
9. [Server talablari](#9-server)
10. [Amalga oshirish bosqichlari](#10-bosqichlar)
11. [Xulosa](#11-xulosa)

---

## 1. KONSEPSIYA

### Hozirgi holat

```
leak_data (izolyatsiyada ishlaydi)
  ├── 5.13B credential
  ├── Shodan 24,897 host
  ├── CVE/KEV/EPSS risk scoring
  ├── RIPE 123 ASN / 787 prefix
  └── Alerts (ko'rilmay qoladi)
```

### Maqsad holat

```
leak_data ─────────────────────────────────────────────┐
OpenCTI  ─── threat intel ────────────────────────────┤
                                                        ▼
                                              SOC Platform
                                         ┌────────────────────┐
                                         │  Wazuh (SIEM/XDR)  │
                                         │  TheHive (Cases)   │
                                         │  Cortex (Analysis) │
                                         │  Shuffle (SOAR)    │
                                         └────────────────────┘
                                                        │
                                              Analyst → CERT-UZ Hisobot
```

### Asosiy g'oya

Sizning tizimingiz faqat **ma'lumot to'plamaydi** — u endi:
- Har bir alertni avtomatik case'ga aylantiradi
- Har bir IoC'ni 10+ manbadan boyitadi
- Analyst bir tugma bilan PDF hisobot oladi
- CERT-UZ ga STIX/TAXII orqali ulashadi

---

## 2. SOC KOMPONENTLARI

### To'liq stack (hammasi ochiq manba, bepul)

| Komponent | Rol | Texnologiya | Port |
|-----------|-----|-------------|------|
| **leak_data** | OSINT ma'lumot manbai | FastAPI + PostgreSQL | 8000 |
| **leak_UI** | Operator interfeysi | Next.js | 3000 |
| **OpenCTI** | Threat Intelligence Platform | Node.js + ElasticSearch | 8080 |
| **Wazuh** | SIEM / XDR / Log management | OpenSearch-based | 55000, 443 |
| **TheHive** | Case management | Scala + Cassandra | 9000 |
| **Cortex** | Avtomatik tahlil / enrichment | Python | 9001 |
| **Shuffle** | SOAR / Playbook avtomatizatsiya | Go + React | 3001 |
| **MISP** | Threat sharing (CERT-UZ) | PHP + MySQL | 80/443 |

---

## 3. TO'LIQ ARXITEKTURA

```
╔══════════════════════════════════════════════════════════════════════╗
║                     MA'LUMOT MANBALARI                               ║
║                                                                      ║
║  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌──────────────┐  ║
║  │ PostgreSQL  │  │   Shodan    │  │   RIPE   │  │  NVD/KEV/    │  ║
║  │ 5.13B creds │  │ 24K hosts   │  │ ASN/pref │  │  EPSS feeds  │  ║
║  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  └──────┬───────┘  ║
║         └────────────────┴──────────────┴───────────────┘           ║
║                                  │                                   ║
║                            leak_data API                             ║
║                            (FastAPI :8000)                           ║
╚══════════════════════════════════════════════════════════════════════╝
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
╔═══════════╗  ╔═══════════╗  ╔══════════════════════════════════════╗
║  OpenCTI  ║  ║   MISP    ║  ║         SHUFFLE (SOAR)              ║
║  :8080    ║  ║  :80/443  ║  ║             :3001                   ║
║           ║  ║           ║  ║                                      ║
║ MITRE     ║  ║ Threat    ║  ║  Playbook 1: Credential Alert       ║
║ ATT&CK    ║  ║ sharing   ║  ║  Playbook 2: C2 Detection           ║
║ ThreatFox ║  ║ CERT-UZ   ║  ║  Playbook 3: CVE Critical          ║
║ OTX feeds ║  ║ STIX/TAXII║  ║  Playbook 4: RIPE Change           ║
║ C2 IoC    ║  ║           ║  ║  Playbook 5: Shodan New Host       ║
╚═════╤═════╝  ╚═════╤═════╝  ╚═══════════════════╤════════════════╝
      │               │                             │
      └───────────────┴─────────────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │       TheHive :9000         │
                    │    (Case Management)        │
                    │                             │
                    │  Alert → Case → Task        │
                    │  Observable enrichment      │
                    │  Analyst assignment         │
                    │  SLA tracking               │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │       Cortex :9001          │
                    │   (Analysis Engine)         │
                    │                             │
                    │  Shodan analyzer            │
                    │  VirusTotal analyzer        │
                    │  AbuseIPDB analyzer         │
                    │  OpenCTI analyzer           │
                    │  leak_data analyzer (yangi) │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │       Wazuh :443            │
                    │     (SIEM / XDR)            │
                    │                             │
                    │  Log aggregation            │
                    │  Detection rules            │
                    │  Real-time monitoring       │
                    │  Dashboard                  │
                    └────────────────────────────┘
```

---

## 4. MA'LUMOT OQIMLARI (DATA FLOWS)

### Flow 1 — Credential Leak Aniqlash

```
1. leak_data: yangi fayl upload → credentials parse qilinadi
2. Domain root_domain .uz bo'lsa → Alert yaratiladi (severity: high)
3. Alert → Shuffle webhook (POST /api/v1/hooks/webhook_leak)
4. Shuffle Playbook 1 ishga tushadi:
   a. AbuseIPDB'dan domen IP reputation tekshiradi
   b. OpenCTI'dan domen threat context tekshiradi
   c. VirusTotal'dan domen reputatsiyasi oladi
5. Agar tashkilot hukumat/bank bo'lsa → TheHive'da CRITICAL case yaratadi
6. Cortex analyzer: domen + IP to'liq tahlil
7. Analyst xabardor qilinadi (email/Telegram)
8. Case yechilganda → MISP orqali CERT-UZ ga yuboriladi
```

### Flow 2 — C2 Server Detection (Eng muhim)

```
1. OpenCTI: ThreatFox/Feodo connector → yangi C2 IP qo'shiladi
2. OpenCTI webhook → Shuffle webhook trigger
3. Shuffle Playbook 2:
   a. IP ni leak_data shodan_hosts da tekshiradi
   b. IP ni RIPE prefixes da tekshiradi (UZ tarmog'idami?)
   c. VirusTotal + AbuseIPDB enrichment
4. Match topilsa:
   → TheHive'da CRITICAL case yaratiladi
   → "APT C2 server UZ tarmog'ida" deb belgilanadi
   → ISP ga xabarnoma yuborish uchun task yaratiladi
5. MISP orqali boshqa CERT larga ulashiladi
6. PDF hisobot avtomatik generatsiya qilinadi
```

### Flow 3 — CVE Critical Alert

```
1. leak_data: sync_cve.py → yangi CRITICAL/HIGH CVE topiladi
2. Alert → Shuffle webhook
3. Shuffle Playbook 3:
   a. CVE shodan_vulns jadvalida bor-yo'qligini tekshiradi
   b. Qaysi UZ tashkilotlari zaif ekanini aniqlaydi (shodan_hosts + ripe_asns)
   c. EPSS score va KEV statusini oladi
4. Agar KEV = true va UZ da zaif host bor:
   → TheHive CRITICAL case
   → Zaif tashkilotlar ro'yxati task sifatida qo'shiladi
   → 72 soatlik SLA timer boshlanadi
5. PDF hisobot: CVE + zaif hostlar + tashkilotlar + remediation
6. MISP orqali CERT-UZ'ga yuboriladi
```

### Flow 4 — RIPE Monitoring

```
1. leak_data: monitor_ripe_trends.py → prefix o'zgarish aniqlandi
2. Alert (new_prefix / removed_prefix / new_asn)
3. Shuffle Playbook 4:
   a. Yangi prefix/ASN legitimmi? (RIPE WHOIS tekshiradi)
   b. BGP hijack ehtimoli? (prefix manbai tahlili)
   c. Yangi hostlar skanerlash kerakmi?
4. Shubhali bo'lsa → TheHive Medium/High case
5. Yangi prefix → avtomatik Shodan scanning trigger
```

### Flow 5 — Wazuh Log Analysis

```
Agar Wazuh agent server larga o'rnatilsa:
1. Server loglarini Wazuh'ga yuboradi
2. Wazuh qoidalari: SQL injection, brute force, privilege escalation...
3. Alert level 12+ → Shuffle webhook
4. Shuffle: OpenCTI enrichment + TheHive case
5. Cortex: file hash / IP / domain tahlili
```

---

## 5. INTEGRATSIYA XARITASI

### Tizimlar o'rtasidagi ulanishlar

```
┌──────────────┐     webhook POST      ┌─────────────┐
│  leak_data   │ ──────────────────►   │   Shuffle   │
│  :8000       │                        │   :3001     │
└──────────────┘                        └──────┬──────┘
                                               │
                ┌──────────────────────────────┼──────────────────────┐
                │              │               │              │        │
                ▼              ▼               ▼              ▼        ▼
        ┌───────────┐  ┌───────────┐  ┌────────────┐  ┌──────────┐  ...
        │ TheHive   │  │  Cortex   │  │  OpenCTI   │  │VirusTotal│
        │  :9000    │  │  :9001    │  │   :8080    │  │  (API)   │
        └─────┬─────┘  └─────┬─────┘  └─────┬──────┘  └──────────┘
              │              │               │
              │◄─────────────┘               │
              │    enrichment                │
              │                              │
              │◄─────────────────────────────┘
              │    threat context
              │
              ▼
        ┌───────────┐
        │   Wazuh   │ ◄── log correlation
        │   :443    │
        └─────┬─────┘
              │
              ▼
        ┌───────────┐
        │   MISP    │ ──► CERT-UZ / boshqa CERT lar
        │  :80/443  │
        └───────────┘
```

### API ulanishlar jadvali

| Kimdan | Kimga | Metod | Maqsad |
|--------|-------|-------|--------|
| leak_data | Shuffle | POST webhook | Alert yuborish |
| OpenCTI | Shuffle | SSE stream | Real-time IoC |
| Shuffle | TheHive | POST /api/v1/alert | Case yaratish |
| Shuffle | OpenCTI | GraphQL | Threat context olish |
| Shuffle | VirusTotal | REST API | IoC reputatsiya |
| Shuffle | AbuseIPDB | REST API | IP abuse score |
| Shuffle | leak_data | GET /shodan-hosts | Host ma'lumoti |
| TheHive | Cortex | REST API | Observable tahlili |
| Cortex | Shodan | REST API | IP intelligence |
| Cortex | OpenCTI | GraphQL | Indicator lookup |
| Cortex | leak_data | GET /leaks/search | Credential check |
| Wazuh | Shuffle | POST webhook | SIEM alert |
| MISP | OpenCTI | TAXII/STIX | Threat sharing |

---

## 6. KOMPONENTLAR BATAFSIL

### 6.1 Wazuh — SIEM/XDR

**Nima qiladi:**
- Server, endpoint, network loglarini markazlashtiradi
- 300+ integratsiya (firewall, cloud, OS loglar)
- Anomaliya va hujum aniqlash qoidalari
- File integrity monitoring
- Vulnerability detection
- Compliance (PCI DSS, GDPR, ISO 27001)

**Sizning loyihaga qo'shimchasi:**
```
Yangi Wazuh qoidalari (custom rules):
- Rule 100001: leak_data CRITICAL alert → Wazuh Level 12
- Rule 100002: OpenCTI C2 match → Wazuh Level 15
- Rule 100003: Shodan yangi kritik vuln → Wazuh Level 13
- Rule 100004: RIPE prefix hijack → Wazuh Level 14
```

**Wazuh Indexer (OpenSearch) dashboard'lari:**
- UZ infratuzilmasi real-time monitoring
- CVE trends (haftalik/oylik)
- Top zaif tashkilotlar
- Alert severity timeline

**Integratsiya (ossec.conf):**
```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://shuffle:3001/api/v1/hooks/webhook_wazuh</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

### 6.2 TheHive — Case Management

**Nima qiladi:**
- Alert → Case → Task → Observable zanjiri
- Analyst ish tartibi (assignment, SLA, progress)
- Observable enrichment (Cortex orqali)
- MISP integratsiya
- PDF/email hisobot

**Sizning loyiha uchun case templatelar:**

```
Template 1: "UZ Credential Leak"
  Fields:
    - Tashkilot nomi (ripe_asns.org_name)
    - Zarar ko'rgan domenlar (credentials.root_domain)
    - Leak soni (credentials COUNT)
    - Risk darajasi
  Tasks:
    - Tashkilotga xabardorlik xati yuborish
    - CERT-UZ ga bildirish
    - Veb-resursni tekshirish
    - Patch status monitoring

Template 2: "C2 Server UZ Tarmog'ida"
  Fields:
    - IP manzil
    - ISP (ripe_asns)
    - Malware oilasi (OpenCTI)
    - APT attribution (OpenCTI)
  Tasks:
    - ISP ga takedown so'rovi
    - Boshqa affected host'larni aniqlash
    - CERT-UZ + boshqa CERT larga ulashish

Template 3: "Critical CVE — UZ Host Zaif"
  Fields:
    - CVE ID
    - CVSS / EPSS / KEV
    - Zaif tashkilotlar ro'yxati
    - Remediation deadline (72 soat)
  Tasks:
    - Har bir tashkilotga alohida xabardorlik
    - Patch verification
    - Follow-up monitoring
```

---

### 6.3 Cortex — Avtomatik Enrichment

**Sizning loyiha uchun foydali analyzer'lar:**

| Analyzer | Nima tahlil qiladi | API |
|----------|-------------------|-----|
| **Shodan_Host** | IP → port, servis, vuln, org | Shodan API key |
| **VirusTotal_GetReport_3_1** | IP/domain/hash reputatsiya | VT API key |
| **AbuseIPDB** | IP abuse score va kategoriya | AbuseIPDB key |
| **IPinfo_1_0** | IP geolokatsiya, ASN, org | IPinfo token |
| **GreyNoise** | IP — scanner/bot/attacker | GreyNoise key |
| **OpenCTI** | Indicator → threat context | OpenCTI token |
| **URLScan_io_Search** | URL/domain screenshot + scan | URLScan key |
| **MaxMind_GeoIP** | IP → mamlakat, shahar | MaxMind key |
| **leak_data** | Domain/email → credentials | Internal |

**Yangi custom analyzer — leak_data:**

```python
# Cortex/analyzers/LeakData_Analyzer/leakdata.py

from cortexutils.analyzer import Analyzer
import requests

class LeakDataAnalyzer(Analyzer):
    def run(self):
        data = self.get_param("data", None, "Data is missing")
        data_type = self.data_type  # domain, email, ip

        if data_type == "domain":
            resp = requests.get(
                f"http://leak_data:8000/leaks/search",
                params={"q": data, "match_type": "match", "fields": "domain"},
                headers={"Authorization": f"Bearer {self.get_param('config.api_token')}"}
            )
            result = resp.json()
            total = result.get("total", 0)

            if total > 0:
                self.report({
                    "summary": f"{total} ta credential topildi",
                    "full": result,
                    "taxonomies": [
                        self.build_taxonomy(
                            "danger" if total > 100 else "suspicious",
                            "LeakData",
                            "CredentialCount",
                            total
                        )
                    ]
                })
            else:
                self.report({"summary": "Credential topilmadi", "taxonomies": []})

if __name__ == "__main__":
    LeakDataAnalyzer().run()
```

---

### 6.4 Shuffle — SOAR Playbook'lar

**5 ta asosiy playbook:**

#### Playbook 1: Credential Alert → TheHive Case

```
Trigger: leak_data webhook (alert_type: new_credentials, severity: high/critical)
  │
  ├── 1. Parse alert (domain, count, org)
  ├── 2. GET /ripe/asns?domain={domain} → org info
  ├── 3. Cortex: Shodan analyzer → IP reputatsiya
  ├── 4. OpenCTI query: domen threat context
  ├── 5. AbuseIPDB: IP abuse score
  │
  ├── IF score > 70 OR OpenCTI threat match:
  │     → TheHive: CRITICAL case yaratish
  │     → Template: "UZ Credential Leak"
  │     → Analyst: auto-assign
  │
  └── IF score < 30:
        → TheHive: MEDIUM case
        → SLA: 7 kun
```

#### Playbook 2: OpenCTI C2 Match → Emergency Response

```
Trigger: OpenCTI stream (new malware/c2 IP indicator)
  │
  ├── 1. leak_data: GET /shodan-hosts?ip={ip} → UZ da bormi?
  ├── 2. RIPE: GET /ripe/prefix?ip={ip} → qaysi ISP?
  ├── 3. OpenCTI: full threat context (APT, malware family, TTPs)
  ├── 4. VirusTotal: IP report
  │
  ├── IF UZ IP:
  │     → TheHive: CRITICAL case
  │     → Title: "CRITICAL: {malware_family} C2 Server — {org}"
  │     → Task 1: ISP ga takedown xabari
  │     → Task 2: CERT-UZ ga bildiruv
  │     → Task 3: MISP ga export
  │     → Email/Telegram: on-call analyst
  │
  └── IF non-UZ:
        → OpenCTI: sighting yaratish (ko'rildi, UZ da emas)
```

#### Playbook 3: Critical CVE → Vulnerability Case

```
Trigger: leak_data webhook (alert_type: new_cve, severity: critical, kev=true)
  │
  ├── 1. CVE details: GET /cve/{cve_id}
  ├── 2. Zaif hostlar: GET /shodan-hosts?cve={cve_id}
  ├── 3. Tashkilotlar: shodan_hosts → ripe_asns → org classification
  ├── 4. EPSS probability check
  │
  ├── IF zaif UZ host topilsa:
  │     → TheHive: CRITICAL case
  │     → Task har bir tashkilot uchun alohida
  │     → Deadline: KEV bo'lsa 72h, boshqa 7 kun
  │     → PDF hisobot generatsiya
  │
  └── MISP: CVE + affected IPs export → CERT-UZ
```

#### Playbook 4: RIPE Change Monitor

```
Trigger: leak_data webhook (alert_type: new_prefix / removed_prefix)
  │
  ├── 1. RIPE WHOIS: prefix legitimmi?
  ├── 2. BGP tarix: eski prefix egasi kim edi?
  ├── 3. OpenCTI: prefix/ASN threat context
  │
  ├── IF yangi prefix (new_prefix):
  │     → Shodan scan schedule qilish
  │     → TheHive: INFO case (monitoring uchun)
  │
  └── IF prefix yo'qoldi (removed_prefix):
        → TheHive: HIGH case "Prefix hijack shubhasi"
        → RIPE WHOIS tekshirish task
```

#### Playbook 5: Wazuh → TheHive Incident

```
Trigger: Wazuh webhook (level >= 10)
  │
  ├── 1. Alert parse: rule_id, description, agent, src_ip
  ├── 2. IF src_ip → AbuseIPDB + OpenCTI lookup
  ├── 3. IF file_hash → VirusTotal lookup
  ├── 4. IF domain → leak_data credential check
  │
  ├── IF known threat:
  │     → TheHive: HIGH/CRITICAL case
  │
  └── IF unknown:
        → TheHive: MEDIUM case
        → Cortex: to'liq enrichment run
```

---

### 6.5 MISP — Threat Sharing

**Nima uchun kerak:**
- CERT-UZ va boshqa regional CERT lar bilan STIX/TAXII orqali ulashish
- Xalqaro threat intel olish (CIRCL, FIRST.org)
- UZ spetsifik IoC larni global community bilan ulashish

**OpenCTI — MISP ulanish:**
```
OpenCTI Connector: MISP Import
  ← MISP events → STIX 2.1 → OpenCTI knowledge graph

OpenCTI Stream: MISP Export
  → OpenCTI indicators → MISP events (auto-export)
```

**TheHive — MISP ulanish:**
```
TheHive case yechildi
  → Cortex: MISP responder
  → MISP event yaratish (TLP: WHITE yoki GREEN)
  → CERT-UZ MISP instancega sync
```

---

## 7. DOCKER DEPLOYMENT REJASI

### Fayl tuzilishi

```
/home/user/soc/
├── docker-compose.yml          — barcha servislar
├── .env                        — API kalitlar va parollar
├── wazuh/
│   ├── config/
│   │   ├── wazuh_manager.conf
│   │   └── custom_rules.xml    — leak_data uchun maxsus qoidalar
│   └── data/
├── thehive/
│   ├── config/
│   │   └── application.conf
│   └── data/
├── cortex/
│   ├── config/
│   │   └── application.conf
│   └── analyzers/
│       └── LeakData/           — custom analyzer
├── shuffle/
│   └── workflows/              — export qilingan playbook'lar
├── opencti/
│   └── (avvalgi docker-compose)
└── misp/
    └── config/
```

### docker-compose.yml (asosiy SOC stack)

```yaml
version: "3.8"

services:

  # ═══════════════════════════════════
  # WAZUH
  # ═══════════════════════════════════
  wazuh-manager:
    image: wazuh/wazuh-manager:4.12.0
    hostname: wazuh-manager
    restart: always
    ports:
      - "1514:1514/udp"    # agent logs
      - "1515:1515/tcp"    # agent enrollment
      - "55000:55000/tcp"  # REST API
    volumes:
      - ./wazuh/config/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf
      - ./wazuh/config/custom_rules.xml:/var/ossec/etc/rules/custom_rules.xml
      - wazuh_data:/var/ossec/data
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=${WAZUH_INDEXER_PASSWORD}

  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.12.0
    restart: always
    ports:
      - "9200:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx4g"
    volumes:
      - wazuh_indexer_data:/var/lib/wazuh-indexer

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:4.12.0
    restart: always
    ports:
      - "443:5601"
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - WAZUH_API_URL=https://wazuh-manager
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=${WAZUH_API_PASSWORD}

  # ═══════════════════════════════════
  # THEHIVE
  # ═══════════════════════════════════
  thehive:
    image: strangebee/thehive:5.5
    restart: always
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms1g -Xmx2g
    volumes:
      - ./thehive/config/application.conf:/etc/thehive/application.conf
      - thehive_data:/opt/thehive/data
    depends_on:
      - cassandra
      - elasticsearch

  cassandra:
    image: cassandra:4.1
    restart: always
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
      - HEAP_NEWSIZE=256M
      - MAX_HEAP_SIZE=1G
    volumes:
      - cassandra_data:/var/lib/cassandra

  # ═══════════════════════════════════
  # CORTEX
  # ═══════════════════════════════════
  cortex:
    image: thehiveproject/cortex:3.1.8
    restart: always
    ports:
      - "9001:9001"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1g
      - http.port=9001
    volumes:
      - ./cortex/config/application.conf:/etc/cortex/application.conf
      - ./cortex/analyzers:/opt/custom-analyzers
      - /var/run/docker.sock:/var/run/docker.sock  # analyzer containers
      - cortex_data:/opt/cortex/data
    depends_on:
      - elasticsearch

  # ═══════════════════════════════════
  # SHUFFLE
  # ═══════════════════════════════════
  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    restart: always
    ports:
      - "3001:3001"
    environment:
      - DATASTORE_EMULATOR_HOST=shuffle-database:8000
      - SHUFFLE_APP_HOTLOAD_FOLDER=./shuffle-apps
      - SHUFFLE_FILE_LOCATION=./shuffle-files
      - BACKEND_HOSTNAME=shuffle-backend
    volumes:
      - shuffle_data:/shuffle-files
      - shuffle_apps:/shuffle-apps
      - /var/run/docker.sock:/var/run/docker.sock

  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    restart: always
    ports:
      - "3002:80"
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
      - BACKEND_PORT=3001

  shuffle-orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    restart: always
    environment:
      - SHUFFLE_APP_SDK_VERSION=1.1.0
      - ENVIRONMENT_NAME=Shuffle
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  shuffle-database:
    image: google/cloud-sdk:emulators
    restart: always
    command: gcloud beta emulators datastore start --host-port 0.0.0.0:8000

  # ═══════════════════════════════════
  # MISP
  # ═══════════════════════════════════
  misp:
    image: coolacid/misp-docker:core-latest
    restart: always
    ports:
      - "8090:80"
      - "8443:443"
    environment:
      - MISP_ADMIN_EMAIL=${MISP_ADMIN_EMAIL}
      - MISP_ADMIN_PASSPHRASE=${MISP_ADMIN_PASSWORD}
      - MISP_BASEURL=https://misp.internal
      - MYSQL_HOST=misp-mysql
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=${MISP_MYSQL_PASSWORD}
    volumes:
      - misp_data:/var/www/MISP/app/files
    depends_on:
      - misp-mysql

  misp-mysql:
    image: mysql:8.0
    restart: always
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=${MISP_MYSQL_PASSWORD}
      - MYSQL_ROOT_PASSWORD=${MISP_MYSQL_ROOT_PASSWORD}
    volumes:
      - misp_mysql_data:/var/lib/mysql

  # ═══════════════════════════════════
  # SHARED SERVICES
  # ═══════════════════════════════════
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    restart: always
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx4g"
    volumes:
      - es_data:/usr/share/elasticsearch/data

volumes:
  wazuh_data:
  wazuh_indexer_data:
  thehive_data:
  cassandra_data:
  cortex_data:
  shuffle_data:
  shuffle_apps:
  misp_data:
  misp_mysql_data:
  es_data:
```

### .env fayl

```bash
# Wazuh
WAZUH_INDEXER_PASSWORD=WazuhSecurePass123!
WAZUH_API_PASSWORD=WazuhAPIPass456!

# TheHive
THEHIVE_SECRET=SuperSecretTheHiveKey789

# Cortex API Keys (tashqi servislar)
VIRUSTOTAL_API_KEY=your_vt_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
IPINFO_TOKEN=your_ipinfo_token
GREYNOISE_API_KEY=your_greynoise_key

# OpenCTI
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=your_opencti_token

# leak_data
LEAK_DATA_URL=http://10.10.201.30:8000
LEAK_DATA_TOKEN=your_leak_api_token

# MISP
MISP_ADMIN_EMAIL=admin@soc.uz
MISP_ADMIN_PASSWORD=MISPSecurePass!
MISP_MYSQL_PASSWORD=MySQLMISPPass!
MISP_MYSQL_ROOT_PASSWORD=MySQLRootPass!
```

---

## 8. PORT VA TARMOQ REJASI

### Ichki tarmoq (internal, tashqaridan yopiq)

| Servis | Port | Protokol | Kirish |
|--------|------|----------|--------|
| leak_data API | 8000 | HTTP | Internal |
| leak_UI | 3000 | HTTP | Internal |
| OpenCTI UI | 8080 | HTTP | Internal |
| OpenCTI GraphQL | 4000 | HTTP | Internal |
| Wazuh API | 55000 | HTTPS | Internal |
| Wazuh Dashboard | 443 | HTTPS | Internal (analysts) |
| TheHive | 9000 | HTTP | Internal |
| Cortex | 9001 | HTTP | Internal |
| Shuffle UI | 3002 | HTTP | Internal |
| Shuffle API | 3001 | HTTP | Internal |
| MISP | 8090/8443 | HTTP/HTTPS | Internal |
| ElasticSearch | 9200 | HTTP | Internal |
| Cassandra | 9042 | TCP | Internal |

### Tashqariga chiqish (Outbound — threat intel feedlar)

| Manzil | Port | Maqsad |
|--------|------|--------|
| api.alienvault.com | 443 | OTX feed |
| api.abuseipdb.com | 443 | IP reputation |
| api.shodan.io | 443 | Shodan enrichment |
| api.virustotal.com | 443 | VT enrichment |
| ipinfo.io | 443 | Geolocation |
| api.greynoise.io | 443 | Noise classification |
| bazaar.abuse.ch | 443 | MalwareBazaar |
| threatfox-api.abuse.ch | 443 | ThreatFox |
| services.nvd.nist.gov | 443 | NVD CVE |

### Nginx reverse proxy (tashqaridan kirish uchun)

```nginx
# Faqat analyzer uchun kerak bo'lganda
server {
    listen 443 ssl;
    server_name soc.internal;

    location /wazuh/ { proxy_pass http://wazuh-dashboard:5601/; }
    location /thehive/ { proxy_pass http://thehive:9000/; }
    location /shuffle/ { proxy_pass http://shuffle-frontend:80/; }
    location /opencti/ { proxy_pass http://opencti:8080/; }
    location /misp/ { proxy_pass http://misp:80/; }
}
```

---

## 9. SERVER TALABLARI

### Hozirgi server holati

| Resurs | Mavjud | Kerak (SOC) | Status |
|--------|--------|-------------|--------|
| RAM | 62 GB (36 GB bo'sh) | 28–32 GB | ✅ Yetarli |
| CPU | 32 core | 16–20 core | ✅ Yetarli |
| Disk | 1.9 TB bo'sh | 500 GB | ✅ Yetarli |
| Docker | Yo'q | Kerak | ⚠️ O'rnatish kerak |

### Komponentlar bo'yicha RAM taqsimoti

| Komponent | RAM | CPU |
|-----------|-----|-----|
| leak_data (hozir) | ~4 GB | 4 core |
| OpenCTI + ES + Redis + MinIO | 8 GB | 6 core |
| Wazuh Manager + Indexer + Dashboard | 8 GB | 4 core |
| TheHive + Cassandra | 4 GB | 2 core |
| Cortex + analyzers | 4 GB | 4 core |
| Shuffle | 2 GB | 2 core |
| MISP + MySQL | 2 GB | 2 core |
| **Jami** | **~32 GB** | **~24 core** |

**Sizda 36 GB bo'sh RAM — yetarli.**

---

## 10. AMALGA OSHIRISH BOSQICHLARI

### Hafta 1 — Infratuzilma

```
[ ] Docker + Docker Compose o'rnatish
[ ] /home/user/soc/ katalog tuzilishi yaratish
[ ] .env fayl sozlash (API kalitlar)
[ ] Docker network yaratish (soc_network)
[ ] leak_data va OpenCTI ham shu networkga ulash
```

### Hafta 2 — OpenCTI (avval shu, chunki boshqalarga kerak)

```
[ ] OpenCTI docker-compose deploy
[ ] MITRE ATT&CK connector yoqish
[ ] ThreatFox + URLhaus + MalwareBazaar connectorlar
[ ] AlienVault OTX connector
[ ] CISA KEV connector
[ ] leak_data → OpenCTI export script (domenlar + hostlar)
[ ] OpenCTI → leak_data webhook ulash
```

### Hafta 3 — TheHive + Cortex

```
[ ] TheHive + Cassandra deploy
[ ] Cortex deploy + Docker socket ulash
[ ] Cortex analyzers yuklab olish (Shodan, VT, AbuseIPDB, IPInfo, GreyNoise)
[ ] Custom LeakData analyzer yozish va deploy
[ ] TheHive ↔ Cortex ulanishni sozlash
[ ] TheHive case template'lar yaratish (5 ta)
[ ] API tokenlar sozlash
```

### Hafta 4 — Shuffle SOAR

```
[ ] Shuffle deploy
[ ] Wazuh app sozlash
[ ] TheHive app sozlash
[ ] OpenCTI app sozlash
[ ] Cortex app sozlash
[ ] leak_data custom app yozish (OpenAPI spec asosida)
[ ] 5 ta playbook yaratish va test qilish
[ ] Webhook URL'larni leak_data ga qo'shish
```

### Hafta 5 — Wazuh SIEM

```
[ ] Wazuh Manager + Indexer + Dashboard deploy
[ ] Custom rules.xml yozish (leak_data alert rules)
[ ] Wazuh → Shuffle webhook sozlash
[ ] Dashboard: UZ infra monitoring views
[ ] Alert severity threshold sozlash
[ ] (Ixtiyoriy) Wazuh agent server'larga o'rnatish
```

### Hafta 6 — MISP + Final integration

```
[ ] MISP deploy va sozlash
[ ] MISP ↔ OpenCTI connector ulash
[ ] TheHive ↔ MISP Cortex responder
[ ] End-to-end test: credential alert → case → enrichment → PDF
[ ] End-to-end test: C2 IP → CRITICAL case → MISP export
[ ] End-to-end test: CVE → zaif host → tashkilot → hisobot
[ ] Monitoring va alerting sozlash
[ ] Hujjatlashtirish
```

---

## 11. XULOSA

### Tizim amalga oshirilgandan keyin imkoniyatlar

| Vazifa | Hozir | SOC bilan |
|--------|-------|-----------|
| Credential leak aniqlash | Manual | Avtomatik, 1 daqiqa |
| C2 server detection | Yo'q | Real-time, OpenCTI orqali |
| CVE → zaif tashkilot | Manual qidiruv | Avtomatik case + hisobot |
| RIPE hijack aniqlash | Alert (ko'rilmay qoladi) | Case + ISP xabardorlik |
| Enrichment (IP/domain) | Yo'q | 10+ manbadan avtomatik |
| CERT-UZ ga yuborish | Manual email | MISP/STIX orqali avtomatik |
| Hisobot | PDF (manual) | Avtomatik, template'dan |
| APT attribution | Yo'q | OpenCTI + MITRE ATT&CK |
| Incident tracking | Yo'q | TheHive SLA + assignment |

### Umumiy loyiha strukturasi (final)

```
Qatlam 1 — Ma'lumot:
  leak_data (PostgreSQL, Shodan, CVE, RIPE, EPSS)

Qatlam 2 — Intelligence:
  OpenCTI (APT, C2, malware, IoC — global threat intel)

Qatlam 3 — Detection & Correlation:
  Wazuh (SIEM) + Shuffle (SOAR playbook'lar)

Qatlam 4 — Response & Enrichment:
  TheHive (cases) + Cortex (analyzers)

Qatlam 5 — Sharing:
  MISP → CERT-UZ, regional CERT lar

Qatlam 6 — Interface:
  leak_UI (operators) + Wazuh Dashboard (analysts)
```

### Qisqa xulosa

Hozirgi tizimingiz kuchli OSINT ma'lumot to'plash platformasi. OpenCTI va SOC stack qo'shilishi bilan u to'liq **Milliy CERT/SOC platformasi**ga aylanadi — ma'lumot to'plashdan tortib, tahdid aniqlash, avtomatik enrichment, incident response, va CERT-UZ bilan ulashishgacha hamma narsa bir tizimda bo'ladi.

---

*Hisobot oxiri — 2026-05-19*
*Keyingi qadam: Docker o'rnatish va OpenCTI deploydan boshlash*
