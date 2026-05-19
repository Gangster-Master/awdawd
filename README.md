# OpenCTI + Leak/OSINT Integratsiya — To'liq Hisobot

**Tayyorlangan:** 2026-05-19  
**Muallif:** Claude (Anthropic)  
**Loyiha:** leak_data / leak_UI  
**Maqsad:** OpenCTI platformasini mavjud OSINT tizimiga integratsiya qilish bo'yicha texnik tahlil

---

## MUNDARIJA

1. [Kirish va maqsad](#1-kirish)
2. [OpenCTI nima?](#2-opencti-nima)
3. [Mavjud loyiha tahlili](#3-mavjud-loyiha-tahlili)
4. [Integratsiya imkoniyatlari](#4-integratsiya-imkoniyatlari)
5. [OpenCTI connector'lar to'liq ro'yxati](#5-connectorlar-royxati)
6. [Tavsiya etilgan minimal set](#6-tavsiya-etilgan-set)
7. [Integratsiya arxitekturasi](#7-arxitektura)
8. [Texnik amalga oshirish](#8-texnik-amalga-oshirish)
9. [Server talablari](#9-server-talablari)
10. [Xulosa va keyingi qadamlar](#10-xulosa)

---

## 1. KIRISH

Hozirgi `leak_data` tizimi mustaqil OSINT platformasi sifatida ishlaydi — credential ma'lumotlar bazasi, Shodan integration, CVE/KEV/EPSS risk scoring, RIPE ASN monitoring va alerts tizimi mavjud.

OpenCTI bilan integratsiya maqsadi:

- Mavjud ma'lumotlarni xalqaro threat intelligence konteksti bilan boyitish
- APT guruhlar, malware C2 server'lar va aktiv ekspluatatsiya qilinayotgan zaifliklar haqida real-time ma'lumot olish
- Hisobotlar sifatini oshirish (MITRE ATT&CK TTPs, APT attribution)
- UZ infratuzilmasidagi tahdidlarni ertaroq aniqlash

---

## 2. OpenCTI NIMA?

**OpenCTI** (Open Cyber Threat Intelligence) — Fransiya ANSSI va Luatix tomonidan yaratilgan, Apache 2.0 litsenziyasi ostida tarqatiladigan ochiq manbali Kibertahdid Razvedkasi platformasi.

### Texnik stack

| Komponent | Texnologiya |
|-----------|-------------|
| Backend | Node.js + GraphQL |
| Ma'lumotlar bazasi | ElasticSearch |
| Kesh | Redis |
| Fayl saqlash | MinIO (S3-compatible) |
| Message broker | RabbitMQ |
| Connector runtime | Python 3 (pycti SDK) |
| Standart | STIX 2.1 |

### Ma'lumot modeli (STIX 2.1)

OpenCTI barcha ma'lumotlarni knowledge graph ko'rinishida saqlaydi:

**STIX Domain Objects (SDOs):**
- Threat Actor / Intrusion Set — APT guruhlar
- Attack Pattern — TTPs (MITRE ATT&CK)
- Malware — zararli dasturlar
- Campaign — hujum kampaniyalari
- Vulnerability — CVE zaifliklar
- Infrastructure — server, C2, botnet
- Report — tahliliy hisobotlar

**STIX Cyber Observables (SCOs):**
- IPv4-Addr / IPv6-Addr
- Domain-Name
- URL
- Email-Addr
- File (MD5/SHA1/SHA256)
- Autonomous-System (ASN)
- Network-Traffic

**STIX Relationship Objects (SROs):**
- uses, targets, attributed-to, indicates, exploits, delivers...

---

## 3. MAVJUD LOYIHA TAHLILI

### 3.1 Hozirgi imkoniyatlar

| Modul | Ma'lumot | Hajm |
|-------|----------|------|
| credentials | url, domain, login, password, root_domain | ~5.13 milliard qator |
| shodan_hosts | IP, org, port, servis, OS | 24,897 host |
| shodan_services | port, transport, product, version, banner | 127,170 ta |
| shodan_vulns | CVE, CVSS, summary | 196,855 ta |
| cve_entries | CVE ID, CVSS, KEV, EPSS, risk_score | NVD to'liq |
| ripe_asns | ASN, org_name, klassifikatsiya | 123 ta |
| ripe_prefixes | prefix, IPv4/IPv6 | 787 ta prefix, 527K+ IP |
| alerts | CVE, Shodan, RIPE alertlari | real-time |

### 3.2 Risk Scoring Formula (mavjud)

```
risk_score = (cvss × 5) + (kev ? 30 : 0) + (exploit ? 15 : 0) + (epss × 20)
Diapazon: 0–100
```

### 3.3 Mavjud kamchiliklar

| Kamchilik | OpenCTI bilan yechim |
|-----------|---------------------|
| APT attribution yo'q | MITRE ATT&CK + OpenCTI APT data |
| C2 IP detection yo'q | ThreatFox + Feodo Tracker connector |
| Malware correlation yo'q | MalwareBazaar + VirusTotal enrichment |
| Threat actor context yo'q | AlienVault OTX 19M+ IoC |
| Hisobotda TTP yo'q | MITRE ATT&CK TTPs + PDF export |

---

## 4. INTEGRATSIYA IMKONIYATLARI

### 4.1 Sizdan OpenCTI ga (PUSH yo'nalishi)

#### A. Credentials → Domain-Name Observable

Sizning 5.13 milliard credential'dan top domenlar OpenCTI'ga yuboriladi:

```
credentials.domain / root_domain
  → Domain-Name Observable
  → Label: "leaked-credential"
  → Score: domain qanchalik ko'p uchrasa, xavf ball yuqori
  → TLP: AMBER (tashkilot ichida)
```

**Foyda:** OpenCTI bu domenlarni ma'lum APT kampaniyalari bilan taqqoslaydi. Agar `bank.uz` OpenCTI'da APT28 nishoni sifatida belgilangan bo'lsa — siz darhol bilib olasiz.

#### B. Shodan Hosts → IPv4-Addr Observable + Vulnerability

```
shodan_hosts.ip
  → IPv4-Addr Observable
  → Labels: "uz-infrastructure", "vulnerable"

shodan_vulns.cve_id
  → Vulnerability object
  → Relationship: "has" (host → vulnerability)

shodan_services
  → Network-Traffic object (port/protocol)
```

**Foyda:** OpenCTI bu IP'larni ma'lum threat actor infratuzilmasi bilan solishtiradi.

#### C. CVE Data → Enriched Vulnerability Objects

Sizning CVE ma'lumotingiz NVD dan kuchliroq — KEV + EPSS + o'z risk_score formulangiz bor:

```
cve_entries → Vulnerability (STIX)
  + x_opencti_cvss_score
  + x_opencti_epss_score
  + x_opencti_kev_status
  + x_opencti_risk_score (sizning formula)
```

#### D. RIPE ASN → Organization + Autonomous-System

```
ripe_asns.org_name → Organization (Identity)
ripe_prefixes.prefix → Autonomous-System Observable
  + Relationship: "belongs-to" (prefix → org)
```

#### E. Alerts → Incident Objects

```
alerts (severity: critical/high)
  → Incident object
  → Label: "uz-cert-alert"
  → Relationship: "targets" (→ organization)
```

---

### 4.2 OpenCTI dan Sizga (PULL yo'nalishi)

#### A. APT Threat Actor Intelligence

OpenCTI + MITRE ATT&CK connector orqali quyidagilar keladi:

| APT Guruh | Davlat | UZ Infrasiga Xavf | TTPs |
|-----------|--------|------------------|------|
| APT28 (Fancy Bear) | Rossiya | Yuqori | T1190, T1566, T1078 |
| Turla (Snake) | Rossiya | Yuqori | T1071, T1090, T1573 |
| APT34 (OilRig) | Eron | O'rta | T1192, T1003, T1027 |
| APT41 | Xitoy | O'rta | T1190, T1133, T1486 |
| Lazarus | Koreya | O'rta | T1059, T1486, T1041 |

**Siz buni qanday ishlatasiz:**
- APT ishlatgan IP/domen'larni `shodan_hosts` bilan solishtirish
- APT target sector'larini `ripe_asns` klassifikatsiya bilan taqqoslash (bank, hukumat, telekom)

#### B. Known Malware C2 Server IP'lari

```
ThreatFox + Feodo Tracker →
  C2 IP'lar (Cobalt Strike, Emotet, TrickBot, QBot...)
    ↓
  shodan_hosts bilan cross-reference
    ↓
  Match topilsa → CRITICAL ALERT
```

**Real scenario:**
```
OpenCTI: 185.220.101.45 → Cobalt Strike C2 (APT28)
shodan_hosts: 185.220.101.45 → UZ tarmog'ida aktiv
→ CRITICAL: "UZ tarmog'ida APT28 C2 server aniqlandi!"
→ Avtomatik CERT-UZ hisobot
```

#### C. Malicious Domain Feed

```
URLhaus + ThreatFox →
  Malicious URL/domain'lar
    ↓
  credentials.domain bilan cross-reference
    ↓
  "Bu tashkilotdan leak bo'lgan credentials malware saytiga tegishli"
```

#### D. Hisobot Sifatini Oshirish

```
Eski PDF hisobot:
  "bank.uz saytida SQL Injection (CWE-89) topildi"

Yangi PDF hisobot:
  "bank.uz saytida SQL Injection (CWE-89) topildi
   ATT&CK: T1190 - Exploit Public-Facing Application
   APT Attribution: APT28 bu TTPs'ni faol ishlatmoqda
   EPSS: 0.73 (73% ehtimol bilan exploit bo'lishi mumkin)
   KEV: Ha — CISA tomonidan aktiv ekspluatatsiya tasdiqlangan"
```

---

## 5. CONNECTOR'LAR TO'LIQ RO'YXATI

### 5.1 EXTERNAL IMPORT (Tashqaridan ma'lumot import qiladi) — 131 ta

#### Bepul va tavsiya etilganlar

| Connector | Manba | Nima beradi | Yangilanish |
|-----------|-------|------------|------------|
| **MITRE ATT&CK** | MITRE | APT guruhlar, TTPs, malware, kampaniyalar | Har versiyada |
| **CISA KEV** | CISA | Faol exploit qilinayotgan CVE'lar | Doimiy |
| **AlienVault OTX** | AlienVault | 19M+ IoC: IP, domain, hash, URL | Kunlik |
| **URLhaus** | abuse.ch | Malware tarqatuvchi URL'lar | Real-time |
| **MalwareBazaar** | abuse.ch | Malware sample va file hash'lar | Real-time |
| **ThreatFox** | abuse.ch | Malware C2 IoC'lar — IP, domain, hash | Real-time |
| **Feodo Tracker** | abuse.ch | Botnet C2 IP'lar (Emotet, TrickBot) | Real-time |
| **First EPSS Bulk** | FIRST.org | CVE exploit ehtimolligi (EPSS) | Kunlik |
| **CVE** | NIST NVD | National Vulnerability Database | Kunlik |
| **DShield** | SANS ISC | Hujum subnet'lari statistikasi | Kunlik |
| **GreyNoise Feed** | GreyNoise | Internet scanner IP klassifikatsiyasi | Kunlik |
| **RansomwareLive** | RansomwareLive | Faol ransomware guruhlari | Real-time |
| **RansomFeed** | RansomFeed | Ransomware qurbonlari to'g'risida | Kunlik |
| **Malpedia** | Malpedia | Malware oilalari + YARA qoidalari | Haftalik |
| **Bambenek** | Bambenek | C2 domain feed | Kunlik |
| **Red Flag Domains** | Jamieson | Malicious domain'lar | Kunlik |
| **StopForumSpam** | StopForumSpam | Spam/abuse IP va email | Kunlik |
| **TAXII2** | Har qanday | STIX data TAXII serverlardan | Sozlanadi |
| **MISP Feed** | MISP | MISP instance feed | Sozlanadi |
| **MITRE ATLAS** | MITRE | AI xavfsizlik hujumlari | Versiyada |
| **DISARM Framework** | DISARM | Dezinformatsiya counter-framework | Versiyada |

#### Pulli (API key va obuna kerak)

| Connector | Narxi | Nima beradi |
|-----------|-------|------------|
| **Recorded Future** | $$$$ | Premium threat intel, dark web |
| **CrowdStrike** | $$$$ | EDR + APT intel |
| **Mandiant** | $$$$ | APT attribution, malware tahlili |
| **IBM X-Force** | $$$ | Threat intel + vulnerability |
| **Kaspersky** | $$$ | APT reports, malware |
| **Intel 471** | $$$$ | Cybercrime intelligence |
| **Flashpoint** | $$$$ | Dark web intelligence |
| **Group-IB** | $$$$ | APT/cybercrime intel (Rossiya fokus) |
| **Cybersixgill** | $$$$ | Dark web monitoring |
| **Accenture ACTI** | $$$$ | Premium APT intel |
| **SpyCloud** | $$$$ | Breach/credential intelligence |
| **Dragos** | $$$$ | ICS/OT threat intelligence |
| **Fortinet TI** | $$$ | Fortinet threat feed |
| **Sekoia** | $$$ | Fransiya CTI platformasi |
| **Team T5** | $$$ | APAC APT intel |
| **EchoCTI** | $$ | Premium CTI |
| **Luminar** | $$$$ | Dark web monitoring |
| **Silobreaker** | $$$$ | Premium dark web |
| **Socradar** | $$ | Threat intel |

#### Ixtiyoriy (bepul, lekin sizga kam kerakli)

| Connector | Nima beradi |
|-----------|------------|
| CRITS | Collaborative threat sharing |
| Cuckoo | Cuckoo sandbox feed |
| CAPE | CAPE malware sandbox |
| MWDB | Malware analysis database |
| Vulners | Vulnerability intelligence |
| Phishunt | Phishing intelligence |
| AnyRun Feed | AnyRun sandbox feed |
| OpenCSAM | Cloud security |
| Email Intel IMAP | Email threat via IMAP |
| Google Drive | Google Drive fayl import |
| S3 | AWS S3 import |
| CPE | Common Platform Enumeration |

---

### 5.2 INTERNAL ENRICHMENT (Mavjud ma'lumotni boyitadi) — 57 ta

#### Bepul va tavsiya etilganlar

| Connector | Nima qiladi | API |
|-----------|------------|-----|
| **Shodan Internetdb** | IP'ning port, servis, CVE ma'lumoti | Bepul |
| **Shodan** | To'liq Shodan IP intelligence | API key (bepul tier) |
| **AbuseIPDB** | IP abuse report'lari, confidence score | API key (bepul) |
| **IPInfo** | IP geolokatsiya, org, ASN | API key (bepul tier) |
| **GreyNoise** | IP — scanner/bot/attacker tasnifi | API key (bepul tier) |
| **First EPSS** | CVE uchun exploit ehtimoli | Bepul |
| **Google DNS** | DNS resolution enrichment | Bepul |
| **Google Safe Browsing** | Sayt xavfsizlik holati | API key (bepul) |
| **DNStwist** | Domain typosquatting tahlili | Open source |
| **IVRE** | Network recon va mapping | Open source |
| **URLscan** | URL scanning va screenshot | API key (bepul tier) |
| **Censys** | Internet host data (Shodan muqobili) | API key (bepul tier) |
| **VirusTotal** | File/URL/domain/IP reputatsiya | API key (bepul tier: 4 req/min) |
| **IPQS** | IP quality score, fraud detection | API key (bepul tier) |
| **Tagger** | Avtomatik entity tagging | Bepul (built-in) |
| **Hygiene** | Ma'lumot sifat tekshiruvi | Bepul (built-in) |
| **YARA** | YARA qoida matching | Bepul (built-in) |

#### Pulli

| Connector | Narxi | Nima beradi |
|-----------|-------|------------|
| **DomainTools** | $$$ | WHOIS, DNS, passive DNS |
| **RiskIQ Passive Total** | $$$ | Passive DNS + WHOIS |
| **ReversingLabs** | $$$ | Malware classification |
| **Joe Sandbox** | $$$ | Advanced malware tahlili |
| **Intezer** | $$$ | Malware genetic tahlili |
| **Hybrid Analysis** | $$ | Malware sandbox (limited bepul) |
| **Recorded Future Enrichment** | $$$$ | Premium enrichment |
| **Kaspersky Enrichment** | $$$ | Kaspersky enrichment |
| **Sophoslabs** | $$$ | Sophos threat enrichment |
| **VMRay** | $$$ | Advanced sandbox |

---

### 5.3 INTERNAL IMPORT FILE — 6 ta

| Connector | Nima qiladi | Kerakmi? |
|-----------|------------|----------|
| **Import File STIX** | STIX 2.1 JSON/XML fayl import | ★ KERAK |
| **Import File MISP** | MISP format fayl import | Ixtiyoriy |
| **Import Document** | Word/PDF hujjatdan entity extraction | Ixtiyoriy |
| **Import Document AI** | AI bilan hujjat tahlili (GPT/Claude) | Ixtiyoriy |
| **Import File YARA** | YARA qoida fayl import | Ixtiyoriy |
| **Import TTPs Navigator** | ATT&CK Navigator fayl import | Ixtiyoriy |

---

### 5.4 INTERNAL EXPORT FILE — 6 ta

| Connector | Nima qiladi | Kerakmi? |
|-----------|------------|----------|
| **Export File STIX** | STIX 2.1 JSON bundle eksport | ★ KERAK |
| **Export Report PDF** | PDF hisobot generatsiya | ★ KERAK |
| **Export File CSV** | CSV formatda eksport | ★ KERAK |
| **Export File TXT** | Text formatda eksport | Ixtiyoriy |
| **Export File YARA** | YARA qoidalar eksport | Ixtiyoriy |
| **Export TTPs Navigator** | ATT&CK Navigator eksport | Ixtiyoriy |

---

### 5.5 STREAM (Real-time chiqarish) — 28 ta

| Connector | Nima qiladi | Kerakmi? |
|-----------|------------|----------|
| **Webhook** | Har qanday tizimga HTTP webhook | ★ KERAK |
| **TAXII Post** | STIX TAXII serverga yuborish | Ixtiyoriy |
| **MISP Intel** | MISP ga real-time sync | Ixtiyoriy |
| Splunk | Splunk SIEM | ✗ Keraksiz |
| Elastic Security | Elastic Security | ✗ Keraksiz |
| Microsoft Sentinel | Azure Sentinel | ✗ Keraksiz |
| Microsoft Defender | MS Defender | ✗ Keraksiz |
| Google Chronicle/SecOps | Google SIEM | ✗ Keraksiz |
| QRadar | IBM QRadar | ✗ Keraksiz |
| Jira | Jira tickets | ✗ Keraksiz |
| SentinelOne | SentinelOne EDR | ✗ Keraksiz |
| CrowdStrike EDR | CrowdStrike EDR | ✗ Keraksiz |
| Tanium | Tanium platform | ✗ Keraksiz |
| Harfanglab | Harfanglab EDR | ✗ Keraksiz |
| Pan Cortex XSOAR | Palo Alto SOAR | ✗ Keraksiz |
| Akamai | Akamai WAF | ✗ Keraksiz |
| Infoblox | Infoblox DNS | ✗ Keraksiz |
| Zscaler | Zscaler proxy | ✗ Keraksiz |
| LogRhythm | LogRhythm SIEM | ✗ Keraksiz |
| Sumo Logic | Sumo Logic SIEM | ✗ Keraksiz |
| Sekoia Intel | Sekoia platform | ✗ Keraksiz |
| Backup Files | Zaxira nusxa | Ixtiyoriy |
| Stream Exporter | Generic eksport | Ixtiyoriy |

---

## 6. TAVSIYA ETILGAN MINIMAL SET

Sizning loyihangiz uchun optimal konfiguratsiya — **15 ta connector**, hammasi **bepul**:

### 6.1 Yoqilishi kerak bo'lgan connector'lar

```yaml
# EXTERNAL IMPORT — 7 ta
connector-mitre:                    # APT/TTP/Malware bazasi
connector-cisa-kev:                 # Aktiv exploit CVE'lar
connector-alienvault-otx:           # 19M+ IoC (IP, domain, URL, hash)
connector-urlhaus:                  # Malware URL'lar
connector-malwarebazaar:            # Malware hash'lar
connector-threatfox:                # C2 server IoC'lar
connector-first-epss-bulk:          # EPSS scores

# INTERNAL ENRICHMENT — 4 ta
connector-shodan-internetdb:        # IP enrichment (bepul)
connector-virustotal:               # File/URL/IP reputatsiya
connector-abuseipdb:                # IP abuse scores
connector-ipinfo:                   # Geolokatsiya

# IMPORT/EXPORT — 3 ta
connector-import-file-stix:         # STIX import
connector-export-file-stix:         # STIX eksport
connector-export-report-pdf:        # PDF hisobot

# STREAM — 1 ta
connector-webhook:                  # leak_data ga real-time push
```

### 6.2 O'chirilgan holda qoldirilishi kerak — 213+ ta connector

Barcha pulli connector'lar, SIEM/EDR connector'lar, va sizga tegishli bo'lmagan xizmatlar.

---

## 7. INTEGRATSIYA ARXITEKTURASI

```
┌──────────────────────────────────────────────────────────────────┐
│                    SIZNING HOZIRGI TIZIM                         │
│                                                                  │
│  PostgreSQL (5.13B credentials)                                  │
│  Shodan (24,897 hosts, 196,855 vulns)                           │
│  CVE/KEV/EPSS (risk scoring)                                    │
│  RIPE (123 ASN, 787 prefix)                                     │
│  Alerts (real-time)                                             │
│  FastAPI (port 8000)                                            │
└────────────┬────────────────────────────┬────────────────────────┘
             │                            │
             │ PUSH (STIX bundles)        │ PULL (pycti API)
             │ Yangi connector yoziladi   │ Real-time webhook
             ▼                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                         OpenCTI                                  │
│                    (port 8080, Docker)                           │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ MITRE ATT&CK│  │  ThreatFox  │  │AlienVault   │             │
│  │ connector   │  │  connector  │  │OTX connector│             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  URLhaus    │  │MalwareBazaar│  │ EPSS Bulk   │             │
│  │  connector  │  │  connector  │  │ connector   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  Knowledge Graph:                                                │
│  APT28 ──uses──► Cobalt Strike ──c2──► 185.220.101.45          │
│  CVE-2024-1234 ──affects──► Apache ──runs-on──► 91.185.x.x     │
└────────────┬────────────────────────────────────────────────────┘
             │
             │ Webhook → /api/opencti/events
             ▼
┌──────────────────────────────────────────────────────────────────┐
│              CROSS-REFERENCE ENGINE (yangi modul)                │
│              app/services/opencti_matcher.py                     │
│                                                                  │
│  C2 IP match:                                                   │
│    OpenCTI malware C2 IP → shodan_hosts → CRITICAL ALERT        │
│                                                                  │
│  Malicious domain match:                                        │
│    OpenCTI malicious domain → credentials.root_domain → ALERT   │
│                                                                  │
│  APT target match:                                              │
│    APT target sector → ripe_asns.classification → HIGH ALERT    │
│                                                                  │
│  Vulnerability correlation:                                     │
│    OpenCTI exploit confirmed → shodan_vulns → ALERT upgrade     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 8. TEXNIK AMALGA OSHIRISH

### 8.1 Bosqich 1 — Docker va OpenCTI o'rnatish

```bash
# Docker Engine o'rnatish
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# OpenCTI Docker repo
git clone https://github.com/OpenCTI-Platform/docker.git opencti
cd opencti

# .env faylni sozlash
cp .env.sample .env
# OPENCTI_ADMIN_TOKEN, MINIO_ROOT_PASSWORD va boshqalar
```

### 8.2 Bosqich 2 — Minimal docker-compose.yml

Asosiy servislar + faqat kerakli 15 ta connector:

```yaml
services:
  # === CORE SERVICES ===
  opencti:
    image: opencti/platform:6.x
    ports: ["8080:8080"]

  worker:
    image: opencti/worker:6.x
    deploy:
      replicas: 3    # 3 ta parallel worker

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.x
    environment:
      - "ES_JAVA_OPTS=-Xms4g -Xmx8g"

  redis:
    image: redis:7.x

  rabbitmq:
    image: rabbitmq:3.x-management

  minio:
    image: minio/minio:latest

  # === EXTERNAL IMPORT CONNECTORS ===
  connector-mitre:
    image: opencti/connector-mitre:6.x
    environment:
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_RUN_AND_TERMINATE=false

  connector-cisa-kev:
    image: opencti/connector-cisa-known-exploited-vulnerabilities:6.x

  connector-alienvault:
    image: opencti/connector-alienvault:6.x
    environment:
      - ALIENVAULT_API_KEY=${ALIENVAULT_API_KEY}

  connector-urlhaus:
    image: opencti/connector-urlhaus:6.x

  connector-malwarebazaar:
    image: opencti/connector-malwarebazaar:6.x

  connector-threatfox:
    image: opencti/connector-threatfox:6.x

  connector-first-epss:
    image: opencti/connector-first-epss-bulk:6.x

  # === ENRICHMENT CONNECTORS ===
  connector-shodan-internetdb:
    image: opencti/connector-shodan-internetdb:6.x

  connector-virustotal:
    image: opencti/connector-virustotal:6.x
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}

  connector-abuseipdb:
    image: opencti/connector-abuseipdb:6.x
    environment:
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}

  connector-ipinfo:
    image: opencti/connector-ipinfo:6.x
    environment:
      - IPINFO_TOKEN=${IPINFO_TOKEN}

  # === IMPORT/EXPORT ===
  connector-import-file-stix:
    image: opencti/connector-import-file-stix:6.x

  connector-export-file-stix:
    image: opencti/connector-export-file-stix:6.x

  connector-export-report-pdf:
    image: opencti/connector-export-report-pdf:6.x

  # === STREAM ===
  connector-webhook:
    image: opencti/connector-webhook:6.x
    environment:
      - WEBHOOK_URL=http://10.10.201.30:8000/api/opencti/events
```

### 8.3 Bosqich 3 — Leak → OpenCTI Export Connector

`app/scripts/opencti_export.py`:

```python
from pycti import OpenCTIApiClient
import asyncpg, asyncio

OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "your-admin-token"

async def export_vulnerable_domains():
    """Top vulnerable UZ domenlarini OpenCTI ga yuborish"""
    client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

    # PostgreSQL dan top domenlar
    conn = await asyncpg.connect(PG_DIRECT_URL)
    rows = await conn.fetch("""
        SELECT root_domain, COUNT(*) as leak_count
        FROM credentials
        WHERE root_domain IS NOT NULL
          AND root_domain LIKE '%.uz'
        GROUP BY root_domain
        ORDER BY leak_count DESC
        LIMIT 5000
    """)

    # STIX bundle yasash
    objects = []
    for row in rows:
        score = min(100, int(row["leak_count"] / 100))
        objects.append({
            "type": "domain-name",
            "spec_version": "2.1",
            "value": row["root_domain"],
            "x_opencti_score": score,
            "labels": ["leaked-credential", "uz-infrastructure"],
            "x_opencti_description": f"Leak bazasida {row['leak_count']} marta topilgan"
        })

    # Push
    bundle = {"type": "bundle", "objects": objects}
    client.stix2_create_bundle(bundle)
    print(f"{len(objects)} ta domen OpenCTI ga yuborildi")

async def export_vulnerable_hosts():
    """Shodan vulnerable host'larini OpenCTI ga yuborish"""
    client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
    conn = await asyncpg.connect(PG_DIRECT_URL)

    rows = await conn.fetch("""
        SELECT h.ip, h.org, h.asn, v.cve_id, v.cvss
        FROM shodan_hosts h
        JOIN shodan_vulns v ON v.host_id = h.id
        WHERE v.cvss >= 9.0
        ORDER BY v.cvss DESC
    """)

    for row in rows:
        # IP observable
        client.stix_cyber_observable.create(
            observableData={
                "type": "ipv4-addr",
                "value": row["ip"]
            },
            objectMarkingIds=["TLP:AMBER"],
            labels=["uz-infrastructure", "critical-vulnerability"]
        )

if __name__ == "__main__":
    asyncio.run(export_vulnerable_domains())
    asyncio.run(export_vulnerable_hosts())
```

### 8.4 Bosqich 4 — OpenCTI → Leak Cross-Reference

`app/api/opencti.py` — yangi FastAPI endpoint:

```python
from fastapi import APIRouter, Request
from app.crud.alerts import create_alert

router = APIRouter(prefix="/opencti", tags=["opencti"])

@router.post("/events")
async def opencti_webhook(request: Request):
    """OpenCTI stream webhook — yangi tahdid IoC'larini qabul qiladi"""
    event = await request.json()

    if event.get("type") == "create":
        data = event.get("data", {})
        entity_type = data.get("type")

        # C2 IP detection
        if entity_type == "ipv4-addr":
            ip = data.get("value")
            labels = data.get("labels", [])

            if any(l in labels for l in ["c2-server", "malware", "botnet"]):
                # Shodan da tekshir
                match = await db.fetchrow(
                    "SELECT ip, org FROM shodan_hosts WHERE ip = $1", ip
                )
                if match:
                    await create_alert(
                        alert_type="c2_detected",
                        severity="critical",
                        title=f"Known C2/Malware server UZ tarmog'ida: {ip}",
                        description=f"Tashkilot: {match['org']}\nOpenCTI labels: {labels}",
                        source="opencti",
                        ref_id=ip
                    )

        # Malicious domain detection
        elif entity_type == "domain-name":
            domain = data.get("value")
            labels = data.get("labels", [])

            if any(l in labels for l in ["malicious", "phishing", "c2"]):
                count = await db.fetchval(
                    "SELECT COUNT(*) FROM credentials WHERE root_domain = $1", domain
                )
                if count > 0:
                    await create_alert(
                        alert_type="malicious_domain_in_leaks",
                        severity="high",
                        title=f"Malicious domain leak bazasida topildi: {domain}",
                        description=f"Leak bazasida {count} ta credential. OpenCTI labels: {labels}",
                        source="opencti",
                        ref_id=domain
                    )

    return {"status": "ok"}
```

---

## 9. SERVER TALABLARI

### 9.1 Hozirgi server holati

| Resurs | Mavjud | Status |
|--------|--------|--------|
| RAM | 62 GB (36 GB bo'sh) | Yetarli |
| CPU | 32 core | Yetarli |
| Disk | 1.9 TB bo'sh | Yetarli |
| Docker | O'rnatilmagan | O'rnatish kerak |

### 9.2 OpenCTI minimal talablari

| Komponent | RAM | CPU | Disk |
|-----------|-----|-----|------|
| OpenCTI Platform | 2 GB | 2 core | — |
| ElasticSearch | 4–8 GB | 4 core | 100 GB+ |
| Redis | 512 MB | 1 core | — |
| RabbitMQ | 512 MB | 1 core | — |
| MinIO | 512 MB | 1 core | 50 GB+ |
| Workers (×3) | 512 MB × 3 | 1 core × 3 | — |
| 15 ta connector | 256 MB × 15 | 0.5 × 15 | — |
| **Jami** | **~14 GB** | **~15 core** | **~200 GB** |

**Sizning server: 36 GB bo'sh RAM, 32 core — to'liq yetarli.**

### 9.3 Port rejasi

| Servis | Port | Kirish |
|--------|------|--------|
| OpenCTI UI | 8080 | Internal only |
| ElasticSearch | 9200 | Internal only |
| Redis | 6379 | Internal only |
| RabbitMQ | 5672, 15672 | Internal only |
| MinIO | 9000, 9001 | Internal only |

OpenCTI tashqaridan kirish uchun nginx reverse proxy tavsiya etiladi.

---

## 10. XULOSA VA KEYINGI QADAMLAR

### 10.1 Integratsiyaning asosiy foydasi

| Imkoniyat | Hozir | OpenCTI bilan |
|-----------|-------|--------------|
| Vulnerable host topish | Shodan scan | + APT attribution |
| CVE prioritization | KEV + EPSS | + Real exploit in wild |
| Credential leak | Domain statistika | + Threat actor targeting |
| Alert | Port/CVE o'zgarishi | + Known C2/malware match |
| PDF hisobot | CWE + Shodan | + ATT&CK TTP + APT context |
| Domain monitoring | RIPE prefix | + Malicious domain feed |
| Incident response | Manual | + Automated correlation |

### 10.2 Amalga oshirish ketma-ketligi

```
Hafta 1: Docker o'rnatish + OpenCTI core setup
Hafta 2: 7 ta EXTERNAL IMPORT connector ulash (MITRE, ThreatFox, OTX...)
Hafta 3: 4 ta ENRICHMENT connector (Shodan, VT, AbuseIPDB, IPInfo)
Hafta 4: leak_data → OpenCTI export connector yozish
Hafta 5: OpenCTI → leak_data webhook + cross-reference engine
Hafta 6: Test, monitoring, hisobot integratsiyasi
```

### 10.3 Kutilayotgan natija

- **C2 detection:** UZ tarmog'idagi ma'lum C2 server'larni avtomatik aniqlash
- **APT context:** Har bir vulnerable host va CVE uchun APT attribution
- **Enriched reports:** CERT-UZ ga yuboriluvchi hisobotlarda ATT&CK TTPs
- **Proactive alerts:** Yangi APT kampaniya UZ sektorini target qilganda alert
- **Data sharing:** CERT-UZ yoki boshqa CSIRT bilan STIX/TAXII orqali ulashish

---

*Hisobot oxiri — 2026-05-19*
