

```yml
filter {
  if "linux-auth" in [tags] {
    if ![event][original] {
      mutate { copy => { "message" => "[event][original]" } }
    }

    # =========================================================
    # SSH hodisalari
    # =========================================================

    if [message] =~ /sshd/ and [message] =~ /Accepted/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: Accepted %{WORD:[_tmp][auth_method]} for %{USERNAME:[user][name]} from %{IP:[source][ip]} port %{NUMBER:[source][port]:int} %{GREEDYDATA}" }
        tag_on_failure => ["_grok_ssh_accept_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "ssh-login-success"
          "[event][outcome]"  => "success"
          "[event][type]"     => "start"
          "[event][category]" => "authentication"
          "qid"               => "5000000"
          "high_category"     => "Authentication"
          "low_category"      => "Authentication Success"
          "severity"          => "2"
        }
      }

    } else if [message] =~ /sshd/ and [message] =~ /Failed password/ {
      grok {
        match => { "message" => [
          "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: Failed password for invalid user %{USERNAME:[user][name]} from %{IP:[source][ip]} port %{NUMBER:[source][port]:int}",
          "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: Failed password for %{USERNAME:[user][name]} from %{IP:[source][ip]} port %{NUMBER:[source][port]:int}"
        ] }
        tag_on_failure => ["_grok_ssh_fail_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "ssh-login-failed"
          "[event][outcome]"  => "failure"
          "[event][type]"     => "start"
          "[event][category]" => "authentication"
          "qid"               => "5000001"
          "high_category"     => "Authentication"
          "low_category"      => "Authentication Failure"
          "severity"          => "5"
        }
      }

    } else if [message] =~ /sshd/ and [message] =~ /Invalid user/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: Invalid user %{USERNAME:[user][name]} from %{IP:[source][ip]} port %{NUMBER:[source][port]:int}" }
        tag_on_failure => ["_grok_ssh_invalid_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "ssh-invalid-user"
          "[event][outcome]"  => "failure"
          "[event][type]"     => "start"
          "[event][category]" => "authentication"
          "qid"               => "5000002"
          "high_category"     => "Authentication"
          "low_category"      => "Invalid User"
          "severity"          => "6"
        }
      }

    } else if [message] =~ /sshd/ and [message] =~ /session (opened|closed)/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: pam_unix\(sshd:session\): session %{WORD:[_tmp][session_state]} for user %{USERNAME:[user][name]}" }
        tag_on_failure => ["_grok_ssh_session_fail"]
      }

      if [_tmp][session_state] == "opened" {
        mutate {
          add_field => {
            "[event][action]" => "ssh-session-start"
            "[event][type]"   => "start"
            "qid"             => "5000010"
            "high_category"   => "Authentication"
            "low_category"    => "Session Opened"
            "severity"        => "2"
          }
        }
      } else {
        mutate {
          add_field => {
            "[event][action]" => "ssh-session-end"
            "[event][type]"   => "end"
            "qid"             => "5000011"
            "high_category"   => "Authentication"
            "low_category"    => "Session Closed"
            "severity"        => "1"
          }
        }
      }
      mutate { add_field => { "[event][category]" => "session" } }

    # =========================================================
    # SSH qo'shimcha hodisalar
    # =========================================================

    } else if [message] =~ /sshd/ and [message] =~ /Connection closed/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: Connection closed by %{IP:[source][ip]}" }
        tag_on_failure => ["_grok_ssh_conn_closed_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "ssh-connection-closed"
          "[event][outcome]"  => "success"
          "[event][type]"     => "end"
          "[event][category]" => "network"
          "qid"               => "5000012"
          "high_category"     => "Authentication"
          "low_category"      => "Connection Closed"
          "severity"          => "1"
        }
      }

    } else if [message] =~ /sshd/ and [message] =~ /Maximum authentication attempts exceeded/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: error: maximum authentication attempts exceeded for %{USERNAME:[user][name]} from %{IP:[source][ip]}" }
        tag_on_failure => ["_grok_ssh_maxauth_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "ssh-max-auth-exceeded"
          "[event][outcome]"  => "failure"
          "[event][type]"     => "start"
          "[event][category]" => "authentication"
          "qid"               => "5000003"
          "high_category"     => "Authentication"
          "low_category"      => "Brute Force"
          "severity"          => "8"
        }
      }

    } else if [message] =~ /sshd/ and [message] =~ /Disconnected from/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sshd\[%{NUMBER:[process][pid]:int}\]: Disconnected from %{IP:[source][ip]}" }
        tag_on_failure => ["_grok_ssh_disconn_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "ssh-disconnected"
          "[event][outcome]"  => "success"
          "[event][type]"     => "end"
          "[event][category]" => "network"
          "qid"               => "5000013"
          "high_category"     => "Authentication"
          "low_category"      => "Disconnected"
          "severity"          => "1"
        }
      }

    # =========================================================
    # SUDO hodisalari
    # =========================================================

    } else if [message] =~ /sudo/ and [message] =~ /COMMAND=/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sudo:\s+%{USERNAME:[user][name]} : TTY=%{DATA:[_tmp][tty]} ; PWD=%{DATA:[process][working_directory]} ; USER=%{USERNAME:[_tmp][target_user]} ; COMMAND=%{GREEDYDATA:[process][command_line]}" }
        tag_on_failure => ["_grok_sudo_cmd_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "sudo-command"
          "[event][outcome]"  => "success"
          "[event][type]"     => "start"
          "[event][category]" => "iam"
          "severity"          => "5"
        }
        rename => { "[_tmp][target_user]" => "[user][effective][name]" }
      }

      # Root sifatida sudo → yuqori severity
      ruby {
        code => '
          target = event.get("[user][effective][name]").to_s
          cmd    = event.get("[process][command_line]").to_s.upcase

          if target == "root"
            event.set("qid",           "6000001")
            event.set("high_category", "Privilege Escalation")
            event.set("low_category",  "Sudo to Root")
            event.set("severity",      "7")
          elsif cmd =~ /PASSWD|USERADD|USERDEL|USERMOD|CHOWN|CHMOD/
            event.set("qid",           "6000002")
            event.set("high_category", "Privilege Escalation")
            event.set("low_category",  "Privileged Command")
            event.set("severity",      "6")
          else
            event.set("qid",           "6000003")
            event.set("high_category", "System")
            event.set("low_category",  "Sudo Command")
            event.set("severity",      "4")
          end
        '
      }

    } else if [message] =~ /sudo/ and [message] =~ /authentication failure/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sudo: pam_unix\(sudo:auth\): authentication failure; logname=%{DATA} uid=%{NUMBER} euid=%{NUMBER} tty=%{DATA} ruser=%{USERNAME:[user][name]} rhost=%{DATA}" }
        tag_on_failure => ["_grok_sudo_authfail_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "sudo-auth-failed"
          "[event][outcome]"  => "failure"
          "[event][type]"     => "start"
          "[event][category]" => "authentication"
          "qid"               => "6000004"
          "high_category"     => "Privilege Escalation"
          "low_category"      => "Sudo Auth Failure"
          "severity"          => "7"
        }
      }

    } else if [message] =~ /sudo/ and [message] =~ /pam_unix\(sudo:session\)/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} sudo: pam_unix\(sudo:session\): session %{WORD:[_tmp][session_state]} for user %{USERNAME:[user][effective][name]}" }
        tag_on_failure => ["_grok_sudo_session_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "sudo-session"
          "[event][category]" => "session"
          "qid"               => "6000005"
          "high_category"     => "System"
          "low_category"      => "Sudo Session"
          "severity"          => "2"
        }
      }

    # =========================================================
    # PAM hodisalari
    # =========================================================

    } else if [message] =~ /pam_unix/ and [message] =~ /account locked/ {
      grok {
        match => { "message" => "%{TIMESTAMP_ISO8601:[_tmp][ts]} %{HOSTNAME:[host][hostname]} %{DATA}: pam_unix\(%{DATA}\): account %{DATA} for user %{USERNAME:[user][name]}" }
        tag_on_failure => ["_grok_pam_locked_fail"]
      }
      mutate {
        add_field => {
          "[event][action]"   => "account-locked"
          "[event][outcome]"  => "failure"
          "[event][type]"     => "change"
          "[event][category]" => "iam"
          "qid"               => "5000020"
          "high_category"     => "Authentication"
          "low_category"      => "Account Locked"
          "severity"          => "7"
        }
      }

    # =========================================================
    # CRON — o'tkazib yuborish
    # =========================================================

    } else if [message] =~ /CRON/ {
      drop {}

    # =========================================================
    # Noma'lum hodisa
    # =========================================================

    } else {
      mutate {
        add_field => {
          "qid"           => "6000000"
          "high_category" => "Unknown"
          "low_category"  => "Unknown"
          "severity"      => "0"
        }
      }
    }

    # =========================================================
    # ECS metadata
    # =========================================================
    mutate {
      replace => {
        "[ecs][version]"           => "8.11.0"
        "[event][kind]"            => "event"
        "[data_stream][type]"      => "logs"
        "[data_stream][dataset]"   => "linux.auth"
        "[data_stream][namespace]" => "main"
      }
    }

    if [_tmp][ts] {
      date {
        match    => ["[_tmp][ts]", "ISO8601"]
        target   => "@timestamp"
        timezone => "Asia/Tashkent"
      }
    }

    if [source][ip] {
      geoip {
        source => "[source][ip]"
        target => "[source][geo]"
      }
      mutate { add_field => { "[related][ip]" => "%{[source][ip]}" } }
    }

    mutate { remove_field => ["[_tmp]"] }
  }
}
```

---

## QID jadvali — linux-auth
```
QID      High Category         Low Category            Severity
────────────────────────────────────────────────────────────────
5000000  Authentication        Authentication Success   2
5000001  Authentication        Authentication Failure   5
5000002  Authentication        Invalid User             6
5000003  Authentication        Brute Force              8
5000010  Authentication        Session Opened           2
5000011  Authentication        Session Closed           1
5000012  Authentication        Connection Closed        1
5000013  Authentication        Disconnected             1
5000020  Authentication        Account Locked           7
6000001  Privilege Escalation  Sudo to Root             7
6000002  Privilege Escalation  Privileged Command       6
6000003  System                Sudo Command             4
6000004  Privilege Escalation  Sudo Auth Failure        7
6000005  System                Sudo Session             2
6000000  Unknown               Unknown                  0
```






Logstash pipeline:
  event.action   = "ssh-login-failed"
  high_category  = "Authentication"
  low_category   = "Authentication Failure"
  severity       = 5
  qid            = "5000001"


```yml
building_blocks:
  - id: BB_CRITICAL_SERVERS
    type: ip_list
    values: ["10.0.0.100", "10.0.0.101"]

  - id: BB_BUSINESS_HOURS
    type: time_range
    start: "08:00"
    end: "18:00"
    days: [1,2,3,4,5]

  - id: BB_AUTH_SCANNERS
    type: ip_list
    values: ["10.0.0.200"]
```


rule
```yml
rules:
  - id: R001
    name: "SSH Brute Force"
    enabled: true

    conditions:
      high_category: "Authentication"
      low_category:  "Authentication Failure"
      exclude:
        source_ip: BB_AUTH_SCANNERS
      threshold:
        count:    5
        window:   120
        group_by: [source_ip, username]

    action:
      severity: 8
      add_to_refset:
        name: "brute_force_sources"
        field: source_ip
        ttl: 600

    response:
      create_offense: true
      index_by: source_ip

    mitre:
      tactic:    "TA0006"
      technique: "T1110.001"

  - id: R002
    name: "Brute Force then Success"
    enabled: true

    conditions:
      high_category: "Authentication"
      low_category:  "Authentication Success"
      source_ip_in_refset: "brute_force_sources"

    action:
      severity: 10
      add_to_refset:
        name: "confirmed_attackers"
        field: source_ip
        ttl: 3600

    response:
      create_offense: true
      index_by: source_ip
      email: "soc@company.com"

    mitre:
      tactic:    "TA0001"
      technique: "T1078"

  - id: R003
    name: "Confirmed Attacker SQL Injection"
    enabled: true

    conditions:
      high_category: "Exploit"
      low_category:  "SQL Injection"
      source_ip_in_refset: "confirmed_attackers"

    action:
      severity: 10

    response:
      create_offense: true
      index_by: source_ip
      email: "soc-critical@company.com"

    mitre:
      tactic:    "TA0001"
      technique: "T1190"
```

---

## 5. Go Engine — Ichki ishlash
```
Startup:
  1. YAML qoidalar yuklanadi → Struct
  2. BB'lar yuklanadi → Struct
  3. Redis ulanadi
  4. Kafka consumer ishga tushadi

Har event kelganda (parallel goroutine):
  1. Event JSON parse
  2. Har qoida uchun tekshirish:
     a. high_category mos?  → string compare
     b. low_category mos?   → string compare
     c. exclude BB?         → Redis/memory lookup
     d. refset da bormi?    → Redis SISMEMBER
     e. threshold yetdimi?  → Redis sliding window
  3. Match → Action bajar:
     a. severity o'zgartir
     b. RefSet ga qo'sh (Redis SADD + TTL)
  4. Match → Offense Manager ga yuborish

Kechikish: ~1-5 millisekund
```

---

## 6. Yangilangan To'liq Arxitektura
```
┌─────────────────────────────────────────────────┐
│              SERVERLAR / AGENTLAR               │
└──────────────────┬──────────────────────────────┘
                   │ raw log
                   ▼
┌─────────────────────────────────────────────────┐
│                  LOGSTASH                       │
│  Grok → ECS normalize                          │
│  high_category + low_category + qid + severity │
└────────┬──────────────────────┬────────────────┘
         │ JSON                 │ JSON
         ▼                      ▼
┌──────────────┐      ┌─────────────────────┐
│   Kafka      │      │  Elasticsearch      │
│  (buffer)    │      │  siem-events-*      │
└──────┬───────┘      └─────────────────────┘
       │ event stream
       ▼
┌─────────────────────────────────────────────────┐
│           Go CRE Engine (ecs-ep)                │
│                                                 │
│  YAML Rules yuklanadi                          │
│  BB'lar yuklanadi                              │
│                                                 │
│  Har event:                                     │
│   category check → string compare              │
│   BB exclude     → memory lookup               │
│   RefSet check   → Redis SISMEMBER             │
│   Threshold      → Redis sliding window        │
│   MATCH          → Action + Offense signal     │
└──────────┬──────────────────────────────────────┘
           │ match signal
           ▼
┌─────────────────────────────────────────────────┐
│              Redis                              │
│  Sliding windows: "R001:45.92.X.X" → [T1..T5] │
│  Reference Sets:  "brute_force_sources" → set  │
│  BB cache:        IP list, time range           │
└─────────────────────────────────────────────────┘
           │ offense candidate
           ▼
┌─────────────────────────────────────────────────┐
│           Offense Manager (Magistrate)          │
│                                                 │
│  Ochiq offense bormi? (Redis/ES)               │
│   BOR  → biriktir, magnitude++                 │
│   YO'Q → yangi offense yarat                   │
│                                                 │
│  Timeline, contributing_rules to'planadi       │
│  Magnitude = f(severity, credibility, asset)   │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│              Elasticsearch                      │
│  siem-offenses-*  ← offenselar                 │
│  siem-alerts-*    ← intermediate alertlar      │
│  siem-anomalies-* ← ES|QL natijalar            │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│                   Kibana                        │
│  Offense Dashboard  │  Anomaly │  Threat Hunt  │
└─────────────────────────────────────────────────┘
```

---

## 7. QRadar vs Sizning Tizim — Yakuniy Jadval
```
QRadar komponenti    Sizning tizim
───────────────────────────────────────────────────
DSM                  Logstash (Grok + Mutate)
QID + Kategoriya     high_category + low_category + qid
ecs-ec-ingress       Kafka (zero loss buffer)
ecs-ep / CRE         Go Engine
Rule Wizard          YAML (odam o'qiydi)
Building Block       YAML BB + Redis
Reference Set        Redis Set (SADD/SISMEMBER)
Sliding Window       Redis List + TTL
Magistrate           Offense Manager (Python/Go)
Ariel DB             Elasticsearch siem-events-*
PostgreSQL           Elasticsearch siem-offenses-*
ADE                  ES|QL Watcher
Console UI           Kibana
```

---

![[Pasted image 20260328093328.png]]



QRadar BB turi          Wazuh ekvivalenti
────────────────────────────────────────────
IP ro'yxati         →   CDB List
Vaqt oralig'i       →   Rule time filter
Kategoriya guruhi   →   Rule group
Dinamik ro'yxat     →   Active Response List
Reusable shart      →   Rule (level=0, no alert)


```xml
# /var/ossec/etc/lists/critical_servers
10.0.0.100:
10.0.0.101:
10.0.0.102:

# /var/ossec/etc/lists/auth_scanners
10.0.0.200:
10.0.0.201:

# /var/ossec/etc/lists/admin_users
root:
admin:
administrator:
```

```xml
<ossec_config>
  <ruleset>
    <list>etc/lists/critical_servers</list>
    <list>etc/lists/auth_scanners</list>
    <list>etc/lists/admin_users</list>
  </ruleset>
</ossec_config>
```



```xml
<rule id="100010" level="12">
  <decoded_as>linux-ssh-failed</decoded_as>
  <list field="dstip" lookup="match_key">
    etc/lists/critical_servers
  </list>
  <description>SSH fail on CRITICAL server</description>
  <group>brute_force,critical_asset</group>
</rule>
```

Bu aynan QRadar BB'si kabi:
```xml
QRadar:  when destinationip IN BB: Critical_Servers
Wazuh:   <list field="dstip" lookup="match_key">critical_servers</list>
```