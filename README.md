# tbtinfo.uz Xavfsizlik Audit Hisoboti
**Sana:** 2026-03-31  
**Ruxsat xati:** 2026/12-222-aad3  
**Auditor:** Pentest jamoasi  

---

## Texnik Ma'lumotlar

| Parametr | Qiymat |
|----------|--------|
| Domen | tbtinfo.uz |
| IP | 94.141.85.93 |
| Joylashuv | Toshkent, O'zbekiston (IST Telekom LLC) |
| Veb server | nginx (reverse proxy) + Apache2 (orqa) |
| Framework | Yii2 (PHP) - Advanced template |
| Admin panel | AdminLTE 3 |
| DNS provayder | webspace.uz |

---

## Topilgan Zaifliklar

### 🔴 KRITIK - #1: Maxfiy ma'lumotlar oshkor (Information Disclosure)

**Endpoint:** `POST /admin/site/re`  
**Tavsif:** Parolni tiklash funksiyasi ishlatilganda, server to'liq Yii2 stack trace va ichki tizim yo'llarini oshkor qiladi.

**Oshkor bo'lgan ma'lumotlar:**
- Server fayl yo'li: `/var/www/tbtinfo/`
- Framework: `yii2 v2.x`
- Ma'lumotlar bazasi jadvali: `user_codes` (mavjud emas)
- Ichki kod tuzilishi

**Xavf:** Tajovuzkor server arxitekturasini bilib, keyingi hujumlarni maqsadli qilishi mumkin.

**Tavsiya:** `YII_DEBUG` va `YII_ENV` ni production'da o'chirish:
```php
// index.php
defined('YII_DEBUG') or define('YII_DEBUG', false);
defined('YII_ENV') or define('YII_ENV', 'prod');
```

---

### 🔴 KRITIK - #2: Test muhiti ochiq (Exposed Staging Environment)

**Endpoint:** `http://tbtinfo.uz:8080/`  
**Tavsif:** Port 8080 da alohida "TestUzsti" nomli test ilovasi ishlamoqda. Bu ilova:
- CAPTCHA himoyasi yo'q (asosiy saytda bor)
- HTTP (SSL yo'q) orqali ochiq
- Brute-force hujumiga himoyasiz
- Ma'lumotlar bazasi xatolarini oshkor qilmoqda (Database Exception #1045)

**Xavf:** Tajovuzkor CAPTCHA'siz login formiga cheksiz brute-force hujumi qilishi mumkin.

**Tavsiya:**
- Test muhitini tashqi tarmoqdan bloklash (firewall)
- Yoki test muhitiga ham CAPTCHA qo'shish
- HTTPS ni majburiy qilish

---

### 🟠 YUQORI - #3: SSL Sertifikat noto'g'ri sozlangan (SSL Mismatch)

**Tavsif:** `tbtinfo.uz` uchun SSL sertifikat `adm.tbtinfo.uz` domen nomi uchun berilgan. Bu:
- Brauzerda xavfsizlik ogohlantirishini chiqaradi
- Foydalanuvchilarni fishing hujumlariga nisbatan zaif qiladi

**Tekshiruv:**
```
SSL: no alternative certificate subject name matches target host name 'tbtinfo.uz'
CN=adm.tbtinfo.uz
```

**Tavsiya:** `tbtinfo.uz` va `www.tbtinfo.uz` uchun alohida yoki SAN sertifikat olish.

---

### 🟠 YUQORI - #4: HTTP HTTPS ga yo'naltirilmagan

**Tavsif:** `http://tbtinfo.uz/` (port 80) Apache2 standart sahifasini ko'rsatmoqda - HTTPS ga yo'naltirish yo'q. Bu quyidagilarni oshkor qiladi:
- Apache2 versiyasi va Ubuntu OS ishlatilayotgani
- Server tizim konfiguratsiyasi

**Tavsiya:**
```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

---

### 🟡 O'RTA - #5: Xavfsizlik HTTP sarlavhalari yo'q (Missing Security Headers)

**Tavsif:** Quyidagi muhim xavfsizlik sarlavhalari mavjud emas:

| Sarlavha | Holat | Xavf |
|----------|-------|------|
| `X-Frame-Options` | ❌ YO'Q | Clickjacking |
| `X-XSS-Protection` | ❌ YO'Q | XSS |
| `X-Content-Type-Options` | ❌ YO'Q | MIME sniffing |
| `Content-Security-Policy` | ❌ YO'Q | XSS, injection |
| `Strict-Transport-Security` | ❌ YO'Q | SSL stripping |

**Tavsiya (nginx):**
```nginx
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header Content-Security-Policy "default-src 'self'";
```

---

### 🟡 O'RTA - #6: Session Cookie - Secure flag yo'q

**Tavsif:** Session cookie (`advanced-backend`) `Secure` flag siz berilmoqda. Bu HTTP orqali cookie o'g'irlanishiga imkon beradi.

**Joriy holat:**
```
Set-Cookie: advanced-backend=...; path=/; HttpOnly
```

**Kutilgan holat:**
```
Set-Cookie: advanced-backend=...; path=/; HttpOnly; Secure; SameSite=Strict
```

**Tavsiya:** Yii2 konfiguratsiyasida:
```php
'session' => [
    'cookieParams' => [
        'httpOnly' => true,
        'secure' => true,
        'sameSite' => 'Strict',
    ],
],
```

---

### 🟡 O'RTA - #7: robots.txt - barcha yo'llar bloklangan

**Tavsif:** `robots.txt` faylida `Disallow: /` ko'rsatilgan, lekin bu haqiqiy himoya emas - bu faqat qidiruv tizimlariga ta'sir qiladi, tajovuzkorlarga emas. Admin panel yo'li (`/admin/site/login`) ommaga oshkor.

---

### 🔵 PAST - #8: Server versiyasi oshkor

**Tavsif:** HTTP sarlavhasida `Server: nginx` ko'rinmoqda. Versiya yashirilgan (yaxshi), lekin nginx oshkor.

**Tavsiya:**
```nginx
server_tokens off;
```

---

## Xulosa

| Daraja | Soni |
|--------|------|
| 🔴 Kritik | 2 |
| 🟠 Yuqori | 2 |
| 🟡 O'rta | 3 |
| 🔵 Past | 1 |
| **Jami** | **8** |

---

## Keyingi Qadamlar (Tavsiya etiladi)

1. Zudlik bilan: Port 8080 ni tashqi tarmoqdan yopish
2. Zudlik bilan: `YII_DEBUG=false` qilish (stack trace o'chirish)
3. 1 hafta ichida: SSL sertifikatni to'g'rilash
4. 1 hafta ichida: HTTPS majburiy yo'naltirish
5. 2 hafta ichida: Security headers qo'shish
6. 2 hafta ichida: Cookie flags to'g'rilash

