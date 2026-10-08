# 🛡️ Aegis Real-Time Database Security Monitoring System
### Dual-AI Concurrency (NVIDIA NIM), Supabase HMAC-SHA256 Webhook & Telegram Alert Engine

Sistem monitoring keamanan database real-time yang dirancang oleh Web Security Engineer untuk mendeteksi serangan injeksi basis data, memvalidasi webhook Supabase dengan standar zero-trust HMAC-SHA256, mengirim notifikasi otomatis ke Telegram Bot, dan mengeksekusi inferensi paralel dua model AI (NVIDIA NIM) dengan latensi minimal via `asyncio.gather()`.

---

## 🏗️ 1. Struktur Repositori Lengkap
```text
integrated web/
├── .github/
│   └── workflows/
│       └── deploy.yml          # Pipeline CI/CD GitHub Actions ke Vercel Prod
├── api/
│   ├── proses_ai.py            # FastAPI Serverless: Dual AI Async (NVIDIA NIM)
│   └── webhook.js              # Node.js Serverless: HMAC-SHA256 & Telegram Bot Alert
├── public/
│   ├── index.html              # Web Dashboard Premium Cyber-SOC
│   ├── style.css               # Glassmorphism & Plus Jakarta Sans Styling
│   └── app.js                  # Dynamic State Transition, Web Crypto HMAC & Console
├── scripts/
│   └── test_flows.js           # Uji 3 Skenario Keamanan Webhook (Valid, Tampered, Missing)
├── script/
│   └── test_flows.js           # Alias runner script/test_flows.js
├── test_async_ai.py            # Pengujian benchmark konkurensi (0.5s vs 0.8s)
├── test_api_endpoint.py        # Pengujian fungsional JSON response endpoint FastAPI
├── test_webhook.py             # Pengujian verifikasi integritas HMAC-SHA256 Python
├── package.json                # Konfigurasi ES Module & scripts Node.js
├── requirements.txt            # Dependensi Python untuk runtime Vercel & testing
├── server.js                   # Unified local development server
├── vercel.json                 # Routing serverless Vercel (Python + Node.js + Public)
└── README.md                   # Dokumentasi teknis lengkap & log pengujian
```

---

## 🔐 2. Hasil Uji 3 Skenario Keamanan Webhook (Langkah 3)

Perintah eksekusi:
```bash
node scripts/test_flows.js
```

### Log Output Terminal Uji:
```text
===========================================================================
🛡️  PENGUJIAN 3 SKENARIO KEAMANAN WEBHOOK SUPABASE (HMAC-SHA256)
===========================================================================

[TEST 1] Signature HMAC Benar (Valid Signature)
• Payload : {"status":"bahaya","threat_level":"3 (Kritis)","message":"SQL Injection exploit detected: ' UNION SELECT username, password_hash FROM admin_users --","timestamp":"2026-10-08T04:35:56.591Z"}
• Header  : x-signature = 674de93e931fedb7774af253cc868152bab666512d74d0fb40857a1cd9246bf4
• Status  : 200 OK
• Respons : {
  "status": "success",
  "statusCode": 200,
  "message": "Webhook Supabase berhasil diterima dan diverifikasi dengan HMAC-SHA256.",
  "hmac_verified": true,
  "data": {
    "status_kejadian": "bahaya",
    "threat_level": "3 (Kritis)",
    "detail_pesan": "SQL Injection exploit detected: ' UNION SELECT username, password_hash FROM admin_users --",
    "telegram_alert_sent": true,
    "telegram_info": {
      "simulated": true,
      "note": "Telegram alert simulated. Konfigurasikan TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID untuk pengiriman live."
    }
  }
}
✅ HASIL TEST 1: SUKSES (200 OK) - Webhook diterima & notifikasi Telegram diproses.

---------------------------------------------------------------------------
[TEST 2] Signature Diubah / Dirating (Tampered Signature)
• Header  : x-signature = 674de93e931fedb7774af253cc868152bab666512d74d0fb40857a1cd9abcdef (DIRUSAK)
• Status  : 401 Unauthorized
• Respons : {
  "status": "error",
  "statusCode": 401,
  "message": "Unauthorized: Tanda tangan HMAC-SHA256 tidak valid (tampered/forged signature)."
}
✅ HASIL TEST 2: SUKSES (401 Unauthorized) - Upaya pemalsuan signature berhasil ditolak!

---------------------------------------------------------------------------
[TEST 3] Tanpa Header x-signature (Missing Header)
• Header  : (Tanpa x-signature)
• Status  : 400 Bad Request
• Respons : {
  "status": "error",
  "statusCode": 400,
  "message": "Bad Request: Header x-signature wajib disertakan."
}
✅ HASIL TEST 3: SUKSES (400 Bad Request) - Request tanpa header signature berhasil ditolak!

===========================================================================
🎉 KESIMPULAN: SEMUA 3 SKENARIO KEAMANAN LOLOS DENGAN SEMPURNA!
   - Test 1 (Valid)    : 200 OK
   - Test 2 (Tampered) : 401 Unauthorized
   - Test 3 (Missing)  : 400 Bad Request
===========================================================================
```

---

## ⚡ 3. Hasil Pembuktian Konkurensi Asynchronous Dual AI (Langkah 2)

Perintah eksekusi:
```bash
python test_async_ai.py
```

### Log Output Terminal Uji:
```text
======================================================================
🛡️  PENGUJIAN KONKURENSI ASYNCHRONOUS DUAL AI (NVIDIA NIM)
======================================================================

[TEST 1] Eksekusi Paralel (asyncio.gather) - SQL Injection Threat:
Input: "' UNION SELECT credit_card_num, cvv FROM customers WHERE 1=1 --"
----------------------------------------------------------------------
  Model A (RF)  : Random Forest (RF / NVIDIA NIM) -> Prediksi: [BAHAYA] (Conf: 95.0%) [Delay: ~0.3s]
  Model B (SVM) : Support Vector Machine (SVM / NVIDIA NIM) -> Prediksi: [BAHAYA] (Conf: 93.1%) [Delay: ~0.5s]
----------------------------------------------------------------------
⏱️  TOTAL WAKTU PARALEL (asyncio.gather) : 0.5100 detik
    Target Waktu Maksimal                : ~0.50 detik (waktu model terlama)

[TEST 2] Perbandingan Benchmark: Sekuensial vs Paralel:
  • Waktu Eksekusi Sekuensial (0.3s + 0.5s) : 0.8165 detik
  • Waktu Eksekusi Paralel    (asyncio.gather): 0.5100 detik
  • Penghematan Waktu (Latency Reduction) : 0.3065 detik (37.5% lebih cepat)
----------------------------------------------------------------------
✅ PEMBUKTIAN SUKSES: Waktu total ≈ 0.5 detik (mengikuti durasi model terlama / SVM).
   Bukan 0.8 detik (sekuensial). Konkurensi non-blocking terbukti aktif sempurna!
======================================================================
```

---

## 🖥️ 4. Spesifikasi UI Dashboard Keamanan (Langkah 4)

1. **Desain Visual Premium (Dark Theme)**:
   - Efek Glassmorphism dengan latar blur (`backdrop-filter: blur(14px)`).
   - Tipografi modern Google Fonts: **Plus Jakarta Sans** (UI utama) & **JetBrains Mono** (Metrik, hash, dan log).
   - Palet warna cyber-SOC terkurasi: Obsidian `#070b14`, Emerald `#10b981`, Crimson `#ef4444`, Cyan `#00f0ff`.

2. **Metric Card dengan State Transition Dinamis**:
   - **State Aman**: Class `.state-secured`, background hijau gradasi, badge `AMAN`, teks `SYSTEM SECURED`.
   - **State Bahaya**: Class `.state-critical`, background merah gradasi pulse, badge `BAHAYA`, teks `LEVEL ALERT: CRITICAL`.
   - Transisi status berjalan dinamis melalui JavaScript tanpa perlu me-reload halaman.

3. **Panel Simulator Webhook HMAC Client-Side**:
   - Dropdown status: `aman` / `bahaya`.
   - Dropdown level ancaman: `0` (Normal) hingga `3` (Kritis).
   - Input teks pesan laporan & kunci rahasia HMAC.
   - Checkbox `Kirim tanda tangan palsu (simulasi serangan)`.
   - Tombol kirim webhook yang menghitung HMAC-SHA256 di browser menggunakan `window.crypto.subtle`.

4. **Panel Benchmark AI Asynchronous**:
   - Tombol `Jalankan Rantai AI (Paralel)`.
   - Tampilan total waktu eksekusi (`0.5039s`).
   - Kartu terpisah untuk Model RF dan Model SVM dengan indikator warna (Hijau = Aman, Merah = Bahaya).

5. **Log Console Virtual (Monospace)**:
   - Jendela terminal Unix lengkap dengan window controls (merah, kuning, hijau).
   - Menampilkan rekam jejak setiap aktivitas (HMAC digest, status webhook, Telegram alert, hasil AI inference) beserta timestamp real-time.
