import crypto from 'node:crypto';

/**
 * Serverless Function Node.js (Webhook Receiver)
 * Endpoint: POST /api/webhook
 * Menerima laporan dari Supabase dengan validasi HMAC-SHA256 & notifikasi Telegram
 */
export default async function handler(req, res) {
  // Compatibility wrapper untuk status & json jika dijalankan di Node HTTP standar
  if (!res.status) {
    res.status = (code) => {
      res.statusCode = code;
      return res;
    };
  }
  if (!res.json) {
    res.json = (data) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(data));
    };
  }

  // Hanya menerima method POST
  if (req.method !== 'POST') {
    return res.status(405).json({
      status: 'error',
      statusCode: 405,
      message: 'Method not allowed. Hanya menerima request POST.'
    });
  }

  // 2a. Periksa apakah header x-signature ada. Jika tidak ada, tolak dengan 400 Bad Request
  const signature = req.headers['x-signature'] || req.headers['X-Signature'];
  if (!signature) {
    return res.status(400).json({
      status: 'error',
      statusCode: 400,
      message: 'Bad Request: Header x-signature wajib disertakan.'
    });
  }

  // 2b. Ambil isi body request sebagai string (json.stringify jika perlu)
  let bodyString = '';
  if (typeof req.body === 'string') {
    bodyString = req.body;
  } else if (Buffer.isBuffer(req.body)) {
    bodyString = req.body.toString('utf-8');
  } else if (req.body && typeof req.body === 'object') {
    bodyString = JSON.stringify(req.body);
  } else {
    // Jika body kosong atau belum di-buffer
    bodyString = '';
  }

  // 2c. Buat HMAC-SHA256 dari body string menggunakan crypto.createHmac("sha256", hmac_secret).update(body).digest("hex")
  const hmacSecret = process.env.SUPABASE_WEBHOOK_SECRET || process.env.HMAC_SECRET || 'super-secret-hmac-key-supabase-2026';
  const computedHmac = crypto
    .createHmac('sha256', hmacSecret)
    .update(bodyString)
    .digest('hex');

  // Bersihkan prefix jika ada (misal sha256=...)
  const cleanSignature = String(signature).replace(/^sha256=/, '').trim();

  // 2d. Bandingkan hmac yang dibuat dengan nilai di header x-signature menggunakan perbandingan string biasa
  const isMatch = (computedHmac === cleanSignature);

  // 2e. Jika tidak cocok, tolak dengan 401 Unauthorized
  if (!isMatch) {
    return res.status(401).json({
      status: 'error',
      statusCode: 401,
      message: 'Unauthorized: Tanda tangan HMAC-SHA256 tidak valid (tampered/forged signature).'
    });
  }

  // Jika cocok, parse payload Supabase
  let payload = {};
  try {
    payload = typeof req.body === 'object' && req.body !== null ? req.body : JSON.parse(bodyString);
  } catch {
    payload = { raw: bodyString };
  }

  const eventStatus = payload.status || (payload.is_threat ? 'bahaya' : 'aman') || 'aman';
  const threatLevel = payload.threat_level !== undefined ? payload.threat_level : (eventStatus === 'bahaya' ? '3 (Kritis)' : '0 (Normal)');
  const messageDetail = payload.message || payload.query || payload.detail || 'Tidak ada rincian pesan.';

  // 3. Integrasi Telegram Bot Alert
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  let telegramSent = false;
  let telegramResponse = null;

  const telegramText = [
    `🛡️ *AEGIS SOC - LAPORAN KEAMANAN DATABASE*`,
    `━━━━━━━━━━━━━━━━━━━━━━`,
    `📌 *Status Kejadian:* ${String(eventStatus).toUpperCase() === 'BAHAYA' ? '🚨 BAHAYA' : '✅ AMAN'}`,
    `⚠️ *Level Ancaman:* Level ${threatLevel}`,
    `📝 *Detail Pesan:*`,
    `\`${String(messageDetail).replace(/[`*_\\]/g, '')}\``,
    `⏱️ *Waktu:* ${new Date().toISOString()}`,
    `🔐 *Integritas:* HMAC-SHA256 Verified`
  ].join('\n');

  if (botToken && chatId) {
    try {
      const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: telegramText,
          parse_mode: 'Markdown'
        })
      });
      telegramResponse = await tgRes.json();
      telegramSent = tgRes.ok;
    } catch (err) {
      console.error('Gagal mengirim pesan Telegram:', err);
      telegramResponse = { error: err.message };
    }
  } else {
    // Mode fallback / simulasi jika env belum dikonfigurasi di lokal
    telegramSent = true;
    telegramResponse = {
      simulated: true,
      note: 'Telegram alert simulated. Konfigurasikan TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID untuk pengiriman live.'
    };
  }

  // Return sukses 200 OK
  return res.status(200).json({
    status: 'success',
    statusCode: 200,
    message: 'Webhook Supabase berhasil diterima dan diverifikasi dengan HMAC-SHA256.',
    hmac_verified: true,
    data: {
      status_kejadian: eventStatus,
      threat_level: threatLevel,
      detail_pesan: messageDetail,
      telegram_alert_sent: telegramSent,
      telegram_info: telegramResponse
    }
  });
}
