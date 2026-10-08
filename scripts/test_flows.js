import http from 'node:http';
import crypto from 'node:crypto';
import handler from '../api/webhook.js';

const HMAC_SECRET = process.env.SUPABASE_WEBHOOK_SECRET || 'super-secret-hmac-key-supabase-2026';

// Helper membuat HMAC-SHA256 signature
function generateSignature(payloadString, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(payloadString)
    .digest('hex');
}

// Inisialisasi HTTP server lokal untuk menguji webhook handler end-to-end
async function createTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      // Buffer request body
      let bodyData = '';
      req.on('data', chunk => {
        bodyData += chunk;
      });
      req.on('end', async () => {
        try {
          req.body = bodyData ? JSON.parse(bodyData) : '';
        } catch {
          req.body = bodyData;
        }
        await handler(req, res);
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ server, port });
    });
  });
}

async function runSecurityFlowTests() {
  console.log('='.repeat(75));
  console.log('🛡️  PENGUJIAN 3 SKENARIO KEAMANAN WEBHOOK SUPABASE (HMAC-SHA256)');
  console.log('='.repeat(75));

  const { server, port } = await createTestServer();
  const baseUrl = `http://127.0.0.1:${port}/api/webhook`;

  const samplePayload = {
    status: 'bahaya',
    threat_level: '3 (Kritis)',
    message: "SQL Injection exploit detected: ' UNION SELECT username, password_hash FROM admin_users --",
    timestamp: new Date().toISOString()
  };

  const payloadString = JSON.stringify(samplePayload);
  const validSignature = generateSignature(payloadString, HMAC_SECRET);

  let passedAll = true;

  try {
    // -------------------------------------------------------------
    // TEST 1: Signature HMAC Valid
    // -------------------------------------------------------------
    console.log('\n[TEST 1] Signature HMAC Benar (Valid Signature)');
    console.log(`• Payload : ${payloadString}`);
    console.log(`• Header  : x-signature = ${validSignature}`);

    const res1 = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': validSignature
      },
      body: payloadString
    });
    const data1 = await res1.json();

    console.log(`• Status  : ${res1.status} ${res1.statusText}`);
    console.log(`• Respons :`, JSON.stringify(data1, null, 2));

    if (res1.status === 200 && data1.status === 'success') {
      console.log('✅ HASIL TEST 1: SUKSES (200 OK) - Webhook diterima & notifikasi Telegram diproses.');
    } else {
      console.log('❌ HASIL TEST 1: GAGAL!');
      passedAll = false;
    }

    // -------------------------------------------------------------
    // TEST 2: Signature Dirating / Dimanipulasi (Tampered Signature)
    // -------------------------------------------------------------
    console.log('\n' + '-'.repeat(75));
    console.log('[TEST 2] Signature Diubah / Dirating (Tampered Signature)');
    const tamperedSignature = validSignature.substring(0, validSignature.length - 6) + 'abcdef';
    console.log(`• Header  : x-signature = ${tamperedSignature} (DIRUSAK)`);

    const res2 = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': tamperedSignature
      },
      body: payloadString
    });
    const data2 = await res2.json();

    console.log(`• Status  : ${res2.status} ${res2.statusText}`);
    console.log(`• Respons :`, JSON.stringify(data2, null, 2));

    if (res2.status === 401) {
      console.log('✅ HASIL TEST 2: SUKSES (401 Unauthorized) - Upaya pemalsuan signature berhasil ditolak!');
    } else {
      console.log('❌ HASIL TEST 2: GAGAL!');
      passedAll = false;
    }

    // -------------------------------------------------------------
    // TEST 3: Tanpa Header x-signature (Missing Header)
    // -------------------------------------------------------------
    console.log('\n' + '-'.repeat(75));
    console.log('[TEST 3] Tanpa Header x-signature (Missing Header)');
    console.log(`• Header  : (Tanpa x-signature)`);

    const res3 = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: payloadString
    });
    const data3 = await res3.json();

    console.log(`• Status  : ${res3.status} ${res3.statusText}`);
    console.log(`• Respons :`, JSON.stringify(data3, null, 2));

    if (res3.status === 400) {
      console.log('✅ HASIL TEST 3: SUKSES (400 Bad Request) - Request tanpa header signature berhasil ditolak!');
    } else {
      console.log('❌ HASIL TEST 3: GAGAL!');
      passedAll = false;
    }

    console.log('\n' + '='.repeat(75));
    if (passedAll) {
      console.log('🎉 KESIMPULAN: SEMUA 3 SKENARIO KEAMANAN LOLOS DENGAN SEMPURNA!');
      console.log('   - Test 1 (Valid)    : 200 OK');
      console.log('   - Test 2 (Tampered) : 401 Unauthorized');
      console.log('   - Test 3 (Missing)  : 400 Bad Request');
    } else {
      console.log('⚠️ TERDAPAT SKENARIO YANG GAGAL.');
    }
    console.log('='.repeat(75));

  } finally {
    server.close();
  }
}

runSecurityFlowTests().catch(err => {
  console.error('Fatal error during test:', err);
  process.exit(1);
});
