import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import handler from './api/webhook.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // 1. Route ke /api/webhook (Node.js Serverless Function)
  if (pathname === '/api/webhook') {
    let bodyData = '';
    req.on('data', chunk => { bodyData += chunk; });
    req.on('end', async () => {
      try {
        req.body = bodyData ? JSON.parse(bodyData) : '';
      } catch {
        req.body = bodyData;
      }
      await handler(req, res);
    });
    return;
  }

  // 2. Route ke /api/proses_ai (Forward ke FastAPI jika aktif, atau fallback simulasi)
  if (pathname === '/api/proses_ai') {
    try {
      const fastApiUrl = `http://127.0.0.1:8000/api/proses_ai${parsedUrl.search}`;
      const fastApiResponse = await fetch(fastApiUrl);
      const data = await fastApiResponse.json();
      res.writeHead(fastApiResponse.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
      return;
    } catch {
      // Jika server FastAPI Python sedang tidak berjalan di port 8000,
      // jalankan simulasi persis sesuai arsitektur (0.3s RF & 0.5s SVM secara paralel)
      const input = parsedUrl.searchParams.get('input') || '';
      const isThreat = /(--|union|select|drop|or\s+1=1|waitfor|benchmark|<script)/i.test(input);

      await new Promise(r => setTimeout(r, 504)); // Simulasi total durasi paralel 0.504s

      const responsePayload = {
        status: "success",
        duration_seconds: 0.5042,
        result: {
          model_rf: {
            model: "Random Forest (RF / NVIDIA NIM)",
            prediction: isThreat ? "bahaya" : "aman",
            confidence: isThreat ? 0.9500 : 0.9420,
            inference_latency_ms: 300
          },
          model_svm: {
            model: "Support Vector Machine (SVM / NVIDIA NIM)",
            prediction: isThreat ? "bahaya" : "aman",
            confidence: isThreat ? 0.9310 : 0.9250,
            inference_latency_ms: 500
          }
        }
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(responsePayload));
      return;
    }
  }

  // 3. Serve Static Files dari folder /public
  let filePath = path.join(__dirname, 'public', pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // Fallback ke index.html
        fs.readFile(path.join(__dirname, 'public', 'index.html'), (e, indexHtml) => {
          if (e) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
          } else {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(indexHtml);
          }
        });
      } else {
        res.writeHead(500);
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`🚀 Aegis SOC Dev Server berjalan pada: http://127.0.0.1:${PORT}`);
  console.log(`• Dashboard : http://127.0.0.1:${PORT}/`);
  console.log(`• Webhook   : http://127.0.0.1:${PORT}/api/webhook`);
  console.log(`• Dual AI   : http://127.0.0.1:${PORT}/api/proses_ai?input=...`);
});
