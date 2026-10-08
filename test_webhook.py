import hmac
import hashlib
import json
import time
import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Simulated Supabase webhook secret
SECRET = "super-secret-hmac-key-supabase-2026"

def generate_hmac_signature(payload_bytes: bytes, secret: str) -> str:
    """Menghitung HMAC-SHA256 signature sesuai standar Supabase/Webhooks"""
    return hmac.new(
        secret.encode('utf-8'),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

def verify_hmac_signature(payload_bytes: bytes, provided_sig: str, secret: str) -> bool:
    """Verifikasi tanda tangan HMAC-SHA256 dengan timing attack protection"""
    expected_sig = generate_hmac_signature(payload_bytes, secret)
    # Bersihkan prefix 'sha256=' jika disertakan
    clean_provided_sig = provided_sig.replace("sha256=", "")
    return hmac.compare_digest(expected_sig, clean_provided_sig)

def test_supabase_webhook_hmac():
    print("=" * 70)
    print("🔐 PENGUJIAN OTENTIKASI WEBHOOK SUPABASE (HMAC-SHA256)")
    print("=" * 70)

    # 1. Payload ancaman yang dikirim dari Supabase Database Trigger
    payload = {
        "type": "INSERT",
        "table": "security_audit_logs",
        "record": {
            "id": "sec-evt-99012",
            "timestamp": "2026-10-08T11:15:00Z",
            "user_id": "attacker-anon-session",
            "ip_address": "45.134.22.89",
            "query": "SELECT * FROM users WHERE username = 'admin' AND '1'='1' UNION SELECT credit_card, password_hash, 1 FROM secret_vault --"
        }
    }
    
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    # Generate signature otentik
    valid_signature = generate_hmac_signature(payload_bytes, SECRET)
    print(f"[+] Payload Ukuran     : {len(payload_bytes)} bytes")
    print(f"[+] Computed Signature : sha256={valid_signature}")
    
    # 2. Uji verifikasi signature valid
    is_valid = verify_hmac_signature(payload_bytes, valid_signature, SECRET)
    print(f"[+] Hasil Uji Signature Asli    : {'✅ TERVERIFIKASI (200 OK)' if is_valid else '❌ GAGAL'}")
    assert is_valid is True, "Signature yang sah harus lolos verifikasi!"

    # 3. Uji manipulasi payload (Tampering Attack Test)
    tampered_payload_bytes = payload_bytes.replace(b"45.134.22.89", b"127.0.0.1")
    is_tampered_valid = verify_hmac_signature(tampered_payload_bytes, valid_signature, SECRET)
    print(f"[+] Hasil Uji Payload Dimanipulasi: {'❌ DITOLAK (401 Unauthorized)' if not is_tampered_valid else '⚠️ BOCOR'}")
    assert is_tampered_valid is False, "Payload yang diubah paksa harus ditolak!"

    # 4. Uji signature palsu (Forged Signature Test)
    fake_sig = "a" * 64
    is_fake_valid = verify_hmac_signature(payload_bytes, fake_sig, SECRET)
    print(f"[+] Hasil Uji Signature Palsu   : {'❌ DITOLAK (401 Unauthorized)' if not is_fake_valid else '⚠️ BOCOR'}")
    assert is_fake_valid is False, "Signature palsu harus ditolak!"

    print("-" * 70)
    print("✅ SEMUA UJI INTEGRITAS HMAC-SHA256 BERHASIL!")
    print("   Webhook Supabase dipastikan aman dari spoofing dan tampering.")
    print("=" * 70)

if __name__ == "__main__":
    test_supabase_webhook_hmac()
