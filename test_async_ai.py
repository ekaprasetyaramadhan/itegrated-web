import asyncio
import time
import sys
import os

# Set UTF-8 encoding for Windows terminals
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Menambahkan root folder ke sys.path agar bisa import dari api
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api.proses_ai import predict_random_forest, predict_svm

async def run_sequential_test(query: str):
    """Pengujian secara sekuensial (sinkron/berurutan) tanpa asyncio.gather"""
    start_time = time.time()
    res_rf = await predict_random_forest(query)
    res_svm = await predict_svm(query)
    total_time = time.time() - start_time
    return res_rf, res_svm, total_time

async def run_parallel_test(query: str):
    """Pengujian secara paralel menggunakan asyncio.gather()"""
    start_time = time.time()
    res_rf, res_svm = await asyncio.gather(
        predict_random_forest(query),
        predict_svm(query)
    )
    total_time = time.time() - start_time
    return res_rf, res_svm, total_time

async def main():
    print("=" * 70)
    print("🛡️  PENGUJIAN KONKURENSI ASYNCHRONOUS DUAL AI (NVIDIA NIM)")
    print("=" * 70)
    
    test_query_safe = "SELECT id, username, created_at FROM public.users WHERE id = 42;"
    test_query_threat = "' UNION SELECT credit_card_num, cvv FROM customers WHERE 1=1 --"
    
    # 1. Uji Paralel dengan query ancaman
    print(f"\n[TEST 1] Eksekusi Paralel (asyncio.gather) - SQL Injection Threat:")
    print(f"Input: \"{test_query_threat}\"")
    
    rf_res, svm_res, parallel_time = await run_parallel_test(test_query_threat)
    
    print("-" * 70)
    print(f"  Model A (RF)  : {rf_res['model']} -> Prediksi: [{rf_res['prediction'].upper()}] (Conf: {rf_res['confidence'] * 100:.1f}%) [Delay: ~0.3s]")
    print(f"  Model B (SVM) : {svm_res['model']} -> Prediksi: [{svm_res['prediction'].upper()}] (Conf: {svm_res['confidence'] * 100:.1f}%) [Delay: ~0.5s]")
    print("-" * 70)
    print(f"⏱️  TOTAL WAKTU PARALEL (asyncio.gather) : {parallel_time:.4f} detik")
    print(f"    Target Waktu Maksimal                : ~0.50 detik (waktu model terlama)")
    
    # 2. Uji Perbandingan Sekuensial vs Paralel
    print(f"\n[TEST 2] Perbandingan Benchmark: Sekuensial vs Paralel:")
    _, _, seq_time = await run_sequential_test(test_query_safe)
    
    print(f"  • Waktu Eksekusi Sekuensial (0.3s + 0.5s) : {seq_time:.4f} detik")
    print(f"  • Waktu Eksekusi Paralel    (asyncio.gather): {parallel_time:.4f} detik")
    time_saved = seq_time - parallel_time
    efficiency = (time_saved / seq_time) * 100
    print(f"  • Penghematan Waktu (Latency Reduction) : {time_saved:.4f} detik ({efficiency:.1f}% lebih cepat)")
    
    # 3. Validasi Assertion
    print("-" * 70)
    # Toleransi rentang eksekusi paralel harus berada di kisaran ~0.50s - 0.58s (jauh di bawah 0.8s)
    is_concurrent = (parallel_time < 0.65) and (parallel_time >= 0.48)
    if is_concurrent:
        print("✅ PEMBUKTIAN SUKSES: Waktu total ≈ 0.5 detik (mengikuti durasi model terlama / SVM).")
        print("   Bukan 0.8 detik (sekuensial). Konkurensi non-blocking terbukti aktif sempurna!")
    else:
        print(f"⚠️ Catatan: Waktu tercatat {parallel_time:.4f} detik.")

    print("=" * 70)

if __name__ == "__main__":
    asyncio.run(main())
