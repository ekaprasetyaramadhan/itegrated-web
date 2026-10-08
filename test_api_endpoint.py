import asyncio
import sys
import json

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from api.proses_ai import proses_ai

async def test_api_direct():
    print("Testing proses_ai(input='SELECT * FROM users WHERE id = 1') ...")
    data = await proses_ai(input="SELECT * FROM users WHERE id = 1")
    print(json.dumps(data, indent=2))
    assert data["status"] == "success"
    assert "duration_seconds" in data
    assert 0.45 <= data["duration_seconds"] <= 0.65
    assert "model_rf" in data["result"]
    assert "model_svm" in data["result"]
    assert data["result"]["model_rf"]["prediction"] in ["aman", "bahaya"]
    assert 0.0 <= data["result"]["model_rf"]["confidence"] <= 1.0
    print("\n✅ API Endpoint schema & logic verified successfully!")

if __name__ == "__main__":
    asyncio.run(test_api_direct())
