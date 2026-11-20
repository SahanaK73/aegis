import requests
import json

base = "http://localhost:8000/api/v1/events"
token = "dev-token-tenant-a"

print("--- Testing Failure Case 1: SHA-256 mismatch ---")
payload = json.dumps({"collector_id": "c1", "event_id": "e1", "event_type": "metric"})
res = requests.post(
    base,
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Content-SHA256": "bad-hash-000000000000000000000000000000000000000000000000000000000000"
    },
    data=payload
)
print("Status:", res.status_code, "Body:", res.text)

print("\n--- Testing Failure Case 2: Allow-list rejection (unknown fields) ---")
res2 = requests.post(
    base,
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    },
    json={"unauthorized_field": "secret_data", "passwords": "123"}
)
print("Status:", res2.status_code, "Body:", res2.text)

print("\n--- Testing Failure Case 3: Unauthorized tenant token ---")
res3 = requests.post(
    base,
    headers={
        "Authorization": "Bearer invalid-unauthorized-token",
        "Content-Type": "application/json",
    },
    json={"collector_id": "c1"}
)
print("Status:", res3.status_code, "Body:", res3.text)
