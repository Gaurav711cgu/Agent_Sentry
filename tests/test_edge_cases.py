import pytest
from app.gateway import process_request

def test_empty_request_payload():
    result = process_request({})
    assert result.get("status") == "error"

def test_malformed_sql_injection():
    payload = {"query": "SELECT * FROM users WHERE id = 1'; DROP TABLE users;--"}
    result = process_request(payload)
    assert result.get("flagged") is True

def test_oversized_payload_rejection():
    payload = {"query": "A" * 100000}
    result = process_request(payload)
    assert result.get("status") in ["error", "rejected"]
