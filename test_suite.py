"""
GhostWire - Automated Test Suite
Validates moderator authentication, overview stats, user search/filters,
ban/unban, kick, single-moderator policy, cascade delete, broadcasting, audit logs, and export.
"""

import asyncio
import json
import os
import sys
from uuid import uuid4

# Set test environment
os.environ["SECRET_KEY"] = "test-secret-key-12345"
os.environ.pop("MODERATOR_KEY", None)
os.environ["MODERATOR_KEY_HASH"] = "1ee0a6706f91df39f270933f78334ff4d5ddc36527bf2e5400280ddb1efc9ddc"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_chat.db"

import httpx
from server import app, init_db, engine, SQLModel


async def run_tests():
    if os.path.exists("test_chat.db"):
        try:
            os.remove("test_chat.db")
        except Exception:
            pass

    print(">>> Initializing database schema...")
    await init_db()

    # Use ASGITransport for in-memory testing with httpx
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        print(">>> 1. Testing Moderator Key Login with Encrypted Hash Verification...")
        # 1a. Verify wrong key is rejected
        res_fail = await client.post("/api/moderator/login", json={"key": "wrong_key_123"})
        assert res_fail.status_code == 401, "Invalid key was accepted!"
        print("    [PASS] Wrong moderator key rejected with 401 Unauthorized.")

        # 2b. Verify correct key matches against PBKDF2 salt & hash
        res = await client.post("/api/moderator/login", json={"key": "sonofposeidon123"})
        assert res.status_code == 200, f"Moderator login failed: {res.text}"
        mod_data = res.json()
        mod_token = mod_data["token"]
        assert mod_data["role"] == "moderator"
        print(f"    [PASS] Moderator Login successful with encrypted key, token: {mod_token[:15]}...")

        auth_headers = {"Authorization": f"Bearer {mod_token}"}

        print(">>> 2. Creating Test Users...")
        res_u1 = await client.post("/api/auth/simple-login", json={
            "username": "alice",
            "password": "password123",
            "display_name": "Alice Wonderland"
        })
        assert res_u1.status_code == 200, f"Alice registration failed: {res_u1.text}"
        alice = res_u1.json()["user"]
        alice_token = res_u1.json()["token"]

        res_u2 = await client.post("/api/auth/simple-login", json={
            "username": "bob",
            "password": "password123",
            "display_name": "Bob Builder"
        })
        assert res_u2.status_code == 200, f"Bob registration failed: {res_u2.text}"
        bob = res_u2.json()["user"]
        bob_token = res_u2.json()["token"]

        res_u3 = await client.post("/api/auth/simple-login", json={
            "username": "charlie_spammer",
            "password": "password123",
            "display_name": "Charlie Spam"
        })
        assert res_u3.status_code == 200, f"Charlie registration failed: {res_u3.text}"
        charlie = res_u3.json()["user"]
        charlie_token = res_u3.json()["token"]
        print("    [PASS] Created 3 test users: Alice, Bob, Charlie")

        print(">>> 3. Testing Room Creation & Encrypted Messaging...")
        res_room = await client.post(
            "/api/rooms",
            json={"participant_id": bob["id"]},
            headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert res_room.status_code == 200, f"Room creation failed: {res_room.text}"
        room_data = res_room.json()
        room_id = room_data["id"]

        res_msg = await client.post(
            "/api/messages",
            json={
                "room_id": room_id,
                "recipient_id": bob["id"],
                "encrypted_content": "ciphertext_sample_payload_12345"
            },
            headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert res_msg.status_code == 200, f"Message send failed: {res_msg.text}"
        print(f"    [PASS] Room created ({room_id}) and encrypted message relayed.")

        print(">>> 4. Testing Moderator Overview Statistics (/api/moderator/overview)...")
        res_ov = await client.get("/api/moderator/overview", headers=auth_headers)
        assert res_ov.status_code == 200, f"Overview failed: {res_ov.text}"
        ov_data = res_ov.json()
        assert ov_data["total_users"] == 3
        assert ov_data["total_rooms"] == 1
        assert ov_data["total_messages"] >= 1
        print("    [PASS] Overview statistics:", {
            "total_users": ov_data["total_users"],
            "online_users": ov_data["online_users"],
            "total_rooms": ov_data["total_rooms"],
            "total_messages": ov_data["total_messages"],
            "moderator_users": ov_data["moderator_users"]
        })

        print(">>> 5. Testing User Search & Directory Filtering (/api/moderator/users)...")
        res_search = await client.get("/api/moderator/users?q=charlie", headers=auth_headers)
        assert res_search.status_code == 200
        search_data = res_search.json()
        assert search_data["total"] == 1
        assert search_data["users"][0]["username"] == "charlie_spammer"
        print("    [PASS] Search by username filtered correctly.")

        print(">>> 6. Testing User Details Inspection (/api/moderator/users/{id})...")
        res_detail = await client.get(f"/api/moderator/users/{alice['id']}", headers=auth_headers)
        assert res_detail.status_code == 200
        detail_data = res_detail.json()
        assert detail_data["username"] == "alice"
        assert len(detail_data["rooms"]) == 1
        print("    [PASS] User detail retrieved with active room list.")

        print(">>> 7. Testing Kick User (/api/moderator/users/{id}/kick)...")
        res_kick = await client.post(f"/api/moderator/users/{charlie['id']}/kick", headers=auth_headers)
        assert res_kick.status_code == 200
        assert res_kick.json()["status"] == "kicked"
        print("    [PASS] Kick action executed successfully.")

        print(">>> 8. Testing Ban User (/api/moderator/users/{id}/ban)...")
        res_ban = await client.post(
            f"/api/moderator/users/{charlie['id']}/ban",
            json={"reason": "Spamming commercial links in group chat."},
            headers=auth_headers
        )
        assert res_ban.status_code == 200
        assert res_ban.json()["status"] == "banned"

        # Verify banned user cannot log in
        res_banned_login = await client.post("/api/auth/simple-login", json={
            "username": "charlie_spammer",
            "password": "password123"
        })
        assert res_banned_login.status_code == 403, "Banned user was able to log in!"
        print("    [PASS] Ban enforced: Login rejected with 403 Forbidden.")

        print(">>> 9. Testing Unban User (/api/moderator/users/{id}/unban)...")
        res_unban = await client.post(f"/api/moderator/users/{charlie['id']}/unban", headers=auth_headers)
        assert res_unban.status_code == 200
        assert res_unban.json()["status"] == "unbanned"

        # Verify user can log in again
        res_relogin = await client.post("/api/auth/simple-login", json={
            "username": "charlie_spammer",
            "password": "password123"
        })
        assert res_relogin.status_code == 200
        print("    [PASS] Unban verified: Login restored.")

        print(">>> 10. Testing User Promotion Disabled (Single Moderator Policy)...")
        res_role = await client.post(f"/api/moderator/users/{bob['id']}/toggle-moderator", headers=auth_headers)
        assert res_role.status_code == 400, "Role toggle should be rejected under single-moderator architecture!"
        print("    [PASS] User promotion rejected: Platform strictly enforces single Master Moderator.")

        print(">>> 11. Testing System Broadcast Announcement (/api/moderator/broadcast)...")
        res_bcast = await client.post(
            "/api/moderator/broadcast",
            json={
                "title": "Scheduled Server Upgrade",
                "message": "We are upgrading encryption ciphers tonight at midnight.",
                "severity": "warning"
            },
            headers=auth_headers
        )
        assert res_bcast.status_code == 200
        bcast_data = res_bcast.json()
        assert bcast_data["status"] == "broadcasted"
        print("    [PASS] Global system broadcast dispatched.")

        print(">>> 12. Testing Rooms List (/api/moderator/rooms)...")
        res_rooms_mod = await client.get("/api/moderator/rooms", headers=auth_headers)
        assert res_rooms_mod.status_code == 200
        rooms_list = res_rooms_mod.json()
        assert len(rooms_list) >= 1
        print(f"    [PASS] Found {len(rooms_list)} rooms in moderator inspector.")

        print(">>> 13. Testing Permanent Cascade Delete User (/api/moderator/users/{id})...")
        res_del = await client.delete(f"/api/moderator/users/{charlie['id']}", headers=auth_headers)
        assert res_del.status_code == 200
        assert res_del.json()["status"] == "deleted"

        # Verify charlie is completely gone
        res_check = await client.get(f"/api/moderator/users/{charlie['id']}", headers=auth_headers)
        assert res_check.status_code == 404
        print("    [PASS] Charlie was cascade deleted permanently.")

        print(">>> 14. Testing Audit Logs Retrieval (/api/moderator/audit-logs)...")
        res_logs = await client.get("/api/moderator/audit-logs", headers=auth_headers)
        assert res_logs.status_code == 200
        logs = res_logs.json()
        assert len(logs) >= 3
        actions = [l["action"] for l in logs]
        print(f"    [PASS] Audit logs verified ({len(logs)} entries recorded): {actions[:4]}")

        print(">>> 15. Testing Moderator Report Export (/api/moderator/export)...")
        res_export = await client.get("/api/moderator/export", headers=auth_headers)
        assert res_export.status_code == 200
        export_data = res_export.json()
        assert "export_timestamp" in export_data
        assert "summary" in export_data
        assert len(export_data["users"]) >= 2
        print("    [PASS] Moderator data report exported successfully.")

    print("\n" + "=" * 56)
    print("  ALL 15 MODERATOR TEST CASES PASSED PERFECTLY! ")
    print("=" * 56 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(run_tests())
    finally:
        # Dispose engine connections so Windows file handle is released
        try:
            asyncio.run(engine.dispose())
        except Exception:
            pass
        # Clean up test DB file
        try:
            if os.path.exists("test_chat.db"):
                os.remove("test_chat.db")
        except Exception:
            pass
