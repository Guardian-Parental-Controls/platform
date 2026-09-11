"""Tests for agent connection helpers and alert payload normalization."""

# pylint: disable=unused-argument

import hashlib
import hmac
import json
from queue import Empty
from unittest.mock import patch

import pytest

from src.agent.helper import AgentClient, AgentConnectionManager
from src.agent.helper import (
    agent_versions_compatible,
    normalize_agent_alert_payload,
    parse_agent_alert_timestamp,
)
from src.models import AgentDevice

class DummyWS:
    """Minimal websocket double that auto-responds to RPC-style requests."""

    def __init__(self):
        self.sent_messages = []
        self.closed = False
        
    def send(self, message):
        self.sent_messages.append(message)
        # Parse and auto-respond to keep sync commands fast
        try:
            payload = json.loads(message)
            correlation_id = payload.get("correlation_id")
            if correlation_id:
                # Route response immediately
                AgentConnectionManager.route_response(correlation_id, {
                    "success": True,
                    "message": "Mocked Command Success",
                    "data": {"stdout": "stdout_val"}
                })
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    def close(self):
        self.closed = True


def test_agent_versions_compatible_accepts_any_agent_on_dev_server():
    assert agent_versions_compatible('v1.0.0-dev', 'v0.1.0-android', 'android') is True
    assert agent_versions_compatible('v1.0.0-dev', None, 'linux') is True


@patch('src.agent.releases.agent_version_status', return_value=(True, False))
def test_agent_versions_compatible_uses_feed_status(mock_status):
    assert agent_versions_compatible('1.0.0', '1.1.0', 'linux') is True
    mock_status.assert_called_once_with('linux', '1.1.0', '1.0.0')


@patch('src.agent.releases.agent_version_status', return_value=(True, True))
def test_agent_patch_update_recommended_uses_feed_status(mock_status):
    from src.agent.helper import agent_patch_update_recommended

    assert agent_patch_update_recommended('1.0.0', '1.0.0', 'windows') is True
    mock_status.assert_called_once_with('windows', '1.0.0', '1.0.0')


def test_connection_registry():
    ws = DummyWS()
    system_id = "test-system-uuid"
    remote_ip = "10.0.0.5"

    # Register active
    AgentConnectionManager.register(system_id, ws, remote_ip)
    assert AgentConnectionManager.is_online(system_id)
    assert AgentConnectionManager.get_connection(system_id) == ws
    assert AgentConnectionManager.get_ip(system_id) == remote_ip

    # Register pending
    ws_pending = DummyWS()
    AgentConnectionManager.register_pending(system_id, ws_pending)
    assert AgentConnectionManager.get_pending_connection(system_id) == ws_pending

    # Unregister pending
    AgentConnectionManager.unregister_pending(system_id)
    assert AgentConnectionManager.get_pending_connection(system_id) is None

    # Unregister active
    AgentConnectionManager.unregister(system_id)
    assert not AgentConnectionManager.is_online(system_id)
    assert AgentConnectionManager.get_connection(system_id) is None
    assert AgentConnectionManager.get_ip(system_id) == "Offline"

def test_route_response():
    # If correlation_id does not exist
    assert not AgentConnectionManager.route_response("nonexistent-cid", {})

def test_send_command_sync_failures(db_session):
    # Case: system_id is None or empty
    success, msg, _data = AgentConnectionManager.send_command_sync(None, "action", "john")
    assert not success
    assert "No system ID" in msg

    # Case: agent is offline
    success, msg, _data = AgentConnectionManager.send_command_sync("offline-sys", "action", "john")
    assert not success
    assert "is offline" in msg

def test_send_command_sync_success():
    ws = DummyWS()
    system_id = "online-sys"
    AgentConnectionManager.register(system_id, ws, "127.0.0.1")

    # Send command (auto-responded by DummyWS)
    success, msg, data = AgentConnectionManager.send_command_sync(system_id, "test_action", "john")
    assert success
    assert msg == "Mocked Command Success"
    assert data["stdout"] == "stdout_val"

    AgentConnectionManager.unregister(system_id)

def test_send_command_sync_socket_error():
    class ErrorWS:
        def send(self, message):
            raise RuntimeError("Websocket socket send error")
            
    system_id = "error-sys"
    AgentConnectionManager.register(system_id, ErrorWS(), "127.0.0.1")

    success, msg, _data = AgentConnectionManager.send_command_sync(system_id, "action", "john")
    assert not success
    assert "Failed to send command" in msg

    AgentConnectionManager.unregister(system_id)

def test_verify_signature(db_session):
    system_id = "device-uuid"
    challenge = "challenge-string"
    token = "device-secure-pairing-token"

    # Case: device not in DB
    assert not AgentConnectionManager.verify_signature(challenge, system_id, "sig")

    # Add device to DB but unapproved
    device = AgentDevice(system_id=system_id, secure_token=token, status="pending")
    db_session.add(device)
    db_session.commit()

    assert not AgentConnectionManager.verify_signature(challenge, system_id, "sig")

    # Approve device
    device.status = "approved"
    db_session.commit()

    # Calculate valid signature
    token_bytes = token.encode('utf-8')
    msg = (challenge + system_id).encode('utf-8')
    valid_sig = hmac.new(token_bytes, msg, hashlib.sha256).hexdigest()

    assert AgentConnectionManager.verify_signature(challenge, system_id, valid_sig)
    assert not AgentConnectionManager.verify_signature(challenge, system_id, "invalid-sig")
    
    # Exception handling
    # Cause a TypeError by passing None
    assert not AgentConnectionManager.verify_signature(None, system_id, None)

def test_agent_client(db_session):
    ws = DummyWS()
    system_id = "agent-client-sys"
    AgentConnectionManager.register(system_id, ws, "127.0.0.1")

    client = AgentClient(system_id=system_id)

    # Test validate_user
    # When agent helper fails, validate_user should return False
    # Let's temporarily unregister it to cause failure
    AgentConnectionManager.unregister(system_id)
    is_valid, msg, config = client.validate_user("john")
    assert not is_valid
    assert "offline" in msg

    # Re-register
    AgentConnectionManager.register(system_id, ws, "127.0.0.1")

    config_output = {
        "TIME_SPENT_DAY": 1200,
        "LIMIT": 3600,
        "ENABLED": True,
        "LIST": ["a", "b", "c"],
        "LINUX_UID": 1000,
    }
    # Customize DummyWS for this test
    class CustomWS:
        def __init__(self):
            self.payloads = []

        def send(self, message):
            self.payloads.append(json.loads(message))
            payload = json.loads(message)
            correlation_id = payload.get("correlation_id")
            action = payload.get("action")
            data = {"config": config_output}
            if action == "get_domain_policy_state":
                data = {"source_revisions": {"1": "rev-1"}}
            AgentConnectionManager.route_response(correlation_id, {
                "success": True,
                "message": "Success",
                "data": data,
            })
    
    capture_ws = CustomWS()
    AgentConnectionManager.register(system_id, capture_ws, "127.0.0.1")
    is_valid, msg, config = client.validate_user("john")
    assert is_valid
    assert config["TIME_SPENT_DAY"] == 1200
    assert config["LIMIT"] == 3600
    assert config["ENABLED"] is True
    assert config["LIST"] == ["a", "b", "c"]
    assert config["LINUX_UID"] == 1000

    # Test modify_time_left
    success, msg = client.modify_time_left("john", "+", 60)
    assert success

    # Test set_weekly_time_limits
    success, msg = client.set_weekly_time_limits("john", {"monday": 2.0})
    assert success

    # Test set_allowed_hours
    class MockInterval:
        def __init__(self, is_enabled, is_valid, format_val, start_minutes=0, end_minutes=0, sort_order=0):
            self.is_enabled = is_enabled
            self.is_valid = is_valid
            self.format_val = format_val
            self.start_hour = start_minutes // 60
            self.start_minute = start_minutes % 60
            self.end_hour = end_minutes // 60
            self.end_minute = end_minutes % 60
            self.sort_order = sort_order
            
        def is_valid_interval(self):
            return self.is_valid
            
        def to_timekpr_format(self):
            return self.format_val

    intervals = {
        1: [
            MockInterval(True, True, ["9", "10"], start_minutes=540, end_minutes=660, sort_order=0),
            MockInterval(True, True, ["15", "16", "17[0-30]"], start_minutes=900, end_minutes=1050, sort_order=1),
        ],
        2: [MockInterval(True, False, None)],
        3: [MockInterval(False, True, None)]
    }
    success, _msg = client.set_allowed_hours("john", intervals)
    assert success

    allowed_hours_payload = next(
        payload for payload in capture_ws.payloads
        if payload.get("action") == "set_allowed_hours"
    )
    day_one = allowed_hours_payload["args"]["intervals"]["1"]
    day_two = allowed_hours_payload["args"]["intervals"]["2"]
    assert day_one["9"] == {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}
    assert day_one["10"] == {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}
    assert day_one["15"] == {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}
    assert day_one["16"] == {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}
    assert day_one["17"] == {"STARTMIN": 0, "ENDMIN": 30, "UACC": 0}
    assert len(day_two) == 24
    assert day_two["0"] == {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}
    assert day_two["23"] == {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}

    success, msg = client.sync_domain_policy({
        "sources": {"1": ["example.com", "dns.google"]},
        "policies": {"1000": {"linux_username": "john", "source_ids": ["1"]}},
    })
    assert success

    domain_policy_payload = next(
        payload for payload in capture_ws.payloads
        if payload.get("action") == "sync_domain_policy"
    )
    assert domain_policy_payload["args"]["sources"]["1"] == ["example.com", "dns.google"]
    assert domain_policy_payload["args"]["policies"]["1000"]["linux_username"] == "john"
    assert domain_policy_payload["username"] == ""

    success, msg, state = client.get_domain_policy_state()
    assert success
    assert state["source_revisions"] == {"1": "rev-1"}

    success, msg = client.begin_domain_policy_sync("sync-1")
    assert success
    success, msg = client.delete_domain_policy_sources("sync-1", ["2"])
    assert success
    success, msg = client.send_domain_policy_chunk("sync-1", "1", "rev-2", ["example.com"])
    assert success
    success, msg = client.update_domain_policy_manifest("sync-1", {
        "1000": {"linux_username": "john", "source_ids": ["1"]},
    })
    assert success
    success, msg = client.finalize_domain_policy_sync("sync-1")
    assert success
    success, msg = client.abort_domain_policy_sync("sync-1")
    assert success

    incremental_actions = [
        payload["action"]
        for payload in capture_ws.payloads
        if payload.get("action") in {
            "get_domain_policy_state",
            "begin_domain_policy_sync",
            "delete_domain_policy_sources",
            "sync_domain_policy_chunk",
            "update_domain_policy_manifest",
            "finalize_domain_policy_sync",
            "abort_domain_policy_sync",
        }
    ]
    assert incremental_actions == [
        "get_domain_policy_state",
        "begin_domain_policy_sync",
        "delete_domain_policy_sources",
        "sync_domain_policy_chunk",
        "update_domain_policy_manifest",
        "finalize_domain_policy_sync",
        "abort_domain_policy_sync",
    ]

    AgentConnectionManager.unregister(system_id)

def test_send_command_sync_timeout():
    ws = DummyWS()
    system_id = "timeout-sys"
    AgentConnectionManager.register(system_id, ws, "127.0.0.1")
    
    with patch('queue.Queue.get', side_effect=Empty):
        success, msg, _data = AgentConnectionManager.send_command_sync(
            system_id,
            "action",
            "john",
            timeout=0.01,
        )
        assert not success
        assert "timed out" in msg

    AgentConnectionManager.unregister(system_id)

def test_agent_client_parser_missing_lines():
    system_id = "parser-sys"
    client = AgentClient(system_id=system_id)

    stdout_output = "DIGITS: 1;2;3\nBOOL_F: false\n"
    class ParserWS:
        def send(self, message):
            payload = json.loads(message)
            correlation_id = payload.get("correlation_id")
            AgentConnectionManager.route_response(correlation_id, {
                "success": True,
                "message": "Success",
                "data": {"stdout": stdout_output}
            })
    AgentConnectionManager.register(system_id, ParserWS(), "127.0.0.1")
    is_valid, _msg, config = client.validate_user("john")
    assert is_valid
    assert config["DIGITS"] == [1, 2, 3]
    assert config["BOOL_F"] is False

    class MockInterval:
        def __init__(self, is_enabled, is_valid, format_val, start_minutes=0, end_minutes=0, sort_order=0):
            self.is_enabled = is_enabled
            self.is_valid = is_valid
            self.format_val = format_val
            self.start_hour = start_minutes // 60
            self.start_minute = start_minutes % 60
            self.end_hour = end_minutes // 60
            self.end_minute = end_minutes % 60
            self.sort_order = sort_order
            
        def is_valid_interval(self):
            return self.is_valid
            
        def to_timekpr_format(self):
            return self.format_val

    intervals = {
        1: MockInterval(True, True, []),
    }
    success, _msg = client.set_allowed_hours("john", intervals)
    assert success


def test_agent_client_rejects_disjoint_same_hour_intervals():
    client = AgentClient(system_id="unused")

    class MockInterval:
        def __init__(self, start_hour, start_minute, end_hour, end_minute):
            self.is_enabled = True
            self.start_hour = start_hour
            self.start_minute = start_minute
            self.end_hour = end_hour
            self.end_minute = end_minute
            self.sort_order = 0

        def is_valid_interval(self):
            return True

    intervals = {
        1: [
            MockInterval(9, 0, 9, 15),
            MockInterval(9, 30, 9, 45),
        ]
    }

    success, msg = client.set_allowed_hours("john", intervals)
    assert not success
    assert "cannot represent" in msg


def test_parse_agent_alert_timestamp():
    parsed = parse_agent_alert_timestamp("2026-05-25T21:05:00Z")
    assert parsed.year == 2026
    assert parsed.month == 5
    assert parsed.day == 25

    with pytest.raises(ValueError):
        parse_agent_alert_timestamp("not-a-timestamp")


def test_normalize_agent_alert_payload():
    payload = normalize_agent_alert_payload("sys-1", {
        "type": "alert_event",
        "event_type": "user_signed_in",
        "occurred_at": "2026-05-25T21:05:00Z",
        "linux_username": "alice",
        "details": {"session_id": "c3"},
    })

    assert payload["system_id"] == "sys-1"
    assert payload["event_type"] == "user_signed_in"
    assert payload["linux_username"] == "alice"
    assert payload["details"]["session_id"] == "c3"
    assert '"event_type": "user_signed_in"' in payload["payload_json"]

    with pytest.raises(ValueError):
        normalize_agent_alert_payload("sys-1", {"event_type": "nope", "occurred_at": "2026-05-25T21:05:00Z"})

    with pytest.raises(ValueError):
        normalize_agent_alert_payload("sys-1", {"event_type": "system_startup", "occurred_at": "2026-05-25T21:05:00Z", "details": []})


def test_clock_tamper_alert_type():
    payload = normalize_agent_alert_payload("sys-1", {
        "type": "alert_event",
        "event_type": "clock_tamper",
        "occurred_at": "2026-06-06T21:00:00Z",
        "linux_username": "alice",
        "details": {
            "skew_seconds": 420,
            "detection_source": "both",
        },
    })
    assert payload["event_type"] == "clock_tamper"
    assert payload["details"]["skew_seconds"] == 420


def test_boot_config_tamper_alert_type():
    payload = normalize_agent_alert_payload("sys-1", {
        "type": "alert_event",
        "event_type": "boot_config_tamper",
        "occurred_at": "2026-06-06T21:00:00Z",
        "linux_username": "system",
        "details": {
            "source": "bcdedit_enum",
            "entry_id": "{default}",
            "detected_flags": ["safeboot:minimal"],
        },
    })
    assert payload["event_type"] == "boot_config_tamper"
    assert payload["details"]["source"] == "bcdedit_enum"


def test_terminal_command_alert_type():
    payload = normalize_agent_alert_payload("sys-1", {
        "type": "alert_event",
        "event_type": "terminal_command",
        "occurred_at": "2026-06-06T21:00:00Z",
        "linux_username": "alice",
        "details": {
            "cmd": "git status",
            "pwd": "/home/alice/project",
            "tty": "pts/1",
            "session_id": "test-session-uuid",
        },
    })
    assert payload["event_type"] == "terminal_command"
    assert payload["linux_username"] == "alice"
    assert payload["details"]["cmd"] == "git status"
