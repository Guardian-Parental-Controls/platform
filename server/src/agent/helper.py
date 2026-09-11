"""Helpers for managing agent connections and agent-facing commands."""

import hashlib
import hmac
import json
import logging
import os
import re
import time
import threading
import uuid
from datetime import datetime, timezone
from queue import Queue, Empty

from src.models import AgentDevice

logger = logging.getLogger(__name__)


def _parse_release_version_tuple(version: str) -> tuple[int, int, int] | None:
    """Parse major.minor.patch from a release version string."""
    normalized = (version or '').strip().lstrip('v')
    if not normalized:
        return None

    numeric_parts: list[int] = []
    for part in re.split(r'[.\-_+]', normalized):
        if not part:
            continue
        if not part.isdigit():
            break
        numeric_parts.append(int(part))

    if len(numeric_parts) < 2:
        return None
    while len(numeric_parts) < 3:
        numeric_parts.append(0)
    return numeric_parts[0], numeric_parts[1], numeric_parts[2]


def agent_versions_compatible(
    server_version: str,
    agent_version: str | None,
    platform: str | None = None,
) -> bool:
    """Return whether the feed still supports this platform agent."""
    from src.agent.releases import agent_version_status

    compatible, _update_recommended = agent_version_status(
        platform,
        agent_version,
        server_version,
    )
    return compatible


def agent_patch_update_recommended(
    server_version: str,
    agent_version: str | None,
    platform: str | None = None,
) -> bool:
    """Return whether the feed advertises a newer supported agent."""
    from src.agent.releases import agent_version_status

    _compatible, update_recommended = agent_version_status(
        platform,
        agent_version,
        server_version,
    )
    return update_recommended

# Optional registration token firewall for new dynamic pairings
REGISTRATION_TOKEN = os.environ.get('REGISTRATION_TOKEN')

ALLOWED_AGENT_ALERT_TYPES = {
    'system_startup',
    'system_sleep',
    'system_resume',
    'system_restart',
    'system_shutdown',
    'user_signed_in',
    'user_signed_out',
    'app_launched',
    'app_blocked',
    'app_usage',
    'access_requested',
    'terminal_command',
    'clock_tamper',
    'boot_config_tamper',
    'hardware_non_compliant',
    'dialogue_flag',
    'sentiment_breach',
    'ai_bypass_attempt',
}


def _coerce_alert_string(value, field_name, max_length, allow_empty=False):
    """Validate and normalize a string field from an agent alert payload."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field_name} must be a string')

    normalized = value.strip()
    if not normalized and not allow_empty:
        raise ValueError(f'{field_name} must not be empty')
    if len(normalized) > max_length:
        raise ValueError(f'{field_name} exceeds maximum length of {max_length}')
    return normalized


def parse_agent_alert_timestamp(value):
    """Parse an ISO-8601 alert timestamp into a naive UTC datetime."""
    if not isinstance(value, str):
        raise ValueError('occurred_at must be an ISO-8601 string')

    normalized = value.strip()
    if not normalized:
        raise ValueError('occurred_at must not be empty')

    if normalized.endswith('Z'):
        normalized = normalized[:-1] + '+00:00'

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError('occurred_at must be a valid ISO-8601 timestamp') from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed.replace(tzinfo=None)


def normalize_agent_alert_payload(system_id, payload):
    """Validate an incoming alert payload and serialize its canonical form."""
    if not isinstance(payload, dict):
        raise ValueError('alert payload must be an object')

    event_type = _coerce_alert_string(payload.get('event_type'), 'event_type', 64)
    if event_type not in ALLOWED_AGENT_ALERT_TYPES:
        raise ValueError(f'Unsupported event_type: {event_type}')

    linux_username = _coerce_alert_string(
        payload.get('linux_username'),
        'linux_username',
        80,
    )
    details = payload.get('details', {})
    if details is None:
        details = {}
    if not isinstance(details, dict):
        raise ValueError('details must be an object')

    occurred_at = parse_agent_alert_timestamp(payload.get('occurred_at'))
    normalized_payload = {
        'system_id': system_id,
        'event_type': event_type,
        'occurred_at': occurred_at.isoformat() + 'Z',
        'linux_username': linux_username,
        'details': details,
    }
    return {
        'system_id': system_id,
        'event_type': event_type,
        'occurred_at': occurred_at,
        'linux_username': linux_username,
        'details': details,
        'payload_json': json.dumps(normalized_payload, sort_keys=True),
    }

class AgentConnectionManagerMeta(type):
    """Expose registration-token state through the manager class."""

    @property
    def registration_token(cls):
        """Return the current registration token configured for the server."""
        return REGISTRATION_TOKEN

class AgentConnectionManager(metaclass=AgentConnectionManagerMeta):
    """Track live agent connections and coordinate synchronous requests."""

    _manager_lock = threading.Lock()
    _connection_write_locks = {}

    # Active connections (fully approved & authenticated): system_id -> ws_object
    active_connections = {}

    # Pending connections (unapproved devices): system_id -> ws_object
    pending_connections = {}

    # Dynamic IP mapping: system_id -> remote_ip
    active_ips = {}

    # Thread-safe pending requests: correlation_id -> Queue
    pending_requests = {}

    @classmethod
    def register(cls, system_id, ws, remote_ip):
        """Register an active WebSocket connection and snapshot its current IP"""
        with cls._manager_lock:
            cls.active_connections[system_id] = ws
            cls.active_ips[remote_ip] = system_id
            cls.active_connections[system_id + "_ip"] = remote_ip
            if system_id not in cls._connection_write_locks:
                cls._connection_write_locks[system_id] = threading.Lock()
        logger.info("Agent registered: %s from IP %s", system_id, remote_ip)
        from src.common.dashboard_events import notify_dashboard_changed
        notify_dashboard_changed('agent_online')

    @classmethod
    def unregister(cls, system_id):
        """Unregister an active connection"""
        with cls._manager_lock:
            if system_id in cls.active_connections:
                ip = cls.active_connections.get(system_id + "_ip")
                if ip in cls.active_ips:
                    del cls.active_ips[ip]
                if system_id + "_ip" in cls.active_connections:
                    del cls.active_connections[system_id + "_ip"]
                del cls.active_connections[system_id]
                cls._connection_write_locks.pop(system_id, None)
        logger.info("Agent unregistered: %s", system_id)
        from src.common.dashboard_events import notify_dashboard_changed
        notify_dashboard_changed('agent_offline')

    @classmethod
    def register_pending(cls, system_id, ws):
        """Register an active connection in a pending state"""
        with cls._manager_lock:
            cls.pending_connections[system_id] = ws
        logger.info("Agent registered in PENDING state: %s", system_id)

    @classmethod
    def unregister_pending(cls, system_id):
        """Unregister a pending connection"""
        with cls._manager_lock:
            if system_id in cls.pending_connections:
                del cls.pending_connections[system_id]
        logger.info("Agent PENDING connection removed: %s", system_id)

    @classmethod
    def get_pending_connection(cls, system_id):
        """Get the active pending connection for a system_id"""
        with cls._manager_lock:
            return cls.pending_connections.get(system_id)

    @classmethod
    def get_connection(cls, system_id):
        """Get the active WebSocket connection for a system_id"""
        with cls._manager_lock:
            return cls.active_connections.get(system_id)

    @classmethod
    def is_online(cls, system_id):
        """Check if a system_id is currently online"""
        with cls._manager_lock:
            if system_id in cls.active_connections:
                return True

        # Hook for cloud-managed Nintendo devices
        try:
            device = AgentDevice.query.get(system_id)
            if device and device.platform == 'nintendo':
                for mapping in device.user_mappings:
                    if mapping.last_config:
                        try:
                            stats = json.loads(mapping.last_config)
                            last_active_str = stats.get("last_playtime_change_at")
                            if last_active_str:
                                last_active = datetime.fromisoformat(last_active_str)
                                if last_active.tzinfo is None:
                                    last_active = last_active.replace(tzinfo=timezone.utc)
                                now = datetime.now(timezone.utc)
                                if (now - last_active).total_seconds() <= 600:  # 10 minutes
                                    return True
                        except Exception:
                            pass
        except Exception:
            pass
        return False

    @classmethod
    def get_online_system_ids(cls):
        """Return sorted online system IDs without internal IP shadow keys."""
        with cls._manager_lock:
            return sorted(
                system_id
                for system_id in cls.active_connections
                if not system_id.endswith("_ip")
            )

    @classmethod
    def get_ip(cls, system_id):
        """Get the last snapshotted IP address for a system_id"""
        with cls._manager_lock:
            return cls.active_connections.get(system_id + "_ip", "Offline")

    @classmethod
    def route_response(cls, correlation_id, response_data):
        """Route a response message from client back to the waiting thread"""
        with cls._manager_lock:
            response_queue = cls.pending_requests.get(correlation_id)
        if response_queue:
            response_queue.put(response_data)
            return True
        return False

    @classmethod
    def send_command_sync(cls, system_id, action, username, args=None, timeout=15, queue_if_offline=True):
        """
        Send a command to the client and wait synchronously for the response.
        Thread-safe and block-based.
        """
        if not system_id:
            return False, "No system ID associated with this user", None

        ws = cls.get_connection(system_id)
        if not ws:
            from src.agent.push import device_prefers_push, wake_android_for_command
            from src.models import AgentDevice

            device = AgentDevice.query.get(system_id)
            if device_prefers_push(device):
                wake_android_for_command(system_id, action)
                wait_seconds = max(timeout, 45)
                for _ in range(wait_seconds):
                    ws = cls.get_connection(system_id)
                    if ws:
                        break
                    time.sleep(1)
        if not ws:
            if queue_if_offline:
                from src.agent.pending_commands import QUEUEABLE_ACTIONS, queue_offline_command

                if action in QUEUEABLE_ACTIONS:
                    try:
                        queue_offline_command(system_id, action, username, args)
                    except ValueError as exc:
                        return False, str(exc), None
                    wake_android_for_command(system_id, action)
                    return (
                        True,
                        "Command queued for delivery when device reconnects",
                        {"queued": True},
                    )
            return False, f"Agent for system ID '{system_id}' is offline", None

        correlation_id = str(uuid.uuid4())
        response_queue = Queue()
        with cls._manager_lock:
            cls.pending_requests[correlation_id] = response_queue

        with cls._manager_lock:
            if system_id not in cls._connection_write_locks:
                cls._connection_write_locks[system_id] = threading.Lock()
            write_lock = cls._connection_write_locks[system_id]

        payload = {
            "type": "command_request",
            "correlation_id": correlation_id,
            "action": action,
            "username": username,
            "args": args or {}
        }

        try:
            with write_lock:
                ws.send(json.dumps(payload))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            with cls._manager_lock:
                cls.pending_requests.pop(correlation_id, None)
            return False, f"Failed to send command over WebSocket: {exc}", None

        try:
            # Wait for response in the queue (blocking)
            response_data = response_queue.get(timeout=timeout)
            success = response_data.get("success", False)
            message = response_data.get("message", "")
            data = response_data.get("data")
            return success, message, data
        except Empty:
            return False, f"Request timed out after {timeout} seconds", None
        finally:
            with cls._manager_lock:
                cls.pending_requests.pop(correlation_id, None)

    @classmethod
    def send_message(cls, system_id, payload):
        """
        Send a non-RPC JSON message to the connected agent.
        Returns: (success, message)
        """
        if not system_id:
            return False, "No system ID associated with this user"

        ws = cls.get_connection(system_id)
        if not ws:
            return False, f"Agent for system ID '{system_id}' is offline"

        with cls._manager_lock:
            if system_id not in cls._connection_write_locks:
                cls._connection_write_locks[system_id] = threading.Lock()
            write_lock = cls._connection_write_locks[system_id]

        try:
            with write_lock:
                ws.send(json.dumps(payload))
            return True, "Message sent"
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return False, f"Failed to send message over WebSocket: {exc}"

    @classmethod
    def verify_signature(cls, challenge, system_id, signature_hex):
        """Verify the HMAC-SHA256 signature of challenge + system_id using the device-specific token"""
        try:
            device = AgentDevice.query.get(system_id)
            if not device or not device.secure_token:
                logger.warning(
                    "Signature verification rejected: Device %s missing token",
                    system_id,
                )
                return False

            is_approved = device.status == 'approved'
            pending_reset = bool(getattr(device, 'pending_factory_reset', False))
            is_android = (device.platform or '').strip().lower() == 'android'
            if not is_approved and not (pending_reset and is_android):
                logger.warning(
                    "Signature verification rejected: Device %s not approved or missing token",
                    system_id,
                )
                return False

            token_bytes = device.secure_token.encode('utf-8')
            msg = (challenge + system_id).encode('utf-8')
            expected = hmac.new(token_bytes, msg, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        except (
            AttributeError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            logger.error("Error during signature verification: %s", exc)
            return False

class AgentClient:
    """Client wrapper for issuing commands to a connected agent."""

    def __init__(self, system_id):
        self.system_id = system_id

    def _parse_timekpr_output(self, output):
        """Parse the legacy CLI output format into a dictionary"""
        config_dict = {}

        # Regular expression to match key-value pairs
        pattern = r'([A-Z_]+):\s*(.*)'
        
        for line in output.split('\n'):
            match = re.search(pattern, line)
            if match:
                key = match.group(1)
                value = match.group(2).strip()
                
                # Convert numeric values
                if value.isdigit():
                    value = int(value)
                elif ';' in value:
                    # Handle semicolon-separated lists
                    value = value.split(';')
                    # Convert to integers if possible
                    if all(item.isdigit() for item in value):
                        value = [int(item) for item in value]
                elif value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                
                config_dict[key] = value
                
        return config_dict

    def _full_access_day_hours(self):
        return {
            str(hour): {
                "STARTMIN": 0,
                "ENDMIN": 60,
                "UACC": 0,
            }
            for hour in range(24)
        }

    def _interval_to_dbus_hours(self, interval):
        if not interval or not interval.is_enabled or not interval.is_valid_interval():
            return {}

        if interval.start_minute == 0 and interval.end_minute == 0:
            return {
                str(hour): {"STARTMIN": 0, "ENDMIN": 60, "UACC": 0}
                for hour in range(interval.start_hour, interval.end_hour)
            }

        result = {}
        current_hour = interval.start_hour

        if current_hour == interval.end_hour:
            result[str(current_hour)] = {
                "STARTMIN": interval.start_minute,
                "ENDMIN": interval.end_minute,
                "UACC": 0,
            }
            return result

        result[str(current_hour)] = {
            "STARTMIN": interval.start_minute,
            "ENDMIN": 60,
            "UACC": 0,
        }
        current_hour += 1

        while current_hour < interval.end_hour:
            result[str(current_hour)] = {
                "STARTMIN": 0,
                "ENDMIN": 60,
                "UACC": 0,
            }
            current_hour += 1

        if interval.end_minute > 0:
            result[str(interval.end_hour)] = {
                "STARTMIN": 0,
                "ENDMIN": interval.end_minute,
                "UACC": 0,
            }

        return result

    def _build_dbus_day_hours(self, day_num, day_intervals):
        if not isinstance(day_intervals, list):
            day_intervals = [day_intervals]

        ordered_intervals = sorted(
            [
                interval for interval in day_intervals
                if interval and interval.is_enabled and interval.is_valid_interval()
            ],
            key=lambda interval: (
                interval.start_hour * 60 + interval.start_minute,
                interval.end_hour * 60 + interval.end_minute,
                getattr(interval, 'sort_order', 0),
            ),
        )

        if not ordered_intervals:
            return self._full_access_day_hours()

        day_hours = {}
        for interval in ordered_intervals:
            for hour_key, hour_spec in self._interval_to_dbus_hours(interval).items():
                existing = day_hours.get(hour_key)
                if existing is not None and existing != hour_spec:
                    raise ValueError(
                        f"Day {day_num} contains multiple disjoint intervals within hour {hour_key}, "
                        "which the TimeKpr D-Bus API cannot represent"
                    )
                day_hours[hour_key] = hour_spec

        return day_hours

    def validate_user(self, username, linux_uid=None):
        """
        Check if a user exists by querying the agent for normalized user config
        Returns: (is_valid, message, config_dict)
        """
        args = {}
        if linux_uid is not None:
            args["linux_uid"] = linux_uid
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id, "validate_user", username, args
        )
        if not success:
            return False, message, None

        config_dict = None
        if isinstance(data, dict):
            config_payload = data.get("config")
            if isinstance(config_payload, dict):
                config_dict = config_payload

        if config_dict is None:
            stdout = data.get("stdout", "") if isinstance(data, dict) else ""
            config_dict = self._parse_timekpr_output(stdout)

        return True, message, config_dict

    def modify_time_left(self, username, operation, seconds):
        """
        Modify time left for a user through the agent
        Returns: (success, message)
        """
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id, "modify_time_left", username, {
                "operation": operation,
                "seconds": seconds
            }
        )
        return success, message

    def set_weekly_time_limits(self, username, schedule_dict):
        """
        Set daily time limits for a user through the agent
        Returns: (success, message)
        """
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id, "set_weekly_time_limits", username, {
                "schedule": schedule_dict
            }
        )
        return success, message

    def set_allowed_hours(self, username, intervals_dict):
        """
        Set allowed hours for a user through the agent
        Returns: (success, message)
        """
        day_order = [1, 2, 3, 4, 5, 6, 7]  # Monday to Sunday

        intervals_serial = {}
        for day_num in day_order:
            day_intervals = intervals_dict.get(day_num) or []
            try:
                intervals_serial[str(day_num)] = self._build_dbus_day_hours(day_num, day_intervals)
            except ValueError as exc:
                return False, str(exc)

        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id, "set_allowed_hours", username, {
                "intervals": intervals_serial
            }
        )
        return success, message

    def sync_domain_policy(self, payload):
        """
        Synchronize the effective per-device domain policy through the agent.
        Returns: (success, message)
        """
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "sync_domain_policy",
            "",
            payload,
        )
        return success, message

    def get_domain_policy_state(self):
        """
        Fetch the agent's current cached domain-policy state summary.
        Returns: (success, message, data)
        """
        return AgentConnectionManager.send_command_sync(
            self.system_id,
            "get_domain_policy_state",
            "",
            {},
        )

    def begin_domain_policy_sync(self, sync_id):
        """Start an incremental domain-policy sync session on the agent."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "begin_domain_policy_sync",
            "",
            {
                "sync_id": sync_id,
            },
        )
        return success, message

    def delete_domain_policy_sources(self, sync_id, source_ids):
        """Remove stale source payloads from an in-progress policy sync."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "delete_domain_policy_sources",
            "",
            {
                "sync_id": sync_id,
                "source_ids": list(source_ids or []),
            },
        )
        return success, message

    def send_domain_policy_chunk(self, sync_id, source_id, revision, domains):
        """Send one chunk of domains for a single source revision."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "sync_domain_policy_chunk",
            "",
            {
                "sync_id": sync_id,
                "source_id": str(source_id),
                "revision": revision,
                "domains": list(domains or []),
            },
        )
        return success, message

    def update_domain_policy_manifest(self, sync_id, policies):
        """Publish the per-user source manifest for an in-progress sync."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "update_domain_policy_manifest",
            "",
            {
                "sync_id": sync_id,
                "policies": policies or {},
            },
        )
        return success, message

    def finalize_domain_policy_sync(self, sync_id):
        """Commit an incremental domain-policy sync on the agent."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "finalize_domain_policy_sync",
            "",
            {
                "sync_id": sync_id,
            },
        )
        return success, message

    def abort_domain_policy_sync(self, sync_id):
        """Abort an incremental domain-policy sync on the agent."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "abort_domain_policy_sync",
            "",
            {
                "sync_id": sync_id,
            },
        )
        return success, message

    def sync_apparmor_policy(self, username, policies_list, approval_policy=None):
        """Synchronize the effective per-user AppArmor policy through the agent."""
        payload = {
            "policies": policies_list or [],
        }
        if approval_policy:
            payload["approval_policy"] = approval_policy
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "sync_apparmor_policy",
            username,
            payload,
        )
        return success, message

    def sync_android_device_policy(self, username, device_policy):
        """Synchronize AMAPI-aligned Android device restrictions through the agent."""
        payload = {
            "device_policy": device_policy or {},
        }
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "sync_android_device_policy",
            username,
            payload,
        )
        return success, message

    def sync_linux_device_policy(self, username, device_policy):
        """Synchronize Linux device restrictions (polkit + terminal) through the agent."""
        payload = {
            "device_policy": device_policy or {},
        }
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "sync_linux_device_policy",
            username,
            payload,
        )
        return success, message

    def refresh_installed_apps(self, username):
        """Ask the connected agent to scan and push installed application inventory."""
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id,
            "refresh_installed_apps",
            username,
            {},
        )
        if not success:
            raise RuntimeError(message or 'Agent rejected refresh_installed_apps')
        return data or {"queued": True}

    def sync_screenshot_policy(self, screenshot_policy):
        """Synchronize screenshot capture policy to the connected desktop agent."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "sync_screenshot_policy",
            "",
            {"screenshot_policy": screenshot_policy or {}},
        )
        return success, message

    def capture_screenshot(self, linux_username=None):
        """Ask the connected Linux agent to capture and upload a screenshot now."""
        args = {}
        if linux_username:
            args['linux_username'] = linux_username
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id,
            "capture_screenshot",
            linux_username or "",
            args,
            timeout=45,
        )
        if not success:
            raise RuntimeError(message or 'Agent rejected capture_screenshot')
        return data or {"queued": True}

    def show_overlay(self, username, reason, age_tier, parent_note, device_name, locale=None):
        """Ask the agent to show the Guardian Space blocked overlay for a managed user."""
        from src.models import Settings

        if not locale:
            locale = Settings.get_value('default_locale', 'en') or 'en'
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "show_overlay",
            username,
            {
                "reason": reason or "sleep",
                "age_tier": age_tier or "eight12",
                "parent_note": parent_note or "",
                "device_name": device_name or "",
                "lang": locale,
            },
        )
        return success, message

    def dismiss_overlay(self, username):
        """Ask the agent to dismiss the Guardian Space blocked overlay."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "dismiss_overlay",
            username,
            {},
        )
        return success, message

    def unenroll_device(self, username):
        """Ask the connected agent to stop enforcement and clear local enrollment state."""
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "unenroll",
            username,
            {},
            timeout=30,
        )
        return success, message

    def factory_reset_device(self, username):
        """Ask an Android device-owner agent to wipe the device."""
        from src.agent.push import wake_android_for_factory_reset

        wake_android_for_factory_reset(self.system_id)
        success, message, _ = AgentConnectionManager.send_command_sync(
            self.system_id,
            "factory_reset",
            username,
            {},
            timeout=60,
        )
        return success, message


    def apply_hardware_baseline(self, username='', force_reset_password=False):
        """Apply BIOS hardware baseline settings through the connected agent."""
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id,
            'apply_hardware_baseline',
            username,
            {'force_reset_password': bool(force_reset_password)},
            timeout=120,
        )
        return success, message, data or {}

    def audit_hardware_baseline(self, username=''):
        """Audit BIOS hardware baseline settings without applying changes."""
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id,
            'audit_hardware_baseline',
            username,
            {},
            timeout=120,
        )
        return success, message, data or {}

    def detect_hardware_oem(self, username=''):
        """Detect hardware OEM and supported BIOS interface."""
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id,
            'detect_hardware_oem',
            username,
            {},
            timeout=30,
        )
        return success, message, data or {}

    def clear_safe_mode_lockdown(self, username=''):
        """Clear Safe Mode lockdown override on a Windows agent."""
        success, message, data = AgentConnectionManager.send_command_sync(
            self.system_id,
            'clear_safe_mode_lockdown',
            username,
            {},
            timeout=30,
        )
        return success, message, data or {}


def refresh_installed_apps(system_id, username):
    """Module-level helper for API routes."""
    return AgentClient(system_id).refresh_installed_apps(username)
