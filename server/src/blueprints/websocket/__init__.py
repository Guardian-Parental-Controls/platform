import json
import logging
import secrets
import threading
from datetime import datetime, timezone
from flask import Blueprint, request
from simple_websocket.errors import ConnectionClosed
from sqlalchemy.exc import SQLAlchemyError
from src.models import db, AgentDevice
from src.agent.helper import (
    AgentConnectionManager,
    agent_patch_update_recommended,
    agent_versions_compatible,
    normalize_agent_alert_payload,
)
from src.agent.releases import enrich_auth_with_agent_update
from src.agent.push import android_should_use_persistent_websocket, update_device_push_metadata
from src.alerts.manager import _store_agent_alert
from src.policy.apparmor import _store_app_usage_from_alert
from src.device.installed_apps import handle_app_icon_report, handle_installed_apps_report
from src.device.screenshots import handle_screenshot_report

_LOGGER = logging.getLogger(__name__)


def _agent_server_url_from_request() -> str:
    """Build the WebSocket URL agents use to reach this server."""
    proto = request.headers.get('X-Forwarded-Proto')
    if not proto:
        proto = 'https' if request.is_secure else 'http'
    host = request.headers.get('Host', request.host)
    ws_scheme = 'wss' if proto == 'https' else 'ws'
    return f'{ws_scheme}://{host}/ws'

websocket_bp = Blueprint('websocket', __name__)


def _flush_pending_commands_on_connect(system_id, flask_app):
    """Drain persisted pending commands after a device authenticates."""
    from src.agent.pending_commands import flush_pending_commands

    try:
        result = flush_pending_commands(system_id, app=flask_app)
        if result.delivered or result.failed or result.expired:
            _LOGGER.info(
                'Pending command flush for %s: delivered=%s failed=%s expired=%s',
                system_id,
                result.delivered,
                result.failed,
                result.expired,
            )
    except Exception:
        _LOGGER.exception('Pending command flush failed for %s', system_id)


def _close_websocket_connection(ws, system_id, connection_label):
    """Close a websocket connection while swallowing routine disconnect errors."""
    try:
        ws.close()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        _LOGGER.debug(
            "Ignoring %s close failure for %s",
            connection_label,
            system_id,
        )


def _release_db_session():
    """Return the scoped SQLAlchemy connection to the pool during long websocket waits."""
    try:
        db.session.remove()
    except (RuntimeError, TypeError, ValueError, SQLAlchemyError):
        _LOGGER.debug("Could not release websocket database session", exc_info=True)


def ws_agent_handler(ws):
    """
    WebSocket endpoint for client agents.
    Handles dynamic pairing, manual approval review, and HMAC challenge-response handshake.
    """
    from app import __version__, app, task_manager

    remote_ip = request.remote_addr or "127.0.0.1"
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        remote_ip = x_forwarded_for.split(",")[0].strip()
        
    _LOGGER.info("WebSocket connection attempt from %s", remote_ip)
    
    # 1. Await initial "hello" registration message
    system_id = None
    try:
        try:
            hello_msg_raw = ws.receive(timeout=10)
            if not hello_msg_raw:
                _LOGGER.warning("Handshake timeout: empty hello message")
                return
                
            hello_msg = json.loads(hello_msg_raw)
            if hello_msg.get("type") != "hello":
                _LOGGER.warning(
                    "Unexpected initial message type: %s",
                    hello_msg.get('type'),
                )
                ws.send(json.dumps({"type": "auth_result", "success": False, "message": "Expected 'hello' type"}))
                return
                
            system_id = hello_msg.get("system_id")
            system_hostname = hello_msg.get("system_hostname")
            if isinstance(system_hostname, str):
                system_hostname = system_hostname.strip() or None
            reg_token = hello_msg.get("registration_token")
            paired = hello_msg.get("paired", True)
            
            if not system_id:
                _LOGGER.warning("Initial hello missing system_id")
                ws.send(json.dumps({"type": "auth_result", "success": False, "message": "Missing system_id"}))
                return
            
            agent_version = hello_msg.get("agent_version")
            platform = hello_msg.get("platform")
            agent_arch = hello_msg.get("agent_arch")
            server_url = _agent_server_url_from_request()
            if not agent_versions_compatible(
                __version__,
                agent_version,
                platform if isinstance(platform, str) else None,
            ):
                _LOGGER.warning(
                    "Connection rejected: Agent version %s is incompatible with server version %s",
                    agent_version or "unknown",
                    __version__,
                )
                rejection = enrich_auth_with_agent_update(
                    {
                        "type": "auth_result",
                        "success": False,
                        "message": f"Incompatible agent version. Please update to {__version__}.",
                    },
                    platform=platform if isinstance(platform, str) else None,
                    server_version=__version__,
                    agent_version=agent_version if isinstance(agent_version, str) else None,
                    server_url=server_url,
                    agent_arch=agent_arch if isinstance(agent_arch, str) else None,
                    mandatory=True,
                )
                ws.send(json.dumps(rejection))
                return
    
            expected_reg_token = AgentConnectionManager.registration_token
            pending_approval = False
            
            with app.app_context():
                device = AgentDevice.query.get(system_id)
                
                if not device:
                    # Look up household by enrollment token
                    from src.models import Household
                    household = None
                    if reg_token:
                        household = Household.query.filter_by(enrollment_token=reg_token).first()

                    # Fallback: global registration token → first/default household
                    if not household and expected_reg_token and reg_token == expected_reg_token:
                        household = Household.query.first()

                    # Open registration mode (no REGISTRATION_TOKEN configured) →
                    # assign to the first household, creating one if needed.
                    # This preserves single-tenant backward compatibility and
                    # handles fresh installations / test environments gracefully.
                    if not household and not expected_reg_token:
                        household = Household.query.first()
                        if not household:
                            household = Household(
                                name='Home',
                                enrollment_token=secrets.token_hex(16),
                            )
                            db.session.add(household)
                            db.session.commit()  # Commit immediately to get household.id cleanly
                            _LOGGER.info("Auto-created default household for open-registration mode")

                    if not household:
                        _LOGGER.warning(
                            "Registration rejected: Invalid registration/enrollment token from %s",
                            system_id,
                        )
                        ws.send(json.dumps({"type": "auth_result", "success": False, "message": "Invalid registration token"}))
                        return
                    
                    device = AgentDevice(
                        system_id=system_id,
                        system_hostname=system_hostname,
                        system_ip=remote_ip,
                        status='pending',
                        household_id=household.id,
                    )
                    db.session.add(device)
                    _LOGGER.info(
                        "New pending device registered: %s from %s",
                        system_id,
                        remote_ip,
                    )
                else:
                    if "system_hostname" in hello_msg:
                        device.system_hostname = system_hostname
                    device.system_ip = remote_ip

                # Update synced linux users list for all connections
                linux_users = hello_msg.get("linux_users")
                policy_hint_system_ids = set()
                if linux_users is not None:
                    device.linux_users_json = json.dumps(linux_users)
                    from src.user.manager import sync_mapping_linux_uids_from_device
                    policy_hint_system_ids = sync_mapping_linux_uids_from_device(device)

                update_device_push_metadata(device, hello_msg)

                hardware_oem = hello_msg.get("hardware_oem")
                if isinstance(hardware_oem, str) and hardware_oem.strip():
                    device.hardware_oem = hardware_oem.strip().lower()[:32]
                hardware_oem_model = hello_msg.get("hardware_oem_model")
                if isinstance(hardware_oem_model, str) and hardware_oem_model.strip():
                    device.hardware_oem_model = hardware_oem_model.strip()[:128]
                
                db.session.commit()

                if policy_hint_system_ids:
                    try:
                        from app import task_manager
                        task_manager.notify_domain_policy_hint(
                            device.household_id,
                            system_ids=policy_hint_system_ids,
                            reason='mapping_uid_updated',
                        )
                    except Exception:
                        _LOGGER.debug(
                            "Could not notify domain policy after uid sync for %s",
                            system_id,
                            exc_info=True,
                        )

                pending_approval = device.status == 'pending'
                if pending_approval:
                    _LOGGER.info("Device %s is PENDING approval. Waiting...", system_id)
                    AgentConnectionManager.register_pending(system_id, ws)
                    ws.send(json.dumps({"type": "pairing_status", "status": "pending"}))

            if pending_approval:
                try:
                    while True:
                        _release_db_session()
                        msg = ws.receive()
                        if not msg:
                            break
                except (OSError, RuntimeError, ValueError):
                    _LOGGER.debug("Pending websocket closed for %s", system_id)
                return

            with app.app_context():
                device = AgentDevice.query.get(system_id)
                if device is None:
                    _LOGGER.warning("Device %s disappeared before handshake could continue", system_id)
                    return

                pending_factory_reset = bool(getattr(device, 'pending_factory_reset', False))
                is_android = (device.platform or '').strip().lower() == 'android'
                allow_pending_reset_auth = (
                    device.status == 'rejected'
                    and pending_factory_reset
                    and is_android
                    and bool(device.secure_token)
                )

                if device.status == 'rejected' and not allow_pending_reset_auth:
                    _LOGGER.warning(
                        "Connection rejected: Device %s is banned/rejected",
                        system_id,
                    )
                    ws.send(json.dumps({"type": "auth_result", "success": False, "message": "Device rejected/banned"}))
                    return
    
                if device.status == 'approved' and not paired:
                    # Never deliver secure_token without enrollment proof.
                    from src.models import Household
                    hh = Household.query.get(device.household_id) if device.household_id else None
                    hh_token = hh.enrollment_token if hh else None

                    token_valid = (
                        (hh_token and reg_token == hh_token) or
                        (expected_reg_token and reg_token == expected_reg_token)
                    )
                    if not token_valid:
                        _LOGGER.warning(
                            "Token delivery rejected: missing or invalid enrollment token from %s",
                            system_id,
                        )
                        ws.send(json.dumps({
                            "type": "auth_result",
                            "success": False,
                            "message": "Valid enrollment token required for pairing",
                        }))
                        return

                    _LOGGER.info(
                        "Device %s is approved but client reports it is unpaired. Delivering token.",
                        system_id,
                    )
                    ws.send(json.dumps({
                        "type": "pairing_approved",
                        "token": device.secure_token
                    }))
                    return

                if device.status == 'approved' or allow_pending_reset_auth:
                    challenge = secrets.token_hex(32)
                    ws.send(json.dumps({
                        "type": "challenge",
                        "challenge": challenge
                    }))
                    
                    auth_msg_raw = ws.receive(timeout=10)
                    if not auth_msg_raw:
                        _LOGGER.warning("Handshake timeout for approved device %s", system_id)
                        return
                        
                    auth_msg = json.loads(auth_msg_raw)
                    if auth_msg.get("type") != "register":
                        _LOGGER.warning(
                            "Unexpected response type from %s: %s",
                            system_id,
                            auth_msg.get('type'),
                        )
                        return
                        
                    signature = auth_msg.get("signature")
                    if not signature:
                        _LOGGER.warning("Handshake from %s missing signature", system_id)
                        return
                        
                    if not AgentConnectionManager.verify_signature(challenge, system_id, signature):
                        _LOGGER.warning(
                            "Authentication signature verification failed for device %s",
                            system_id,
                        )
                        ws.send(json.dumps({"type": "auth_result", "success": False, "message": "Invalid authentication signature"}))
                        return

                    device = AgentDevice.query.get(system_id)
                    if device is None:
                        _LOGGER.warning("Device %s disappeared during authentication handshake", system_id)
                        return
                        
                    AgentConnectionManager.register(system_id, ws, remote_ip)
                    auth_result = {
                        "type": "auth_result",
                        "success": True,
                        "message": "Authenticated successfully",
                    }
                    if agent_patch_update_recommended(
                        __version__,
                        agent_version,
                        platform if isinstance(platform, str) else None,
                    ):
                        auth_result = enrich_auth_with_agent_update(
                            auth_result,
                            platform=platform if isinstance(platform, str) else None,
                            server_version=__version__,
                            agent_version=agent_version if isinstance(agent_version, str) else None,
                            server_url=server_url,
                            agent_arch=agent_arch if isinstance(agent_arch, str) else None,
                            mandatory=False,
                        )
                        if auth_result.get('update_available'):
                            auth_result["message"] = (
                                "Authenticated successfully. An agent update is available."
                            )
                    if android_should_use_persistent_websocket(device):
                        auth_result["persistent_connection"] = True
                    ws.send(json.dumps(auth_result))
                    
                    device.last_seen = datetime.now(timezone.utc)
                    db.session.commit()
                    _LOGGER.info(
                        "Device %s authenticated successfully. Updated device IP snapshot to %s.",
                        system_id,
                        remote_ip,
                    )

                    if pending_factory_reset:
                        from src.device.lifecycle import deliver_pending_factory_reset_on_connect

                        if deliver_pending_factory_reset_on_connect(system_id):
                            return

                    if app.config.get('TESTING'):
                        _flush_pending_commands_on_connect(system_id, app)
                    else:
                        threading.Thread(
                            target=_flush_pending_commands_on_connect,
                            args=(system_id, app),
                            daemon=True,
                        ).start()
    
        except ConnectionClosed as exc:
            if system_id:
                _LOGGER.info(
                    "WebSocket closed during handshake for %s: %s",
                    system_id,
                    exc,
                )
            else:
                _LOGGER.info(
                    "WebSocket closed before hello from %s: %s",
                    remote_ip,
                    exc,
                )
            return
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            SQLAlchemyError,
        ):
            _LOGGER.exception("Error during WebSocket handshake / loop for %s", system_id)
            return
    
        try:
            while True:
                msg_raw = ws.receive()
                if not msg_raw:
                    break
                    
                msg = json.loads(msg_raw)
                msg_type = msg.get("type")
                
                if msg_type == "command_response":
                    correlation_id = msg.get("correlation_id")
                    AgentConnectionManager.route_response(correlation_id, msg)
                elif msg_type == "policy_sync_check":
                    source_revisions = msg.get("source_revisions") or {}
                    if not isinstance(source_revisions, dict):
                        source_revisions = {}
                    task_manager.request_domain_policy_sync(
                        system_id,
                        source_revisions=source_revisions,
                        reason='agent_timer',
                    )
                elif msg_type == "alert_event":
                    try:
                        normalized_alert = normalize_agent_alert_payload(system_id, msg)
                        alert, alert_row_id = _store_agent_alert(system_id, normalized_alert)
                        alert_event_type = normalized_alert['event_type']
                        _LOGGER.info(
                            "Stored alert %s from agent %s as row %s",
                            alert_event_type,
                            system_id,
                            alert_row_id,
                        )
                        if alert_event_type == 'app_usage':
                            _store_app_usage_from_alert(system_id, normalized_alert)
                        elif alert_event_type in {'access_requested', 'app_blocked'}:
                            try:
                                from src.user.approvals import ingest_access_request
                                ingest_access_request(
                                    system_id,
                                    normalized_alert,
                                    source_alert_id=alert_row_id,
                                )
                            except ValueError as exc:
                                _LOGGER.warning(
                                    "Rejected approval ingest from %s: %s",
                                    system_id,
                                    exc,
                                )
                            except Exception as exc:
                                _LOGGER.error(
                                    "Failed to ingest approval request from %s: %s",
                                    system_id,
                                    exc,
                                )
                        elif alert_event_type in {'dialogue_flag', 'sentiment_breach'}:
                            try:
                                from src.user.approvals import ingest_dialogue_flag_alert
                                ingest_dialogue_flag_alert(
                                    system_id,
                                    normalized_alert,
                                    source_alert_id=alert_row_id,
                                )
                            except ValueError as exc:
                                _LOGGER.warning(
                                    "Rejected dialogue flag ingest from %s: %s",
                                    system_id,
                                    exc,
                                )
                            except Exception as exc:
                                _LOGGER.error(
                                    "Failed to ingest dialogue flag alert from %s: %s",
                                    system_id,
                                    exc,
                                )
                        elif alert_event_type == 'clock_tamper':
                            try:
                                from src.common.dashboard_events import notify_dashboard_changed
                                notify_dashboard_changed('clock_tamper')
                            except Exception as exc:
                                _LOGGER.error(
                                    "Failed to notify dashboard of clock tamper from %s: %s",
                                    system_id,
                                    exc,
                                )
                        elif alert_event_type == 'boot_config_tamper':
                            try:
                                from src.common.dashboard_events import notify_dashboard_changed
                                notify_dashboard_changed('boot_config_tamper')
                            except Exception as exc:
                                _LOGGER.error(
                                    "Failed to notify dashboard of boot config tamper from %s: %s",
                                    system_id,
                                    exc,
                                )
                    except ValueError as exc:
                        _LOGGER.warning(
                            "Rejected invalid alert payload from %s: %s",
                            system_id,
                            exc,
                        )
                    except SQLAlchemyError as exc:
                        db.session.rollback()
                        _LOGGER.exception(
                            "Failed to store alert payload from %s: %s",
                            system_id,
                            exc,
                        )
                elif msg_type == "credential_escrow":
                    try:
                        from src.device.windows_laps import persist_credential_escrow
                        from src.agent.helper import parse_agent_alert_timestamp

                        credential_type = (msg.get("credential_type") or "").strip()
                        rotation_id = (msg.get("rotation_id") or "").strip()
                        password = msg.get("password")
                        if not isinstance(password, str) or not password.strip():
                            raise ValueError("password must be a non-empty string")
                        occurred_at = parse_agent_alert_timestamp(msg.get("occurred_at"))
                        persist_credential_escrow(
                            system_id,
                            credential_type,
                            rotation_id,
                            password.strip(),
                            occurred_at=occurred_at,
                        )
                    except ValueError as exc:
                        _LOGGER.warning(
                            "Rejected invalid credential escrow payload from %s: %s",
                            system_id,
                            exc,
                        )
                    except Exception as exc:
                        db.session.rollback()
                        _LOGGER.error(
                            "Failed to store credential escrow from %s: %s",
                            system_id,
                            exc,
                        )
                elif msg_type == "installed_apps_report":
                    try:
                        result = handle_installed_apps_report(system_id, msg)
                        if result.get("success") and not result.get("pending"):
                            from src.user.approvals import push_approval_policies_after_inventory
                            push_approval_policies_after_inventory(
                                system_id,
                                msg.get("linux_username"),
                            )
                        ws.send(json.dumps({
                            "type": "installed_apps_report_ack",
                            "report_id": msg.get("report_id"),
                            "success": result.get("success", True),
                            "apps_upserted": result.get("apps_upserted", 0),
                            "apps_removed": result.get("apps_removed", 0),
                            "apps_total": result.get("apps_total"),
                            "pending": result.get("pending", False),
                        }))
                    except ValueError as exc:
                        _LOGGER.warning(
                            "Rejected invalid installed apps report from %s: %s",
                            system_id,
                            exc,
                        )
                        ws.send(json.dumps({
                            "type": "installed_apps_report_ack",
                            "report_id": msg.get("report_id"),
                            "success": False,
                            "message": str(exc),
                        }))
                    except SQLAlchemyError as exc:
                        db.session.rollback()
                        _LOGGER.error(
                            "Failed to store installed apps report from %s: %s",
                            system_id,
                            exc,
                        )
                        ws.send(json.dumps({
                            "type": "installed_apps_report_ack",
                            "report_id": msg.get("report_id"),
                            "success": False,
                            "message": "Database error",
                        }))
                elif msg_type == "app_icon_report":
                    try:
                        handle_app_icon_report(msg)
                    except ValueError as exc:
                        _LOGGER.warning(
                            "Rejected invalid app icon report from %s: %s",
                            system_id,
                            exc,
                        )
                    except SQLAlchemyError as exc:
                        db.session.rollback()
                        _LOGGER.error(
                            "Failed to store app icon from %s: %s",
                            system_id,
                            exc,
                        )
                elif msg_type == "screenshot_report":
                    try:
                        result = handle_screenshot_report(system_id, msg)
                        ws.send(json.dumps({
                            "type": "screenshot_report_ack",
                            "screenshot_id": msg.get("screenshot_id"),
                            "success": result.get("success", True),
                            "duplicate": result.get("duplicate", False),
                        }))
                    except ValueError as exc:
                        _LOGGER.warning(
                            "Rejected invalid screenshot report from %s: %s",
                            system_id,
                            exc,
                        )
                        ws.send(json.dumps({
                            "type": "screenshot_report_ack",
                            "screenshot_id": msg.get("screenshot_id"),
                            "success": False,
                            "message": str(exc),
                        }))
                    except SQLAlchemyError as exc:
                        db.session.rollback()
                        _LOGGER.error(
                            "Failed to store screenshot from %s: %s",
                            system_id,
                            exc,
                        )
                        ws.send(json.dumps({
                            "type": "screenshot_report_ack",
                            "screenshot_id": msg.get("screenshot_id"),
                            "success": False,
                            "message": "Database error",
                        }))
                else:
                    _LOGGER.warning(
                        "Received unexpected message type from client %s: %s",
                        system_id,
                        msg_type,
                    )
    
        except (OSError, RuntimeError, ValueError) as exc:
            _LOGGER.info("WebSocket connection closed for agent %s: %s", system_id, exc)
    finally:
        if system_id:
            AgentConnectionManager.unregister_pending(system_id)
            AgentConnectionManager.unregister(system_id)
