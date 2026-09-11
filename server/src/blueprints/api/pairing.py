import logging
import os

from flask import Blueprint, jsonify, request, send_file, session, redirect
from io import BytesIO

from src.agent.helper import AgentConnectionManager
from src.agent.pairing import (
    build_agent_websocket_url,
    build_pairing_payload,
    get_android_apk_storage_path,
    get_server_version,
    has_uploaded_android_apk,
    pairing_payload_json,
    render_pairing_qr_png,
    resolve_android_provisioning,
    get_android_apk_storage_dir,
)
from src.common.settings import (
    _get_agent_websocket_url,
    _get_android_agent_signature_checksum,
)

_LOGGER = logging.getLogger(__name__)

api_pairing_bp = Blueprint('api_pairing', __name__)


@api_pairing_bp.route('/api/pairing/config', methods=['GET'])
def pairing_config():
    """Return JSON payload used by Android/Linux agents during QR setup."""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    explicit_url = (request.args.get('server_url') or '').strip() or None
    server_url = build_agent_websocket_url(
        request,
        explicit_url=explicit_url,
        configured_url=_get_agent_websocket_url(),
    )
    
    household_id = request.args.get('pairing_household_id')
    registration_token = None
    if household_id:
        try:
            from src.models import Household, ParentAccount
            parent_id = session.get('parent_account_id')
            if parent_id:
                p = ParentAccount.query.get(parent_id)
                if p and any(m.household_id == int(household_id) for m in p.memberships):
                    hh = Household.query.get(int(household_id))
                    if hh:
                        registration_token = hh.enrollment_token
        except (ValueError, TypeError):
            pass

    if not registration_token:
        registration_token = AgentConnectionManager.registration_token

    payload = build_pairing_payload(server_url, registration_token)
    return jsonify({'success': True, 'payload': payload})


@api_pairing_bp.route('/api/pairing/qr.png', methods=['GET'])
def pairing_qr_png():
    """Render a QR code PNG for the current server pairing payload."""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    explicit_url = (request.args.get('server_url') or '').strip() or None
    server_url = build_agent_websocket_url(
        request,
        explicit_url=explicit_url,
        configured_url=_get_agent_websocket_url(),
    )
    
    household_id = request.args.get('pairing_household_id')
    registration_token = None
    if household_id:
        try:
            from src.models import Household, ParentAccount
            parent_id = session.get('parent_account_id')
            if parent_id:
                p = ParentAccount.query.get(parent_id)
                if p and any(m.household_id == int(household_id) for m in p.memberships):
                    hh = Household.query.get(int(household_id))
                    if hh:
                        registration_token = hh.enrollment_token
        except (ValueError, TypeError):
            pass

    if not registration_token:
        registration_token = AgentConnectionManager.registration_token

    payload_json = pairing_payload_json(server_url, registration_token)
    png_bytes = render_pairing_qr_png(payload_json)
    return send_file(
        BytesIO(png_bytes),
        mimetype='image/png',
        download_name='timekpr-pairing.png',
        max_age=0,
    )


def _resolve_provisioning_context():
    explicit_url = (request.args.get('server_url') or '').strip() or None
    server_url = build_agent_websocket_url(
        request,
        explicit_url=explicit_url,
        configured_url=_get_agent_websocket_url(),
    )
    
    household_id = request.args.get('pairing_household_id')
    registration_token = None
    if household_id:
        try:
            from src.models import Household, ParentAccount
            parent_id = session.get('parent_account_id')
            if parent_id:
                p = ParentAccount.query.get(parent_id)
                if p and any(m.household_id == int(household_id) for m in p.memberships):
                    hh = Household.query.get(int(household_id))
                    if hh:
                        registration_token = hh.enrollment_token
        except (ValueError, TypeError):
            pass

    if not registration_token:
        registration_token = AgentConnectionManager.registration_token

    return resolve_android_provisioning(
        server_url,
        get_server_version(),
        checksum_override=_get_android_agent_signature_checksum(),
        registration_token=registration_token,
    )


@api_pairing_bp.route('/api/pairing/provisioning/config', methods=['GET'])
def provisioning_config():
    """Return JSON payload used for Android MDM 6-tap provisioning QR codes."""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    context = _resolve_provisioning_context()
    return jsonify({
        'success': True,
        'payload': context['payload'],
        'apk_url': context['apk_url'],
        'apk_source': context['apk_source'],
        'signature_checksum': context['signature_checksum'],
        'checksum_source': context['checksum_source'],
        'provisioning_ready': context['provisioning_ready'],
        'provisioning_warnings': context.get('provisioning_warnings') or [],
        'apk_download_https': context.get('apk_download_https', False),
        'is_dev_version': context['is_dev_version'],
    })


@api_pairing_bp.route('/api/pairing/provisioning/qr.png', methods=['GET'])
def provisioning_qr_png():
    """Render a QR code PNG for Android MDM device provisioning."""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    context = _resolve_provisioning_context()
    if not context['provisioning_ready'] or not context['payload_json']:
        return jsonify({
            'success': False,
            'message': (
                'Android MDM provisioning is not configured. '
                'Upload an Android APK in Settings, or publish a release.'
            ),
        }), 400

    png_bytes = render_pairing_qr_png(context['payload_json'])
    return send_file(
        BytesIO(png_bytes),
        mimetype='image/png',
        download_name='guardian-android-provisioning.png',
        max_age=0,
    )


@api_pairing_bp.route('/api/pairing/provisioning/apk', methods=['GET'])
def provisioning_apk():
    """Serve the uploaded Android agent APK for MDM device provisioning."""
    from flask import session
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    if not has_uploaded_android_apk():
        return jsonify({'success': False, 'message': 'No Android APK uploaded'}), 404

    apk_path = get_android_apk_storage_path()
    return send_file(
        apk_path,
        mimetype='application/vnd.android.package-archive',
        download_name='guardian-android-agent.apk',
        max_age=3600,
        conditional=True,
        etag=True,
    )


@api_pairing_bp.route('/api/pairing/windows/msi', methods=['GET'])
def windows_msi():
    """Serve the local Windows agent MSI installer or redirect to GitHub Releases."""
    from flask import session
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    msi_filename = 'guardian-agent-x86_64-pc-windows-msvc.msi'
    local_path = os.path.join(get_android_apk_storage_dir(), msi_filename)
    if os.path.isfile(local_path) and os.path.getsize(local_path) > 0:
        return send_file(
            local_path,
            mimetype='application/octet-stream',
            download_name=msi_filename,
            max_age=3600,
            conditional=True,
            etag=True,
        )

    from src.agent.releases import get_component

    component = get_component('windows') or {}
    for artifact in component.get('artifacts', []):
        if isinstance(artifact, dict) and artifact.get('id') == 'windows-x86_64':
            url = artifact.get('url')
            if isinstance(url, str) and url:
                return redirect(url)
    return jsonify({
        'success': False,
        'message': 'The Windows installer is not available right now.',
    }), 503


@api_pairing_bp.route('/scripts/install-agent.sh', methods=['GET'])
def linux_install_script():
    """Keep the stable same-origin installer URL backed by the versions feed."""
    from src.agent.releases import get_component

    component = get_component('linux') or {}
    install_script = component.get('install_script')
    if isinstance(install_script, str) and install_script:
        return redirect(install_script)
    return jsonify({
        'success': False,
        'message': 'The Linux installer is not available right now.',
    }), 503
