# pylint: disable=unused-argument

import json
import os
import hmac
import hashlib
from datetime import datetime, timezone
from unittest.mock import patch
from sqlalchemy import text
from app import (
    initialize_runtime,
    ws_agent_handler,
    _ensure_database_schema,
    _get_blocklist_sources,
    task_manager,
)
from src.models import (
    AgentAlert,
    AgentDevice,
    AppArmorRule,
    BlocklistDomain,
    BlocklistSource,
    ManagedUser,
    ManagedUserBlocklistAssignment,
    ManagedUserDeviceMap,
    Settings,
    UserDailyTimeInterval,
    UserWeeklySchedule,
    AppPolicy,
    AppPolicyRule,
    ManagedUserAppPolicyAssignment,
    db,
)
from src.agent.helper import AgentConnectionManager

class MockWS:
    def __init__(self, messages):
        self.messages = messages
        self.sent_messages = []
        self.closed = False
        self.timeout = None

    def receive(self, timeout=None):
        self.timeout = timeout
        if self.messages:
            return self.messages.pop(0)
        return None

    def send(self, data):
        self.sent_messages.append(data)

    def close(self):
        self.closed = True

def test_login_routes(client, db_session):
    # 1. GET login page when not logged in
    res = client.get('/')
    assert res.status_code == 200
    assert b"Login" in res.data

    # 2. POST login with invalid password
    res = client.post('/', data={'username': 'admin', 'password': 'wrongpassword'}, follow_redirects=True)
    assert b"Nothing was changed" in res.data
    assert b'value="admin"' in res.data

    # 3. POST login with correct password
    Settings.set_admin_password("admin")
    res = client.post('/', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    assert b"Dashboard" in res.data

    # 4. GET login page when already logged in -> redirects to dashboard
    res = client.get('/')
    assert res.status_code == 302
    assert "/dashboard" in res.headers['Location']

    # 5. Logout route
    res = client.get('/logout', follow_redirects=True)
    assert b"logged out" in res.data.lower() or b"signed out" in res.data.lower()

def test_oidc_login_redirect(client, db_session):
    with patch('src.common.oidc.OIDCHelper.is_enabled', new=True), \
         patch('src.common.oidc.OIDCHelper.get_authorization_url') as mock_auth_url:
        mock_auth_url.return_value = "https://auth.example.com/login?state=123"
        
        res = client.get('/', follow_redirects=False)
        assert res.status_code == 302
        assert "https://auth.example.com/login" in res.headers['Location']

def test_oidc_callback_route(client, db_session):
    with patch('src.common.oidc.OIDCHelper.is_enabled', new=True):
        # Simulate OIDC Callback with missing code
        with client.session_transaction() as sess:
            sess['oidc_state'] = 'state123'
        res = client.get('/callback?state=state123', follow_redirects=True)
        assert b"finish signing you in" in res.data

        # Simulate OIDC Callback with state mismatch
        res = client.get('/callback?state=wrongstate&code=code123', follow_redirects=True)
        assert b"finish signing you in" in res.data

        # Simulate OIDC Callback success
        with client.session_transaction() as sess:
            sess['oidc_state'] = 'state123'
        
        with patch('src.common.oidc.OIDCHelper.exchange_code') as mock_exchange, \
             patch('src.common.oidc.OIDCHelper.get_user_info') as mock_userinfo, \
             patch.dict('os.environ', {'ALLOWED_OIDC_ADMINS': 'admin@oidc.com'}):
            mock_exchange.return_value = {'access_token': 'access-token'}
            mock_userinfo.return_value = {'preferred_username': 'oidc-admin', 'email': 'admin@oidc.com'}

            res = client.get('/callback?state=state123&code=code123', follow_redirects=True)
            # A brand-new OIDC user with no household is redirected to the
            # onboarding flow to create or join a household.
            assert b"Setup Your Account" in res.data
            # Clean session
            client.get('/logout')

        with client.session_transaction() as sess:
            sess['oidc_state'] = 'state456'
        with patch('src.common.oidc.OIDCHelper.exchange_code') as mock_exchange, \
             patch('src.common.oidc.OIDCHelper.get_user_info') as mock_userinfo, \
             patch.dict('os.environ', {'ALLOWED_OIDC_ADMINS': 'admin@oidc.com'}):
            mock_exchange.return_value = {'access_token': 'access-token'}
            mock_userinfo.return_value = {'preferred_username': 'child', 'email': 'child@school.edu'}

            res = client.get('/callback?state=state456&code=code456', follow_redirects=True)
            assert b"permission to use this console" in res.data.lower()


def test_oidc_session_token_refresh(client, db_session):
    import time
    from src.common.oidc import OIDCRefreshError

    # Set up mock endpoints and configuration
    with patch('src.common.oidc.OIDCHelper.is_enabled', new=True):
        # 1. Token NOT expired
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user'] = {'username': 'oidc-admin'}
            sess['oidc_refresh_token'] = 'refresh-token-xyz'
            sess['oidc_token_expires_at'] = time.time() + 300  # 5 minutes in future

        with patch('src.auth.oidc_token_refresh.refresh_oidc_tokens') as mock_refresh:
            res = client.get('/dashboard')
            assert res.status_code == 200
            mock_refresh.assert_not_called()

        # 2. Token EXPIRED, Refresh Success
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user'] = {'username': 'oidc-admin'}
            sess['oidc_access_token'] = 'old-access-token'
            sess['oidc_refresh_token'] = 'refresh-token-xyz'
            sess['oidc_token_expires_at'] = time.time() - 10  # expired

        with patch('src.auth.oidc_token_refresh.refresh_oidc_tokens') as mock_refresh:
            mock_refresh.return_value = {
                'access_token': 'new-access-token-abc',
                'refresh_token': 'new-refresh-token-123',
                'expires_in': 600
            }
            res = client.get('/dashboard')
            assert res.status_code == 200
            mock_refresh.assert_called_once()
            assert mock_refresh.call_args.args[1] == 'refresh-token-xyz'
            
            with client.session_transaction() as sess:
                assert sess['oidc_access_token'] == 'new-access-token-abc'
                assert sess['oidc_refresh_token'] == 'new-refresh-token-123'
                assert sess['oidc_token_expires_at'] > time.time() + 500

        # 3. Token EXPIRED, Definitive Revocation (Logs user out)
        # Test UI route (redirects to login)
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user'] = {'username': 'oidc-admin'}
            sess['oidc_access_token'] = 'old-access-token'
            sess['oidc_refresh_token'] = 'refresh-token-xyz'
            sess['oidc_token_expires_at'] = time.time() - 10  # expired

        with patch('src.auth.oidc_token_refresh.refresh_oidc_tokens') as mock_refresh:
            mock_refresh.side_effect = OIDCRefreshError("Revoked", is_transient=False, status_code=400)
            res = client.get('/dashboard', follow_redirects=False)
            assert res.status_code == 302
            assert res.headers['Location'].endswith('/') or '/login' in res.headers['Location']
            
            with client.session_transaction() as sess:
                assert not sess.get('logged_in')
                assert 'user' not in sess
                assert 'oidc_access_token' not in sess

        # Test API route (returns 401 JSON)
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user'] = {'username': 'oidc-admin'}
            sess['oidc_access_token'] = 'old-access-token'
            sess['oidc_refresh_token'] = 'refresh-token-xyz'
            sess['oidc_token_expires_at'] = time.time() - 10  # expired

        with patch('src.auth.oidc_token_refresh.refresh_oidc_tokens') as mock_refresh:
            mock_refresh.side_effect = OIDCRefreshError("Revoked", is_transient=False, status_code=400)
            res = client.get('/api/device/approve/sys-1')  # API path
            assert res.status_code == 401
            assert b"Session expired" in res.data
            
            with client.session_transaction() as sess:
                assert not sess.get('logged_in')

        # 4. Token EXPIRED, Transient Failure (Graceful Degradation - keeps user logged in)
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user'] = {'username': 'oidc-admin'}
            sess['oidc_access_token'] = 'old-access-token'
            sess['oidc_refresh_token'] = 'refresh-token-xyz'
            sess['oidc_token_expires_at'] = time.time() - 10  # expired

        with patch('src.auth.oidc_token_refresh.refresh_oidc_tokens') as mock_refresh:
            mock_refresh.side_effect = OIDCRefreshError("Server offline", is_transient=True, status_code=503)
            res = client.get('/dashboard')
            assert res.status_code == 200  # succeeds!
            mock_refresh.assert_called_once()
            
            with client.session_transaction() as sess:
                assert sess.get('logged_in')
                assert sess['oidc_access_token'] == 'old-access-token'
                assert sess.get('oidc_refresh_retry_after', 0) > time.time()

        # 5. Transient failure within backoff window skips another refresh attempt
        with patch('src.auth.oidc_token_refresh.refresh_oidc_tokens') as mock_refresh:
            res = client.get('/dashboard')
            assert res.status_code == 200
            mock_refresh.assert_not_called()


def test_session_extend_endpoint(client, db_session):
    import time

    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['oidc_refresh_token'] = 'refresh-token-xyz'
        sess['oidc_token_expires_at'] = time.time() + 120

    with patch('src.auth.session_lifecycle.refresh_oidc_tokens') as mock_refresh:
        mock_refresh.return_value = {
            'access_token': 'extended-access-token',
            'expires_in': 3600,
        }
        res = client.post('/api/session/extend')
        assert res.status_code == 200
        payload = res.get_json()
        assert payload['success'] is True
        assert 'signed in for longer' in payload['message'].lower()
        mock_refresh.assert_called_once()
        assert mock_refresh.call_args.args[1] == 'refresh-token-xyz'

        with client.session_transaction() as sess:
            assert sess['oidc_access_token'] == 'extended-access-token'
            assert sess['oidc_token_expires_at'] > time.time() + 3500


def test_session_extend_requires_auth(client):
    res = client.post('/api/session/extend')
    assert res.status_code == 401


def test_dashboard_routes(client, db_session):
    # Try accessing when not logged in
    res = client.get('/dashboard')
    assert res.status_code == 302

    # Log in
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    # Create dummy users for dashboard listing
    device = AgentDevice(system_id="sys-1", status="approved", secure_token="token")
    user = ManagedUser(username="jack", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()
    mapping = ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id="sys-1",
        linux_username="jack",
        is_valid=True
    )
    db_session.add(mapping)
    db_session.commit()

    res = client.get('/dashboard')
    assert res.status_code == 200
    assert b"jack" in res.data
    assert b"dashboard-live-indicator" in res.data
    assert b"Never" in res.data

def test_admin_panel(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    pending_device = AgentDevice(system_id="family-alpha-aa", system_hostname="family-pc", status="pending")
    approved_device = AgentDevice(
        system_id="family-beta-bb",
        system_hostname="family-pc",
        status="approved",
        secure_token="token",
    )
    user = ManagedUser(username="alice", system_ip="Unassigned", is_valid=False)
    db_session.add_all([pending_device, approved_device, user])
    db_session.flush()
    db_session.add(ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=approved_device.system_id,
        linux_username="alice",
        is_valid=False,
    ))
    db_session.commit()

    # Try `/admin` redirect
    res = client.get('/admin')
    assert res.status_code == 302
    assert "/admin/users" in res.headers['Location']

    # Fetch users admin page
    res_users = client.get('/admin/users')
    assert res_users.status_code == 200
    assert b"Child Profiles" in res_users.data
    assert b"alice" in res_users.data

    # Fetch devices admin page
    res_devices = client.get('/admin/devices')
    assert res_devices.status_code == 200
    assert b"Devices" in res_devices.data
    assert b"family-pc (aa)" in res_devices.data
    assert b"family-pc (bb)" in res_devices.data

def test_settings_page(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    # GET Settings
    res = client.get('/settings')
    assert res.status_code == 200

    # POST Change Password - Empty fields
    res = client.post('/settings', data={'current_password': '', 'new_password': '', 'confirm_password': ''}, follow_redirects=True)
    assert b"All fields are required" in res.data

    # POST Change Password - Wrong current password
    res = client.post('/settings', data={'current_password': 'wrong', 'new_password': 'pass', 'confirm_password': 'pass'}, follow_redirects=True)
    assert b"Current password is incorrect" in res.data

    # POST Change Password - Passwords mismatch
    res = client.post('/settings', data={'current_password': 'admin', 'new_password': 'pass1', 'confirm_password': 'pass2'}, follow_redirects=True)
    assert b"Passwords do not match" in res.data

    # POST Change Password - Too short
    res = client.post('/settings', data={'current_password': 'admin', 'new_password': 'short', 'confirm_password': 'short'}, follow_redirects=True)
    assert b"must be at least 12 characters" in res.data

    # POST Change Password - Success
    res = client.post('/settings', data={'current_password': 'admin', 'new_password': 'newadminpass12', 'confirm_password': 'newadminpass12'}, follow_redirects=True)
    assert b"updated successfully" in res.data

    # POST alert webhook settings
    with patch('src.common.url_safety.is_safe_outbound_url', return_value=True):
        res = client.post('/admin/settings', data={
            'form_name': 'alert_webhook',
            'alert_webhook_enabled': 'on',
            'alert_webhook_url': 'https://hooks.example.test/timekpr',
            'alert_webhook_secret': 'secret-value',
        }, follow_redirects=True)
    assert b"Alert webhook settings updated successfully" in res.data
    assert Settings.get_value('alert_webhook_enabled') == '1'
    assert Settings.get_value('alert_webhook_url') == 'https://hooks.example.test/timekpr'
    assert Settings.get_value('alert_webhook_secret') == 'secret-value'

    # Enabled without URL should fail validation
    res = client.post('/admin/settings', data={
        'form_name': 'alert_webhook',
        'alert_webhook_enabled': 'on',
        'alert_webhook_url': '',
        'alert_webhook_secret': '',
    }, follow_redirects=True)
    assert b'Webhook URL is required when alert delivery is enabled' in res.data

    # POST agent pairing URL settings
    res = client.post('/admin/settings', data={
        'form_name': 'agent_pairing',
        'agent_websocket_url': 'wss://agents.example.test/ws',
    }, follow_redirects=True)
    assert b'Agent pairing URL updated successfully' in res.data
    assert Settings.get_value('agent_websocket_url') == 'wss://agents.example.test/ws'

    res = client.post('/admin/settings', data={
        'form_name': 'agent_pairing',
        'agent_websocket_url': 'https://agents.example.test/ws',
    }, follow_redirects=True)
    assert b'Agent WebSocket URL must use ws:// or wss://' in res.data

    res = client.post('/admin/settings', data={
        'form_name': 'agent_pairing',
        'agent_websocket_url': '',
    }, follow_redirects=True)
    assert b'Agent pairing URL reset to auto-detect' in res.data
    assert Settings.get_value('agent_websocket_url') == ''

    from io import BytesIO
    import zipfile

    apk_buffer = BytesIO()
    with zipfile.ZipFile(apk_buffer, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest />')
    apk_buffer.seek(0)

    with patch('src.blueprints.ui.dashboard.save_uploaded_android_apk', return_value=('app-release.apk', 'checksum-abc')):
        res = client.post(
            '/admin/settings',
            data={
                'form_name': 'android_provisioning',
                'android_agent_apk': (apk_buffer, 'app-release.apk'),
            },
            content_type='multipart/form-data',
            follow_redirects=True,
        )
    assert b'Android APK uploaded successfully' in res.data
    assert Settings.get_value('android_agent_apk_filename') == 'app-release.apk'
    assert Settings.get_value('android_agent_signature_checksum') == 'checksum-abc'


def test_blocklist_catalog_and_assignment_routes(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(system_id="policy-device", system_hostname="study-pc", status="approved", secure_token="tok")
    user = ManagedUser(username="alice", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()
    mapping = ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=device.system_id,
        linux_username="alice",
        linux_uid=1001,
        is_valid=True,
    )
    db_session.add(mapping)
    db_session.commit()

    res = client.post('/blocklists/sources/add', data={
        'name': 'School Hours',
        'source_type': 'manual',
        'manual_domains': 'dns.google\ncloudflare-dns.com\n',
    }, follow_redirects=True)
    assert b'created with 2 domain(s)' in res.data

    source = BlocklistSource.query.filter_by(name='School Hours').first()
    assert source is not None
    assert source.domain_count == 2

    res = client.post(
        f'/blocklists/sources/{source.id}/domains/add',
        data={'domain': 'example.com'},
        follow_redirects=True,
    )
    assert b'Added example.com' in res.data
    assert BlocklistDomain.query.filter_by(source_id=source.id, domain='example.com').first() is not None

    res = client.post(
        f'/managed-users/{user.id}/blocklists/update',
        data={'source_ids': [str(source.id)]},
        follow_redirects=True,
    )
    assert b'Updated blocklist assignments for alice' in res.data
    assert ManagedUserBlocklistAssignment.query.filter_by(managed_user_id=user.id, source_id=source.id).first() is not None

    sync_status = client.get(f'/api/user/{user.id}/blocklists/sync-status')
    assert sync_status.status_code == 200
    status_payload = json.loads(sync_status.data)
    assert status_payload['success']
    assert status_payload['assigned_source_count'] == 1
    assert status_payload['effective_domain_count'] == 3
    assert status_payload['mapping_count'] == 1

    user_edit_page = client.get(f'/admin/users/{user.id}')
    assert user_edit_page.status_code == 200
    assert b'School Hours' in user_edit_page.data
    assert b'Browsing Shields' in user_edit_page.data or b'browsing-tab' in user_edit_page.data

    device_page = client.get(f'/devices/{device.system_id}')
    assert device_page.status_code == 200
    assert b'Website filters on this device' in device_page.data
    assert b'Lists: 1' in device_page.data


def test_ensure_database_schema_repairs_stamped_empty_database(app, db_session):
    for table_name in db.inspect(db.engine).get_table_names():
        db.session.execute(text(f'DROP TABLE IF EXISTS "{table_name}"'))
    db.session.execute(text(
        'CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)'
    ))
    db.session.execute(text("INSERT INTO alembic_version VALUES ('b3e8a1f04c2d')"))
    db.session.commit()

    migrations_dir = os.path.join(app.root_path, 'migrations')
    _ensure_database_schema(migrations_dir)

    table_names = set(db.inspect(db.engine).get_table_names())
    assert 'blocklist_source' in table_names
    assert 'settings' in table_names
    assert table_names >= set(db.metadata.tables.keys())


def test_android_device_policy_refactor_migration(app, db_session):
    from flask_migrate import upgrade

    migrations_dir = os.path.join(app.root_path, 'migrations')
    for table_name in db.inspect(db.engine).get_table_names():
        db.session.execute(text(f'DROP TABLE IF EXISTS "{table_name}"'))
    db.session.commit()

    upgrade(directory=migrations_dir, revision='6f4e9d1f9b34')

    now = datetime.now(timezone.utc)
    db.session.execute(
        text('''
            INSERT INTO agent_device (system_id, status, secure_token, date_added)
            VALUES (:system_id, 'approved', 'tok', :now)
        '''),
        {'system_id': 'android-refactor', 'now': now},
    )
    db.session.execute(
        text('''
            INSERT INTO managed_user (username, system_ip, date_added)
            VALUES ('child', '127.0.0.1', :now)
        '''),
        {'now': now},
    )
    managed_user_id = db.session.execute(text('SELECT id FROM managed_user WHERE username = "child"')).scalar_one()
    db.session.execute(
        text('''
            INSERT INTO managed_user_device_map (
                managed_user_id, system_id, linux_username, date_added, last_modified,
                blocklist_is_synced
            ) VALUES (
                :managed_user_id, :system_id, 'child', :now, :now, 0
            )
        '''),
        {
            'managed_user_id': managed_user_id,
            'system_id': 'android-refactor',
            'now': now,
        },
    )
    device_map_id = db.session.execute(
        text('SELECT id FROM managed_user_device_map WHERE system_id = :system_id'),
        {'system_id': 'android-refactor'},
    ).scalar_one()
    db.session.execute(
        text('''
            INSERT INTO mapping_android_device_policy (
                device_map_id, screen_capture_disabled, camera_access,
                install_apps_disabled, uninstall_apps_disabled, developer_settings,
                microphone_access, usb_data_access, factory_reset_disabled,
                adjust_volume_disabled, modify_accounts_disabled,
                mount_physical_media_disabled, bluetooth_disabled,
                outgoing_calls_disabled, sms_disabled,
                short_support_message, long_support_message,
                revision, is_synced, created_at, updated_at,
                block_wifi_tethering, block_nfc
            ) VALUES (
                :device_map_id, 1, 'CAMERA_ACCESS_DISABLED',
                0, 0, 'DEVELOPER_SETTINGS_UNSPECIFIED',
                'MICROPHONE_ACCESS_UNSPECIFIED', 'USB_DATA_ACCESS_UNSPECIFIED', 0,
                0, 0, 0, 0, 0, 0,
                'Short msg', 'Long msg',
                'rev-1', 0, :now, :now, 0, 0
            )
        '''),
        {'device_map_id': device_map_id, 'now': now},
    )
    db.session.commit()

    _ensure_database_schema(migrations_dir)

    policy_columns = {col['name'] for col in db.inspect(db.engine).get_columns('mapping_android_device_policy')}
    assert 'system_id' in policy_columns
    assert 'device_map_id' not in policy_columns

    row = db.session.execute(
        text('''
            SELECT system_id, screen_capture_disabled, short_support_message
            FROM mapping_android_device_policy
            WHERE system_id = :system_id
        '''),
        {'system_id': 'android-refactor'},
    ).one()
    assert row.system_id == 'android-refactor'
    assert bool(row.screen_capture_disabled) is True
    assert row.short_support_message == 'Short msg'

    device_columns = {col['name'] for col in db.inspect(db.engine).get_columns('agent_device')}
    assert 'is_device_owner' in device_columns
    assert 'android_force_installed_app' in set(db.inspect(db.engine).get_table_names())


def test_ensure_database_schema_applies_pending_column_migrations(app, db_session):
    db.session.execute(text('DROP TABLE IF EXISTS app_policy'))
    db.session.execute(text('''
        CREATE TABLE app_policy (
            id INTEGER PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )
    '''))
    db.session.execute(text('DROP TABLE IF EXISTS alembic_version'))
    db.session.execute(text(
        'CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)'
    ))
    db.session.execute(text("INSERT INTO alembic_version VALUES ('c4d9e2a1b7f3')"))
    db.session.commit()

    migrations_dir = os.path.join(app.root_path, 'migrations')
    _ensure_database_schema(migrations_dir)

    columns = {col['name'] for col in db.inspect(db.engine).get_columns('app_policy')}
    assert 'platform' in columns


def test_initialize_runtime_is_idempotent_and_preserves_data(app, db_session):
    device = AgentDevice(
        system_id="persist-device",
        system_hostname="persist-pc",
        status="approved",
        secure_token="tok",
    )
    db_session.add(device)
    db_session.commit()

    initialize_runtime(start_background_tasks=False)
    initialize_runtime(start_background_tasks=False)

    assert AgentDevice.query.filter_by(system_id="persist-device").count() == 1


def test_delete_blocklist_source_uses_bulk_delete_path(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(system_id="delete-policy-device", system_hostname="study-pc", status="approved", secure_token="tok")
    user = ManagedUser(username="delete-alice", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()
    db_session.add(ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=device.system_id,
        linux_username="delete-alice",
        linux_uid=1002,
        is_valid=True,
    ))
    source = BlocklistSource(
        name='Delete Large Source',
        source_type=BlocklistSource.TYPE_MANUAL,
        is_enabled=True,
    )
    db_session.add(source)
    db_session.flush()
    db_session.add_all([
        ManagedUserBlocklistAssignment(managed_user_id=user.id, source_id=source.id),
        BlocklistDomain(source_id=source.id, domain='one.example.com'),
        BlocklistDomain(source_id=source.id, domain='two.example.com'),
    ])
    db_session.commit()
    source_id = source.id

    with patch.object(db.session, 'delete', side_effect=AssertionError('ORM delete should not be used')):
        res = client.post(
            f'/blocklists/sources/{source_id}/delete',
            follow_redirects=True,
        )

    assert res.status_code == 200
    assert b'deleted' in res.data
    assert BlocklistSource.query.filter_by(id=source_id).first() is None
    assert BlocklistDomain.query.filter_by(source_id=source_id).count() == 0
    assert ManagedUserBlocklistAssignment.query.filter_by(source_id=source_id).count() == 0


def test_blocklist_source_catalog_uses_capped_preview(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    manual_source = BlocklistSource(
        name='Manual Preview',
        source_type=BlocklistSource.TYPE_MANUAL,
        is_enabled=True,
    )
    external_source = BlocklistSource(
        name='External Huge',
        source_type=BlocklistSource.TYPE_EXTERNAL_URL,
        source_url='https://example.test/huge.txt',
        is_enabled=True,
    )
    db_session.add_all([manual_source, external_source])
    db_session.flush()

    for index in range(30):
        db_session.add(BlocklistDomain(
            source_id=manual_source.id,
            domain=f'manual-{index:03d}.example.com',
        ))
        db_session.add(BlocklistDomain(
            source_id=external_source.id,
            domain=f'external-{index:03d}.example.com',
        ))
    db_session.commit()

    catalog = _get_blocklist_sources(include_domains=True)
    manual_payload = next(item for item in catalog if item['id'] == manual_source.id)
    external_payload = next(item for item in catalog if item['id'] == external_source.id)

    assert manual_payload['domain_count'] == 30
    assert len(manual_payload['domains']) == 25
    assert manual_payload['domains'][0]['domain'] == 'manual-000.example.com'
    assert manual_payload['domains'][-1]['domain'] == 'manual-024.example.com'
    assert external_payload['domain_count'] == 30
    assert external_payload.get('domains') is None

    page = client.get('/admin/restrictions')
    assert page.status_code == 200
    assert b'manual-000.example.com' in page.data
    assert b'manual-024.example.com' in page.data
    assert b'manual-025.example.com' not in page.data
    assert b'external-000.example.com' not in page.data

def test_user_operations(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    # Approve a device so we can register a user to it
    device = AgentDevice(system_id="device-abc", system_hostname="laptop", status="approved", secure_token="tkn")
    db_session.add(device)
    db_session.commit()

    # 1. Add new user - missing username/system_id
    res = client.post('/users/add', data={'username': '', 'system_id': ''}, follow_redirects=True)
    assert b"Both username and device are required" in res.data

    # 2. Add new user - device not approved
    res = client.post('/users/add', data={'username': 'bob', 'system_id': 'device-unapproved'}, follow_redirects=True)
    assert b"is not registered or approved" in res.data

    # 3. Add new user - success
    res = client.post('/users/add', data={'username': 'bob', 'system_id': 'device-abc'}, follow_redirects=True)
    assert b"and mapping added" in res.data

    # 4. Add existing user
    res = client.post('/users/add', data={'username': 'bob', 'system_id': 'device-abc'}, follow_redirects=True)
    assert b"already exists" in res.data

    # Retrieve bob's user record
    bob_user = ManagedUser.query.filter_by(username="bob").first()
    assert bob_user is not None

    # 4b. Create managed user using new endpoint
    res = client.post('/managed-users/add', data={'username': 'alice'}, follow_redirects=True)
    assert b"Managed user alice created" in res.data
    alice = ManagedUser.query.filter_by(username="alice").first()
    assert alice is not None

    # 4c. Add mapping using new endpoint
    res = client.post(
        f'/managed-users/{alice.id}/mappings/add',
        data={'system_id': 'device-abc', 'linux_username': 'alice', 'linux_uid': '1001'},
        follow_redirects=True
    )
    assert b"Mapping added: alice -&gt; alice@laptop" in res.data
    alice_mapping = ManagedUserDeviceMap.query.filter_by(managed_user_id=alice.id, system_id='device-abc').first()
    assert alice_mapping is not None

    # 5. Validate user manual triggers
    with patch('src.agent.helper.AgentClient.validate_user') as mock_val:
        mock_val.return_value = (True, "Valid User", {"TIME_SPENT_DAY": 1200})
        res = client.get(f'/users/validate/{bob_user.id}', follow_redirects=True)
        assert b"Validated" in res.data

    # 6. Delete user
    res = client.post(f'/users/delete/{bob_user.id}', follow_redirects=True)
    assert b"removed successfully" in res.data

def test_rest_apis(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    # Setup devices
    device_pending = AgentDevice(system_id="sys-pending-aa", system_hostname="family-pc", status="pending")
    device_approved = AgentDevice(
        system_id="sys-approved-bb",
        system_hostname="family-pc",
        status="approved",
        secure_token="some-tkn",
    )
    db_session.add_all([device_pending, device_approved])
    db_session.commit()

    # Approve Device API - Device Not Found
    res = client.post('/api/device/approve/sys-none')
    assert res.status_code == 404

    # Approve Device API - Device not pending
    res = client.post('/api/device/approve/sys-approved-bb')
    assert res.status_code == 400

    # Approve Device API - Success
    res = client.post('/api/device/approve/sys-pending-aa')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert data['message'] == 'Device family-pc (aa) approved successfully.'
    assert device_pending.status == "approved"
    assert device_pending.secure_token is not None

    # Reject Device API - Device Not Found
    res = client.post('/api/device/reject/sys-none')
    assert res.status_code == 404

    # Reject Device API - Success
    res = client.post('/api/device/reject/sys-approved-bb')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert data['message'] == 'Device family-pc (bb) rejected successfully.'
    assert device_approved.status == "rejected"
    assert device_approved.secure_token is None

    # Task status and restart APIs
    res = client.get('/api/task-status')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert 'running' in data['status']

    res = client.post('/restart-tasks', follow_redirects=True)
    assert b"restarted" in res.data

def test_websocket_handler(app, db_session):
    from simple_websocket.errors import ConnectionClosed

    class DisconnectBeforeHelloWS(MockWS):
        def receive(self, timeout=None):
            raise ConnectionClosed(1005)

    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(DisconnectBeforeHelloWS([]))

    # 1. Connection attempt timeout (empty hello)
    ws_timeout = MockWS([])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_timeout)
    assert not ws_timeout.sent_messages

    # 2. Hello with invalid type
    ws_invalid = MockWS([json.dumps({"type": "not_hello"})])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_invalid)
    assert json.loads(ws_invalid.sent_messages[0])['message'] == "Expected 'hello' type"

    # 3. Hello missing system_id
    ws_missing = MockWS([json.dumps({"type": "hello"})])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_missing)
    assert json.loads(ws_missing.sent_messages[0])['message'] == "Missing system_id"

    # 4. Hello invalid registration token firewall check
    with patch('src.agent.helper.REGISTRATION_TOKEN', new='secret-firewall-token'):
        ws_firewall = MockWS([json.dumps({
            "type": "hello",
            "system_id": "sys-fw",
            "registration_token": "wrong-token",
            "agent_version": "v0.10"
        })])
        with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            ws_agent_handler(ws_firewall)
        assert json.loads(ws_firewall.sent_messages[0])['message'] == "Invalid registration token"

    # 5. New Pending Device pair registration
    ws_pending_new = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-new-pending",
        "system_hostname": "kids-pc",
        "agent_version": "v0.10"
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_pending_new)
    # Check that it gets marked pending and pairing_status sent
    assert json.loads(ws_pending_new.sent_messages[0])['type'] == "pairing_status"
    assert json.loads(ws_pending_new.sent_messages[0])['status'] == "pending"
    pending_device = AgentDevice.query.get("sys-new-pending")
    assert pending_device.system_hostname == "kids-pc"


def test_websocket_handshake_saves_linux_users(app, db_session):
    from app import ws_agent_handler
    
    users_payload = [
        {"username": "child1", "uid": 1001},
        {"username": "child2", "uid": 1002}
    ]
    
    ws = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-users-test",
        "system_hostname": "test-pc",
        "agent_version": "v0.10",
        "linux_users": users_payload
    })])
    
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '1.2.3.4'}):
        ws_agent_handler(ws)
        
    device = AgentDevice.query.get("sys-users-test")
    assert device is not None
    assert len(device.linux_users) == 2
    assert device.linux_users[0]['username'] == "child1"
    assert device.linux_users[1]['uid'] == 1002


def test_websocket_handshake_unpaired_approved_device(app, db_session):
    from app import ws_agent_handler
    from src.models import Household
    
    system_id = "approved-but-unpaired"
    token = "approved-token-value"
    household = Household(name='Test Home', enrollment_token='enroll-test-token')
    db_session.add(household)
    db_session.flush()
    device = AgentDevice(
        system_id=system_id,
        status="approved",
        secure_token=token,
        household_id=household.id,
    )
    db_session.add(device)
    db_session.commit()

    hello_msg = json.dumps({
        "type": "hello",
        "system_id": system_id,
        "agent_version": "v0.10",
        "paired": False,
        "registration_token": "enroll-test-token",
    })

    ws = MockWS([hello_msg])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws)

    assert len(ws.sent_messages) == 1
    resp = json.loads(ws.sent_messages[0])
    assert resp['type'] == "pairing_approved"
    assert resp['token'] == token


def test_websocket_unpaired_approved_device_rejects_missing_enrollment_token(app, db_session):
    from app import ws_agent_handler

    system_id = "approved-no-enrollment"
    token = "approved-token-value"
    device = AgentDevice(system_id=system_id, status="approved", secure_token=token)
    db_session.add(device)
    db_session.commit()

    hello_msg = json.dumps({
        "type": "hello",
        "system_id": system_id,
        "agent_version": "v0.10",
        "paired": False,
    })

    ws = MockWS([hello_msg])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws)

    assert len(ws.sent_messages) == 1
    resp = json.loads(ws.sent_messages[0])
    assert resp['type'] == "auth_result"
    assert resp['success'] is False


    # 6. Approved Device authentication flow (HMAC challenge-response)
    system_id = "approved-system-id"
    token = "approved-token"
    device = AgentDevice(system_id=system_id, status="approved", secure_token=token)
    db_session.add(device)
    db_session.commit()

    # Step A: Hello
    hello_msg = json.dumps({"type": "hello", "system_id": system_id, "agent_version": "v0.10"})
    
    # Custom MockWS that captures the challenge sent by the handler and generates a valid signature response
    # to feed back on next receive() call
    class FlowWS(MockWS):
        def send(self, data):
            super().send(data)
            payload = json.loads(data)
            if payload.get("type") == "challenge":
                challenge = payload.get("challenge")
                # Calculate signature
                token_bytes = token.encode('utf-8')
                msg = (challenge + system_id).encode('utf-8')
                signature = hmac.new(token_bytes, msg, hashlib.sha256).hexdigest()
                # Queue signature response for next receive call
                self.messages.append(json.dumps({
                    "type": "register",
                    "signature": signature
                }))
                self.messages.append(json.dumps({
                    "type": "alert_event",
                    "event_type": "system_startup",
                    "occurred_at": "2026-05-25T21:05:00Z",
                    "details": {"source": "test-suite"}
                }))

    ws_flow = FlowWS([hello_msg])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_flow)

    # Check that challenge was sent and auth_result was successful
    assert len(ws_flow.sent_messages) == 2
    assert json.loads(ws_flow.sent_messages[0])['type'] == "challenge"
    assert json.loads(ws_flow.sent_messages[1])['type'] == "auth_result"
    assert json.loads(ws_flow.sent_messages[1])['success'] is True

    android_system_id = "android-persistent-ws"
    android_token = "android-persistent-token"
    android_device = AgentDevice(
        system_id=android_system_id,
        status="approved",
        secure_token=android_token,
        platform='android',
        fcm_token='device-fcm-token',
    )
    db_session.add(android_device)
    db_session.commit()

    android_hello = json.dumps({
        "type": "hello",
        "system_id": android_system_id,
        "agent_version": "v0.10",
        "platform": "android",
        "fcm_token": "device-fcm-token",
    })

    class AndroidFlowWS(MockWS):
        def send(self, data):
            super().send(data)
            payload = json.loads(data)
            if payload.get("type") == "challenge":
                challenge = payload.get("challenge")
                token_bytes = android_token.encode('utf-8')
                msg = (challenge + android_system_id).encode('utf-8')
                signature = hmac.new(token_bytes, msg, hashlib.sha256).hexdigest()
                self.messages.append(json.dumps({
                    "type": "register",
                    "signature": signature,
                }))

    android_ws = AndroidFlowWS([android_hello])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(android_ws)

    android_auth = json.loads(android_ws.sent_messages[1])
    assert android_auth['type'] == "auth_result"
    assert android_auth['success'] is True
    assert android_auth.get('persistent_connection') is True

    stored_alert = AgentAlert.query.filter_by(system_id=system_id, event_type='system_startup').first()
    assert stored_alert is not None
    assert stored_alert.delivery_status == AgentAlert.DELIVERY_DISABLED
    assert stored_alert.payload["details"]["source"] == "test-suite"

    policy_check_system_id = "policy-check-system-id"
    policy_check_token = "policy-check-token"
    db_session.add(AgentDevice(system_id=policy_check_system_id, status="approved", secure_token=policy_check_token))
    db_session.commit()

    class PolicyCheckWS(MockWS):
        def send(self, data):
            super().send(data)
            payload = json.loads(data)
            if payload.get("type") == "challenge":
                challenge = payload.get("challenge")
                token_bytes = policy_check_token.encode('utf-8')
                msg = (challenge + policy_check_system_id).encode('utf-8')
                signature = hmac.new(token_bytes, msg, hashlib.sha256).hexdigest()
                self.messages.append(json.dumps({
                    "type": "register",
                    "signature": signature
                }))
                self.messages.append(json.dumps({
                    "type": "policy_sync_check",
                    "source_revisions": {"1": "rev-1"}
                }))

    ws_policy_check = PolicyCheckWS([json.dumps({
        "type": "hello",
        "system_id": policy_check_system_id,
        "agent_version": "v0.10"
    })])
    with patch.object(task_manager, 'request_domain_policy_sync') as mock_request_sync:
        with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            ws_agent_handler(ws_policy_check)
    mock_request_sync.assert_called_once_with(
        policy_check_system_id,
        source_revisions={"1": "rev-1"},
        reason='agent_timer',
    )

    class InvalidAlertWS(MockWS):
        def send(self, data):
            super().send(data)
            payload = json.loads(data)
            if payload.get("type") == "challenge":
                challenge = payload.get("challenge")
                token_bytes = token.encode('utf-8')
                msg = (challenge + invalid_system_id).encode('utf-8')
                signature = hmac.new(token_bytes, msg, hashlib.sha256).hexdigest()
                self.messages.append(json.dumps({
                    "type": "register",
                    "signature": signature
                }))
                self.messages.append(json.dumps({
                    "type": "alert_event",
                    "event_type": "invalid_type",
                    "occurred_at": "2026-05-25T21:05:00Z",
                    "details": {"source": "bad-payload"}
                }))

    invalid_system_id = "approved-system-invalid"
    invalid_device = AgentDevice(system_id=invalid_system_id, status="approved", secure_token=token)
    db_session.add(invalid_device)
    db_session.commit()

    invalid_ws = InvalidAlertWS([json.dumps({"type": "hello", "system_id": invalid_system_id, "agent_version": "v0.10"})])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(invalid_ws)

    assert AgentAlert.query.filter_by(system_id=invalid_system_id).count() == 0

def test_websocket_handler_accepts_mismatched_agent_on_dev_server(app, db_session, monkeypatch):
    import app as app_module
    from app import ws_agent_handler

    monkeypatch.setattr(app_module, '__version__', 'v0.0.0-dev')

    ws_dev = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-dev-android",
        "agent_version": "v0.1.0-android",
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_dev)

    assert len(ws_dev.sent_messages) == 1
    resp = json.loads(ws_dev.sent_messages[0])
    assert resp['type'] == "pairing_status"


def test_websocket_handler_version_checking(app, db_session, monkeypatch):
    from app import __version__, ws_agent_handler

    # 1. Test mismatched agent version (non-android: no APK fields)
    ws_mismatch = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-mismatch",
        "agent_version": "v0.0.1"
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_mismatch)
    
    assert len(ws_mismatch.sent_messages) == 1
    resp = json.loads(ws_mismatch.sent_messages[0])
    assert resp['type'] == "auth_result"
    assert resp['success'] is False
    assert resp['update_required'] is True
    assert resp['target_version'] == __version__
    assert 'apk_url' not in resp
    assert 'signature_checksum' not in resp

    # 1b. Android mismatch includes update metadata when available
    def _mock_update_info(platform, target_version, server_url='', agent_arch=None):
        return {
            'github_repo': 'pantherale0/timekpr-webui',
            'apk_url': 'https://example.com/agent.apk',
            'signature_checksum': 'abc123checksum',
            'update_available': True,
            'target_version': target_version,
            'download_url': '',
            'checksum_url': '',
        }

    monkeypatch.setattr(
        'src.agent.releases.resolve_agent_update_info',
        _mock_update_info,
    )
    ws_android_mismatch = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-android-mismatch",
        "agent_version": "v0.0.1",
        "platform": "android",
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_android_mismatch)

    assert len(ws_android_mismatch.sent_messages) == 1
    resp_android = json.loads(ws_android_mismatch.sent_messages[0])
    assert resp_android['update_required'] is True
    assert resp_android['github_repo'] == 'pantherale0/timekpr-webui'
    assert resp_android['apk_url'] == 'https://example.com/agent.apk'
    assert resp_android['signature_checksum'] == 'abc123checksum'
    assert resp_android['update_available'] is True

    # 2. Test missing agent version
    ws_missing_ver = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-missing-ver"
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_missing_ver)
        
    assert len(ws_missing_ver.sent_messages) == 1
    resp2 = json.loads(ws_missing_ver.sent_messages[0])
    assert resp2['type'] == "auth_result"
    assert resp2['success'] is False
    assert resp2['update_required'] is True
    assert resp2['target_version'] == __version__

    # 3. Test matching agent version (v prefix and no prefix stripped match)
    ws_matching = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-pending-match",
        "agent_version": "0.10"
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_matching)
    # Since it is a new pending device, it should respond with "pairing_status" or similar (which means it passed the version check!)
    assert len(ws_matching.sent_messages) == 1
    resp3 = json.loads(ws_matching.sent_messages[0])
    assert resp3['type'] == "pairing_status"

    # 4. Older patch on the same release line is allowed (server v0.10 == v0.10.0)
    ws_patch_match = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-patch-match",
        "agent_version": "v0.10.0",
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_patch_match)
    assert len(ws_patch_match.sent_messages) == 1
    resp4 = json.loads(ws_patch_match.sent_messages[0])
    assert resp4['type'] == "pairing_status"

    # 5. Agent patch ahead of server patch is rejected
    ws_patch_ahead = MockWS([json.dumps({
        "type": "hello",
        "system_id": "sys-patch-ahead",
        "agent_version": "v0.10.2",
    })])
    with app.test_request_context('/ws', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        ws_agent_handler(ws_patch_ahead)
    assert len(ws_patch_ahead.sent_messages) == 1
    resp5 = json.loads(ws_patch_ahead.sent_messages[0])
    assert resp5['type'] == "auth_result"
    assert resp5['success'] is False
    assert resp5['update_required'] is True


def test_new_endpoints(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(system_id="sys-new", status="approved", secure_token="tkn")
    user = ManagedUser(username="jack", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()
    mapping = ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id="sys-new",
        linux_username="jack",
        is_valid=True
    )
    db_session.add(mapping)
    db_session.commit()

    res = client.get(f'/stats/{user.id}')
    assert res.status_code == 200
    assert b"jack" in res.data

    res = client.post('/weekly-schedule/update', data={
        'user_id': user.id,
        'monday': '2.5',
        'tuesday': '3.0'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert user.weekly_schedule is not None
    assert user.weekly_schedule.monday_hours == 2.5
    assert user.weekly_schedule.tuesday_hours == 3.0

    res = client.post('/weekly-schedule/update', data={'monday': '2.5'}, follow_redirects=True)
    assert b"User ID is required" in res.data

    res = client.post('/weekly-schedule/update', data={'user_id': 'invalid'}, follow_redirects=True)
    assert b"Invalid user ID" in res.data

    res = client.get(f'/api/schedule-sync-status/{user.id}')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert not data['is_synced']

    user_no_sched = ManagedUser(username="nosched", system_ip="Unassigned")
    db_session.add(user_no_sched)
    db_session.flush()
    db_session.add(ManagedUserDeviceMap(
        managed_user_id=user_no_sched.id,
        system_id="sys-new",
        linux_username="nosched",
    ))
    db_session.commit()
    res = client.get(f'/api/schedule-sync-status/{user_no_sched.id}')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['is_synced']
    assert data['schedule'] is None

    res = client.get(f'/api/user/{user.id}/intervals')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert data['username'] == "jack"
    assert data['step_minutes'] == 15
    assert data['intervals']['1'] == []

    interval_data = {
        'intervals': {
            '1': [
                {
                    'start_hour': 9,
                    'start_minute': 0,
                    'end_hour': 11,
                    'end_minute': 0,
                    'is_enabled': True
                },
                {
                    'start_hour': 15,
                    'start_minute': 0,
                    'end_hour': 17,
                    'end_minute': 30,
                    'is_enabled': True
                }
            ],
            '2': []
        }
    }
    res = client.post(
        f'/api/user/{user.id}/intervals/update',
        data=json.dumps(interval_data),
        content_type='application/json'
    )
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']

    day_one_intervals = UserDailyTimeInterval.query.filter_by(
        user_id=user.id,
        day_of_week=1
    ).order_by(UserDailyTimeInterval.sort_order).all()
    assert len(day_one_intervals) == 2
    assert day_one_intervals[0].start_hour == 9
    assert day_one_intervals[1].end_minute == 30
    assert not day_one_intervals[0].is_synced
    hidden_day_two = UserDailyTimeInterval.query.filter_by(user_id=user.id, day_of_week=2).all()
    assert len(hidden_day_two) == 1
    assert hidden_day_two[0].is_enabled is False

    res = client.get(f'/api/user/{user.id}/intervals')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert len(data['intervals']['1']) == 2
    assert data['intervals']['1'][0]['sort_order'] == 0
    assert data['intervals']['1'][1]['time_range'] == "15:00-17:30"

    invalid_interval_data = {
        'intervals': {
            '1': [
                {
                    'start_hour': 10,
                    'start_minute': 0,
                    'end_hour': 12,
                    'end_minute': 0,
                    'is_enabled': True
                },
                {
                    'start_hour': 11,
                    'start_minute': 45,
                    'end_hour': 13,
                    'end_minute': 0,
                    'is_enabled': True
                }
            ]
        }
    }
    res = client.post(
        f'/api/user/{user.id}/intervals/update',
        data=json.dumps(invalid_interval_data),
        content_type='application/json'
    )
    assert res.status_code == 400

    invalid_step_data = {
        'intervals': {
            '1': [
                {
                    'start_hour': 18,
                    'start_minute': 10,
                    'end_hour': 19,
                    'end_minute': 0,
                    'is_enabled': True
                }
            ]
        }
    }
    res = client.post(
        f'/api/user/{user.id}/intervals/update',
        data=json.dumps(invalid_step_data),
        content_type='application/json'
    )
    assert res.status_code == 400

    res = client.post(
        f'/api/user/{user.id}/intervals/update',
        data='null',
        content_type='application/json'
    )
    assert res.status_code == 400

    res = client.get(f'/api/user/{user.id}/intervals/sync-status')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert data['needs_sync']

    class DummyWS:
        def send(self, message):
            pass

    ws = DummyWS()
    AgentConnectionManager.register("sys-new", ws, "127.0.0.1")
    
    with patch('src.agent.helper.AgentClient.modify_time_left') as mock_modify, \
         patch('src.agent.helper.AgentClient.validate_user') as mock_val:
        mock_modify.return_value = (True, "Time modified successfully")
        mock_val.return_value = (True, "Valid User", {"TIME_SPENT_DAY": 1200})
        res = client.post('/api/modify-time', data={
            'user_id': user.id,
            'operation': '+',
            'seconds': '300'
        })
        assert res.status_code == 200
        data = json.loads(res.data)
        assert data['success']
        assert not data.get('pending')

    AgentConnectionManager.unregister("sys-new")
    res = client.post('/api/modify-time', data={
        'user_id': user.id,
        'operation': '-',
        'seconds': '600'
    })
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert data['pending']
    assert user.pending_time_adjustment is None
    assert user.pending_time_operation is None
    assert user.daily_limit_adjustment_seconds == -300
    assert user.daily_limit_adjustment_date == datetime.now(timezone.utc).date()

    res = client.post('/api/modify-time', data={
        'user_id': user.id,
    })
    assert res.status_code == 400

    res = client.post('/api/modify-time', data={
        'user_id': 'invalid',
        'operation': '+',
        'seconds': 'abc'
    })
    assert res.status_code == 400

    res = client.post('/api/modify-time', data={
        'user_id': user.id,
        'operation': '*',
        'seconds': '300'
    })
    assert res.status_code == 400


def test_alert_pages_for_user_and_device(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(
        system_id="device-alert-aa",
        system_hostname="family-pc",
        system_ip="10.0.0.22",
        status="approved",
        secure_token="tok",
    )
    user = ManagedUser(username="jack", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()
    db_session.add(ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=device.system_id,
        linux_username="jack",
        is_valid=True,
    ))
    db_session.add_all([
        AgentAlert(
            system_id=device.system_id,
            event_type='user_signed_in',
            linux_username='jack',
            occurred_at=datetime.now(timezone.utc),
            payload_json=json.dumps({
                'system_id': device.system_id,
                'event_type': 'user_signed_in',
                'linux_username': 'jack',
                'details': {'session_id': 'c1', 'source': 'login'},
            }),
            webhook_enabled_snapshot=False,
            delivery_status=AgentAlert.DELIVERY_DISABLED,
        ),
        AgentAlert(
            system_id=device.system_id,
            event_type='system_sleep',
            linux_username=None,
            occurred_at=datetime.now(timezone.utc),
            payload_json=json.dumps({
                'system_id': device.system_id,
                'event_type': 'system_sleep',
                'details': {'phase': 'prepare'},
            }),
            webhook_enabled_snapshot=False,
            delivery_status=AgentAlert.DELIVERY_DISABLED,
        ),
        AgentAlert(
            system_id=device.system_id,
            event_type='user_signed_out',
            linux_username='other-user',
            occurred_at=datetime.now(timezone.utc),
            payload_json=json.dumps({
                'system_id': device.system_id,
                'event_type': 'user_signed_out',
                'linux_username': 'other-user',
                'details': {'session_id': 'hidden'},
            }),
            webhook_enabled_snapshot=False,
            delivery_status=AgentAlert.DELIVERY_DISABLED,
        ),
    ])
    db_session.commit()

    res = client.get(f'/stats/{user.id}')
    assert res.status_code == 200
    assert b'Activity Feed' in res.data

    api_res = client.get(f'/api/alerts?managed_user_id={user.id}')
    assert api_res.status_code == 200
    api_data = json.loads(api_res.data)
    assert api_data['success'] is True
    alerts = api_data['data']['alerts']

    event_types = [a['event_type'] for a in alerts]
    assert 'user_signed_in' in event_types
    assert 'system_sleep' in event_types
    assert 'user_signed_out' not in event_types

    # For search filtering
    filtered_api_res = client.get(f'/api/alerts?managed_user_id={user.id}&search=prepare')
    assert filtered_api_res.status_code == 200
    filtered_data = json.loads(filtered_api_res.data)
    filtered_alerts = filtered_data['data']['alerts']
    filtered_event_types = [a['event_type'] for a in filtered_alerts]
    assert 'system_sleep' in filtered_event_types
    assert 'user_signed_in' not in filtered_event_types

    # For device page
    device_page = client.get(f'/devices/{device.system_id}')
    assert device_page.status_code == 200
    assert b'Accounts, apps, and activity logs for this device.' in device_page.data
    assert b'jack' in device_page.data
    assert b'Manage routines' in device_page.data

    # Query device alerts API
    device_api_res = client.get(f'/api/alerts?system_id={device.system_id}')
    assert device_api_res.status_code == 200
    device_api_data = json.loads(device_api_res.data)
    device_alerts = device_api_data['data']['alerts']
    device_event_types = [a['event_type'] for a in device_alerts]
    assert 'user_signed_in' in device_event_types
    assert 'system_sleep' in device_event_types
    assert 'user_signed_out' in device_event_types

    # Filter device alerts
    device_filtered_api_res = client.get(f'/api/alerts?system_id={device.system_id}&search=other-user')
    assert device_filtered_api_res.status_code == 200
    device_filtered_data = json.loads(device_filtered_api_res.data)
    device_filtered_alerts = device_filtered_data['data']['alerts']
    device_filtered_event_types = [a['event_type'] for a in device_filtered_alerts]
    assert 'user_signed_out' in device_filtered_event_types
    assert 'user_signed_in' not in device_filtered_event_types


def test_alerts_endpoint_filters_terminal_commands(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(
        system_id="device-alert-term",
        status="approved",
        secure_token="tok",
    )
    user = ManagedUser(username="jack", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()
    db_session.add(ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=device.system_id,
        linux_username="jack",
        is_valid=True,
    ))
    db_session.add_all([
        AgentAlert(
            system_id=device.system_id,
            event_type='user_signed_in',
            linux_username='jack',
            occurred_at=datetime.now(timezone.utc),
            payload_json=json.dumps({
                'system_id': device.system_id,
                'event_type': 'user_signed_in',
                'linux_username': 'jack',
                'details': {},
            }),
            webhook_enabled_snapshot=False,
            delivery_status=AgentAlert.DELIVERY_DISABLED,
        ),
        AgentAlert(
            system_id=device.system_id,
            event_type='terminal_command',
            linux_username='jack',
            occurred_at=datetime.now(timezone.utc),
            payload_json=json.dumps({
                'system_id': device.system_id,
                'event_type': 'terminal_command',
                'linux_username': 'jack',
                'details': {'cmd': 'ls -l'},
            }),
            webhook_enabled_snapshot=False,
            delivery_status=AgentAlert.DELIVERY_DISABLED,
        ),
    ])
    db_session.commit()

    # 1. Querying /api/alerts by default should filter out terminal_command
    res = client.get(f'/api/alerts?managed_user_id={user.id}')
    assert res.status_code == 200
    data = json.loads(res.data)
    event_types = [a['event_type'] for a in data['data']['alerts']]
    assert 'user_signed_in' in event_types
    assert 'terminal_command' not in event_types
    # terminal_command should also be filtered out from dropdown options
    dropdown_values = [et['value'] for et in data['data']['filters']['event_types']]
    assert 'terminal_command' not in dropdown_values

    # 2. Querying with explicit event_type=terminal_command should return it
    res_term = client.get(f'/api/alerts?managed_user_id={user.id}&event_type=terminal_command')
    assert res_term.status_code == 200
    data_term = json.loads(res_term.data)
    event_types_term = [a['event_type'] for a in data_term['data']['alerts']]
    assert 'terminal_command' in event_types_term
    assert 'user_signed_in' not in event_types_term


def test_apparmor_policy_rejects_globbed_custom_paths(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    policy = AppPolicy(name="Maya Policy")
    db_session.add(policy)
    db_session.commit()

    res = client.post(
        f'/admin/app-policies/{policy.id}/rule/add',
        data={
            'application_name': 'Everything',
            'match_type': 'executable',
            'executable_path': '/usr/bin/**',
            'preset': 'complain',
        },
        follow_redirects=True,
    )

    assert res.status_code == 200
    assert b'glob patterns like /usr/bin/** are not allowed' in res.data
    assert AppPolicyRule.query.filter_by(
        policy_id=policy.id,
        executable_path='/usr/bin/**',
    ).count() == 0


def test_apparmor_policy_accepts_home_subtree_path_rules(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    policy = AppPolicy(name="Maya Policy")
    db_session.add(policy)
    db_session.commit()

    res = client.post(
        f'/admin/app-policies/{policy.id}/rule/add',
        data={
            'application_name': 'Downloads',
            'match_type': 'path_pattern',
            'executable_path': '$HOME/Downloads/**',
            'preset': 'blocked',
        },
        follow_redirects=True,
    )

    assert res.status_code == 200
    rule = AppPolicyRule.query.filter_by(
        policy_id=policy.id,
        executable_path='$HOME/Downloads/**',
    ).first()
    assert rule is not None
    assert rule.match_type == AppArmorRule.MATCH_TYPE_PATH_PATTERN
    assert rule.preset == AppArmorRule.PRESET_BLOCKED


def test_delete_app_policy_rule_recompiles_and_resyncs(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(
        system_id="device-apparmor-delete",
        system_hostname="family-pc",
        system_ip="10.0.0.31",
        status="approved",
        secure_token="tok",
    )
    user = ManagedUser(username="nina", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()

    mapping = ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=device.system_id,
        linux_username="nina",
        is_valid=True,
    )
    db_session.add(mapping)
    db_session.flush()

    policy = AppPolicy(name="Nina Policy")
    db_session.add(policy)
    db_session.flush()

    rule = AppPolicyRule(
        policy_id=policy.id,
        application_name='OBS Studio',
        executable_path='/usr/bin/obs',
        preset=AppPolicyRule.PRESET_BLOCKED,
        is_custom=True,
    )
    db_session.add(rule)
    db_session.flush()

    assignment = ManagedUserAppPolicyAssignment(managed_user_id=user.id, policy_id=policy.id)
    db_session.add(assignment)
    db_session.commit()

    # Compile initial rules
    from src.policy.apparmor import compile_user_apparmor_rules
    compile_user_apparmor_rules(user)

    # Verify compiled rule exists
    assert AppArmorRule.query.filter_by(device_map_id=mapping.id, executable_path='/usr/bin/obs').first() is not None

    with patch.object(AgentConnectionManager, 'is_online', return_value=True), \
         patch('src.agent.helper.AgentClient.sync_apparmor_policy') as mock_sync:
        mock_sync.return_value = (True, 'ok')
        res = client.post(
            f'/admin/app-policies/rule/{rule.id}/delete',
            follow_redirects=True,
        )

    assert b'Removed rule for' in res.data
    assert b'OBS Studio' in res.data
    assert db_session.get(AppPolicyRule, rule.id) is None
    # Verify compiled AppArmorRule was cleaned up after re-compilation
    assert AppArmorRule.query.filter_by(device_map_id=mapping.id, executable_path='/usr/bin/obs').first() is None
    mock_sync.assert_called_once()
    assert mock_sync.call_args.args[0] == 'nina'
    assert mock_sync.call_args.args[1] == []


def test_modify_time_tracks_server_daily_adjustment_for_scheduled_users(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    online_device = AgentDevice(system_id="sched-online", status="approved", secure_token="tok")
    offline_device = AgentDevice(system_id="sched-offline", status="approved", secure_token="tok")
    user = ManagedUser(username="scheduled_user", system_ip="Unassigned", is_valid=True)
    db_session.add_all([online_device, offline_device, user])
    db_session.flush()
    db_session.add_all([
        ManagedUserDeviceMap(
            managed_user_id=user.id,
            system_id="sched-online",
            linux_username="scheduled_user",
            is_valid=True,
        ),
        ManagedUserDeviceMap(
            managed_user_id=user.id,
            system_id="sched-offline",
            linux_username="scheduled_user",
            is_valid=True,
        ),
    ])

    schedule = UserWeeklySchedule(user_id=user.id, is_synced=True)
    weekday_columns = (
        'monday_hours',
        'tuesday_hours',
        'wednesday_hours',
        'thursday_hours',
        'friday_hours',
        'saturday_hours',
        'sunday_hours',
    )
    setattr(schedule, weekday_columns[datetime.now(timezone.utc).date().weekday()], 2.0)
    db_session.add(schedule)
    db_session.commit()

    class DummyWS:
        def send(self, message):
            pass

    AgentConnectionManager.register("sched-online", DummyWS(), "127.0.0.1")

    with patch('src.agent.helper.AgentClient.modify_time_left') as mock_modify:
        mock_modify.return_value = (True, "Time modified successfully")
        res = client.post('/api/modify-time', data={
            'user_id': user.id,
            'operation': '+',
            'seconds': '300'
        })

    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['success']
    assert data['pending']
    assert user.daily_limit_adjustment_seconds == 300
    assert user.daily_limit_adjustment_date == datetime.now(timezone.utc).date()
    assert user.pending_time_adjustment is None
    assert user.pending_time_operation is None
    assert mock_modify.call_count == 1

    AgentConnectionManager.unregister("sched-online")


def test_app_policies_compiles_and_resolves_precedence(client, db_session):
    Settings.set_admin_password("admin")
    client.post('/', data={'username': 'admin', 'password': 'admin'})

    device = AgentDevice(
        system_id="device-apparmor-policy",
        system_hostname="family-pc",
        system_ip="10.0.0.50",
        status="approved",
        secure_token="tok",
    )
    user = ManagedUser(username="elena", system_ip="Unassigned", is_valid=True)
    db_session.add_all([device, user])
    db_session.flush()

    mapping = ManagedUserDeviceMap(
        managed_user_id=user.id,
        system_id=device.system_id,
        linux_username="elena",
        is_valid=True,
    )
    db_session.add(mapping)
    db_session.flush()

    policy_allow = AppPolicy(name="Allow Browse")
    policy_block = AppPolicy(name="Block Browse")
    db_session.add_all([policy_allow, policy_block])
    db_session.flush()

    rule_allow = AppPolicyRule(
        policy_id=policy_allow.id,
        application_name="Firefox",
        executable_path="/usr/bin/firefox",
        match_type=AppPolicyRule.MATCH_TYPE_EXECUTABLE,
        preset=AppPolicyRule.PRESET_ALLOWED,
        is_custom=True
    )
    rule_block = AppPolicyRule(
        policy_id=policy_block.id,
        application_name="Firefox",
        executable_path="/usr/bin/firefox",
        match_type=AppPolicyRule.MATCH_TYPE_EXECUTABLE,
        preset=AppPolicyRule.PRESET_BLOCKED,
        is_custom=True
    )
    db_session.add_all([rule_allow, rule_block])
    db_session.flush()

    assign_allow = ManagedUserAppPolicyAssignment(managed_user_id=user.id, policy_id=policy_allow.id)
    assign_block = ManagedUserAppPolicyAssignment(managed_user_id=user.id, policy_id=policy_block.id)
    db_session.add_all([assign_allow, assign_block])
    db_session.commit()

    from src.policy.apparmor import compile_user_apparmor_rules
    compile_user_apparmor_rules(user)

    active_rules = AppArmorRule.query.filter_by(device_map_id=mapping.id).all()
    assert len(active_rules) == 1
    assert active_rules[0].executable_path == "/usr/bin/firefox"
    assert active_rules[0].preset == AppArmorRule.PRESET_BLOCKED

