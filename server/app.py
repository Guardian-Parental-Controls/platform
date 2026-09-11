import fcntl
import logging
import os
import secrets
import threading
from datetime import datetime, timezone
import pytz
from flask import Flask, url_for
from flask_wtf.csrf import CSRFProtect
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

# Initialize WebSocket support
from flask_sock import Sock
from src.common.websocket import disable_permessage_deflate_handshake

disable_permessage_deflate_handshake()
from flask_migrate import Migrate

# Import DB and models for registration
from src.models import db, Settings, AgentDevice
from src.common.tasks import BackgroundTaskManager
from src.common.oidc import OIDCHelper

# Import helpers for direct exposure and backwards-compatibility
from src.common.helpers import (
    _resolve_local_timezone,
    _env_flag_enabled,
    inject_oidc_status,
    localtime_filter,
    inject_timezone,
    inject_create_profile_wizard,
    inject_i18n,
    TIMEZONE_STR,
    LOCAL_TIMEZONE,
    ADMIN_USERNAME,
)
from src.blocklist.manager import _get_blocklist_sources
from src.blueprints.websocket import ws_agent_handler

_LOGGER = logging.getLogger(__name__)

# Version metadata
__version__ = os.environ.get("TIMEKPR_SERVER_VERSION", "v1.0.1-dev")
import time
_startup_version = __version__ if __version__ != "v0.0.0-dev" else f"v0.0.0-dev-{int(time.time())}"

def _load_secret_key(flask_app):
    """Load a stable Flask secret key for signed sessions across restarts/workers."""
    if os.environ.get('TESTING'):
        return 'timekpr-test-secret-key'

    env_key = (os.environ.get('FLASK_SECRET_KEY') or '').strip()
    if env_key:
        return env_key

    os.makedirs(flask_app.instance_path, exist_ok=True)
    key_file = os.path.join(flask_app.instance_path, 'secret.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as handle:
            return handle.read()

    secret_key = os.urandom(32)
    with open(key_file, 'wb') as handle:
        handle.write(secret_key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return secret_key


# Initialize Sentry if a DSN is provided
sentry_dsn = os.environ.get("SENTRY_DSN")
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        release=os.environ.get("TIMEKPR_SERVER_VERSION", "v0.0.0-dev"),
        ignore_errors=[StopIteration],
    )


# Initialize Flask app
app = Flask(__name__)
app.secret_key = _load_secret_key(app)
app.config.setdefault('WTF_CSRF_TIME_LIMIT', None)

# Configure Flask permanent session lifetime
_session_days = int(os.environ.get('PERMANENT_SESSION_LIFETIME_DAYS', '30'))
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=_session_days)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
if os.environ.get('SESSION_COOKIE_SECURE', '').strip().lower() in {'1', 'true', 'yes', 'on'}:
    app.config['SESSION_COOKIE_SECURE'] = True

csrf = CSRFProtect(app)
_default_db_uri = 'sqlite:///:memory:' if os.environ.get('TESTING') else 'sqlite:///timekpr.db'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL')
    or os.environ.get('SQLALCHEMY_DATABASE_URI')
    or _default_db_uri
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
_db_uri_for_pool = (
    os.environ.get('DATABASE_URL')
    or os.environ.get('SQLALCHEMY_DATABASE_URI')
    or _default_db_uri
)
if _db_uri_for_pool.startswith('postgresql') and not os.environ.get('TESTING'):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': int(os.environ.get('SQLALCHEMY_POOL_SIZE', '10')),
        'max_overflow': int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', '20')),
    }

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
sock = Sock(app)

# Configure logging
_LOGGING_CONFIGURED = False


def _configure_logging():
    """Configure process logging once, even if app.py is imported multiple times."""
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if os.environ.get("DEBUG", "0") == "1":
        os.makedirs(app.instance_path, exist_ok=True)
        file_handler = logging.FileHandler(os.path.join(app.instance_path, "debug.log"))
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)
    _LOGGING_CONFIGURED = True


_configure_logging()

# Initialize background task manager
task_manager = BackgroundTaskManager(
    refresh_external_blocklists=_env_flag_enabled('TIMEKPR_TASKS_REFRESH_EXTERNAL', True),
    update_user_data=_env_flag_enabled('TIMEKPR_TASKS_UPDATE_USER_DATA', True),
    sync_domain_policies=_env_flag_enabled('TIMEKPR_TASKS_SYNC_DOMAIN_POLICIES', True),
    deliver_pending_alerts=_env_flag_enabled('TIMEKPR_TASKS_DELIVER_ALERTS', True),
)
task_manager.init_app(app)
_runtime_init_lock = threading.Lock()
# Global state tracking
RUNTIME_STATE = {'initialized': False}

# Initialize OIDC helper
oidc_helper = OIDCHelper()

# Register template filters and context processors from helpers
app.context_processor(inject_oidc_status)
app.template_filter('localtime')(localtime_filter)
app.context_processor(inject_timezone)
app.context_processor(inject_create_profile_wizard)
app.context_processor(inject_i18n)

@app.context_processor
def inject_server_version():
    return {'server_version': _startup_version}


@app.context_processor
def inject_household_context():
    from flask import session
    from src.models import ParentAccount, Household
    
    parent_id = session.get('parent_account_id')
    active_hh_id = session.get('active_household_id')
    households = []
    active_hh = None
    
    if session.get('logged_in'):
        if not parent_id:
            parent = ParentAccount.query.filter_by(email='admin@local').first()
            if parent:
                parent_id = parent.id
                
        if parent_id:
            parent = ParentAccount.query.get(parent_id)
            if parent:
                households = [m.household for m in parent.memberships if m.household]
                
        if active_hh_id:
            active_hh = Household.query.get(active_hh_id)
            
    return {
        'parent_households': households,
        'active_household': active_hh,
    }


@app.before_request
def _resolve_request_locale():
    """Resolve active UI locale for this request."""
    from flask import g, request, session
    from src.models import Settings
    from src.i18n.catalog import resolve_locale

    household_default = None
    try:
        household_default = Settings.get_value('default_locale')
    except Exception:
        household_default = None
    g.locale = resolve_locale(session, request.headers.get('Accept-Language'), household_default)


@app.before_request
def _refresh_oidc_tokens():
    """Check if the OIDC access token is about to expire, and refresh it if needed."""
    from flask import session, redirect, url_for, jsonify, request
    from src.auth.session_lifecycle import (
        OidcRefreshOutcome,
        clear_oidc_session,
        refresh_oidc_session_tokens,
    )

    if not oidc_helper.is_enabled:
        return

    # Skip token refresh for static assets, service worker, or logout
    if request.path.startswith('/static/') or request.path == '/sw.js' or request.path == '/logout':
        return

    if not session.get('logged_in') or not session.get('oidc_refresh_token'):
        return

    outcome = refresh_oidc_session_tokens(session, oidc_helper)
    if outcome == OidcRefreshOutcome.AUTH_FAILURE:
        _LOGGER.info("OIDC session is no longer valid; logging user out.")
        from src.i18n.catalog import flash_t
        flash_t('flash.auth.session_expired', 'warning')
        clear_oidc_session(session)

        if request.path.startswith('/api/') or request.headers.get('X-Guardian-SPA') == 'fragment':
            return jsonify({'success': False, 'message': 'Session expired'}), 401
        return redirect(url_for('ui_auth.login'))


# Import and register blueprints
from src.blueprints import (
    ui_auth_bp,
    ui_dashboard_bp,
    ui_schedule_bp,
    ui_apparmor_bp,
    ui_spa_bp,
    api_devices_bp,
    api_users_bp,
    api_schedule_bp,
    api_blocklists_bp,
    api_time_bp,
    api_tasks_bp,
    api_alerts_bp,
    api_pairing_bp,
    api_dashboard_bp,
    api_installed_apps_bp,
    api_approvals_bp,
    api_android_device_policy_bp,
    api_linux_device_policy_bp,
    api_nintendo_bp,
    api_xbox_bp,
    api_screenshots_bp,
    api_youtube_bp,
    api_hardware_baseline_bp,
    api_windows_laps_bp,
    api_access_requests_bp,
    websocket_bp,
    api_ai_bp,
    sharing_api_bp,
    api_session_bp,
)

@app.before_request
def enforce_household_isolation():
    """Enforce tenant/household boundaries and granular scopes for logged-in multi-tenant parents.

    Only activates when parent_account_id is present in the session (OIDC flow).
    Local admin mode and test environments without a parent account pass through
    unaffected, preserving backward compatibility.
    """
    from flask import request, session, abort
    parent_id = session.get('parent_account_id')
    # Only enforce when we have an explicit parent account identity in the session.
    # Local admin (no parent_account_id) is implicitly trusted.
    if not session.get('logged_in') or not parent_id:
        return

    from src.common.helpers import (
        parent_has_access_to_child,
        parent_has_access_to_device,
        parent_can_manage_blocklist_source,
        parent_can_manage_app_policy,
        parent_can_manage_device,
        device_route_requires_admin,
        get_parent_household_ids,
    )
    from src.models import ManagedUserDeviceMap, ApprovalRequest, PolicyApprovalGrant, DeviceScreenshot, AppPolicyRule

    user_id = None
    if request.view_args and 'user_id' in request.view_args:
        try:
            user_id = int(request.view_args['user_id'])
        except (ValueError, TypeError):
            pass

    if user_id is None and request.view_args and 'managed_user_id' in request.view_args:
        try:
            user_id = int(request.view_args['managed_user_id'])
        except (ValueError, TypeError):
            pass

    if user_id is None:
        try:
            if request.form and 'user_id' in request.form:
                user_id = int(request.form['user_id'])
            elif request.is_json and request.json and 'user_id' in request.json:
                user_id = int(request.json['user_id'])
            elif request.form and 'managed_user_id' in request.form:
                user_id = int(request.form['managed_user_id'])
            elif request.is_json and request.json and 'managed_user_id' in request.json:
                user_id = int(request.json['managed_user_id'])
        except Exception:
            pass

    if request.view_args and 'request_id' in request.view_args:
        try:
            request_id = int(request.view_args['request_id'])
            request_row = ApprovalRequest.query.get(request_id)
            if request_row and request_row.device_map:
                user_id = request_row.device_map.managed_user_id
        except (ValueError, TypeError):
            pass

    if user_id is not None:
        try:
            required_perm = 'can_view_screentime'
            path = request.path
            if any(p in path for p in ['/whitelist', '/block', '/policy', '/presets', '/apparmor']):
                required_perm = 'can_manage_policies'
            elif '/installed-apps' in path and request.method not in ('GET', 'HEAD', 'OPTIONS'):
                required_perm = 'can_manage_policies'
            elif any(p in path for p in ['/schedule', '/limits', '/screentime', '/pause', '/add-time', '/intervals', '/tamper']):
                required_perm = 'can_manage_screentime'
            elif any(p in path for p in ['/inspect', '/stats', '/history', '/logs']):
                required_perm = 'can_view_monitoring'
            elif '/approvals/' in path and (path.endswith('/approve') or path.endswith('/deny')):
                required_perm = 'can_manage_policies'

            if not parent_has_access_to_child(parent_id, user_id, required_perm):
                abort(403)
        except (ValueError, TypeError):
            pass

    # 2. system_id path param → verify device access
    if request.view_args and 'system_id' in request.view_args:
        try:
            system_id = str(request.view_args['system_id'])
            if not parent_has_access_to_device(parent_id, system_id):
                abort(403)
            if device_route_requires_admin(request.path, request.method):
                if not parent_can_manage_device(parent_id, system_id):
                    abort(403)
        except (ValueError, TypeError):
            pass

    # 3. mapping_id path param → verify via the mapping's child + device
    if request.view_args and 'mapping_id' in request.view_args:
        try:
            mapping_id = int(request.view_args['mapping_id'])
            mapping = ManagedUserDeviceMap.query.get(mapping_id)
            if not mapping:
                abort(404)
            if not parent_has_access_to_child(parent_id, mapping.managed_user_id, 'can_view_screentime'):
                abort(403)
            if not parent_has_access_to_device(parent_id, mapping.system_id):
                abort(403)
        except (ValueError, TypeError):
            pass

    if request.view_args and 'grant_id' in request.view_args:
        try:
            grant_id = int(request.view_args['grant_id'])
            grant = PolicyApprovalGrant.query.get(grant_id)
            if not grant:
                abort(404)
            mapping = grant.device_map
            if not mapping:
                abort(404)
            if not parent_has_access_to_child(parent_id, mapping.managed_user_id, 'can_manage_policies'):
                abort(403)
            if not parent_has_access_to_device(parent_id, mapping.system_id):
                abort(403)
        except (ValueError, TypeError):
            pass

    if request.view_args and 'screenshot_id' in request.view_args:
        try:
            screenshot_id = int(request.view_args['screenshot_id'])
            screenshot = DeviceScreenshot.query.get(screenshot_id)
            if not screenshot:
                abort(404)
            if not parent_has_access_to_device(parent_id, screenshot.system_id):
                abort(403)
        except (ValueError, TypeError):
            pass

    if request.view_args and 'source_id' in request.view_args and '/blocklists/sources/' in request.path:
        try:
            source_id = int(request.view_args['source_id'])
            if not parent_can_manage_blocklist_source(parent_id, source_id):
                abort(403)
        except (ValueError, TypeError):
            pass

    if request.view_args and 'policy_id' in request.view_args and '/app-policies/' in request.path:
        try:
            policy_id = int(request.view_args['policy_id'])
            if not parent_can_manage_app_policy(parent_id, policy_id):
                abort(403)
        except (ValueError, TypeError):
            pass

    if request.view_args and 'rule_id' in request.view_args and '/app-policies/' in request.path:
        try:
            rule_id = int(request.view_args['rule_id'])
            rule = AppPolicyRule.query.get(rule_id)
            if not rule:
                abort(404)
            if not parent_can_manage_app_policy(parent_id, rule.policy_id):
                abort(403)
        except (ValueError, TypeError):
            pass

    if request.path.startswith('/api/alerts'):
        system_id_filter = None
        managed_user_filter = None
        if request.args.get('system_id'):
            system_id_filter = str(request.args.get('system_id')).strip()
        if request.args.get('managed_user_id'):
            try:
                managed_user_filter = int(request.args.get('managed_user_id'))
            except (ValueError, TypeError):
                pass
        if request.method == 'POST' and request.is_json and request.json:
            if request.json.get('system_id'):
                system_id_filter = str(request.json.get('system_id')).strip()
            if request.json.get('managed_user_id') is not None:
                try:
                    managed_user_filter = int(request.json.get('managed_user_id'))
                except (ValueError, TypeError):
                    pass
        if system_id_filter and not parent_has_access_to_device(parent_id, system_id_filter):
            abort(403)
        if managed_user_filter is not None and not parent_has_access_to_child(parent_id, managed_user_filter):
            abort(403)

    if (
        '/mappings/' in request.path
        or request.path.endswith('/mappings/add')
        or request.path.endswith('/mappings/connect')
    ):
        linked_system_id = None
        try:
            if request.form and request.form.get('system_id'):
                linked_system_id = str(request.form.get('system_id')).strip()
            elif request.is_json and request.json and request.json.get('system_id'):
                linked_system_id = str(request.json.get('system_id')).strip()
        except Exception:
            pass
        if linked_system_id and not parent_has_access_to_device(parent_id, linked_system_id):
            abort(403)

    if request.path == '/api/user/create' and request.method == 'POST':
        household_raw = None
        if request.is_json and request.json:
            household_raw = request.json.get('household_id')
        elif request.form:
            household_raw = request.form.get('household_id')
        if household_raw is not None:
            try:
                household_id = int(household_raw)
                if household_id not in get_parent_household_ids(parent_id):
                    abort(403)
            except (ValueError, TypeError):
                pass


app.register_blueprint(ui_auth_bp)
app.register_blueprint(ui_dashboard_bp)
app.register_blueprint(ui_schedule_bp)
app.register_blueprint(ui_apparmor_bp)
app.register_blueprint(ui_spa_bp)
app.register_blueprint(api_devices_bp)
app.register_blueprint(api_users_bp)
app.register_blueprint(api_schedule_bp)
app.register_blueprint(api_blocklists_bp)
app.register_blueprint(api_time_bp)
app.register_blueprint(api_tasks_bp)
app.register_blueprint(api_alerts_bp)
app.register_blueprint(api_pairing_bp)
app.register_blueprint(api_dashboard_bp)
app.register_blueprint(api_installed_apps_bp, url_prefix='/api')
app.register_blueprint(api_approvals_bp)
app.register_blueprint(api_android_device_policy_bp)
app.register_blueprint(api_linux_device_policy_bp)
app.register_blueprint(api_nintendo_bp)
app.register_blueprint(api_xbox_bp)
app.register_blueprint(api_screenshots_bp)
app.register_blueprint(api_youtube_bp)
app.register_blueprint(api_hardware_baseline_bp)
app.register_blueprint(api_windows_laps_bp)
csrf.exempt(api_youtube_bp)
app.register_blueprint(api_access_requests_bp)
csrf.exempt(api_access_requests_bp)
app.register_blueprint(sharing_api_bp)
app.register_blueprint(api_session_bp)
app.register_blueprint(api_ai_bp)
csrf.exempt(api_ai_bp)
app.register_blueprint(websocket_bp)


# Register WebSocket endpoint via Flask-Sock
sock.route('/ws')(ws_agent_handler)


def fallback_handler(error, endpoint, values):
    """Fallback handler to seamlessly map unqualified url_for to modular Blueprint endpoints."""
    if '.' not in endpoint:
        for bp_name in app.blueprints:
            bp_endpoint = f"{bp_name}.{endpoint}"
            try:
                return url_for(bp_endpoint, **values)
            except Exception:
                continue
    raise error


app.url_build_error_handlers.append(fallback_handler)


@app.route('/sw.js')
def service_worker():
    """Serve the service worker from site root for full-scope PWA install."""
    response = app.make_response(app.send_static_file('sw.js'))
    response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    response.headers['Service-Worker-Allowed'] = '/'
    return response


def _expected_schema_tables():
    return set(db.metadata.tables.keys())


def _create_missing_tables(missing_tables):
    if not missing_tables:
        return
    _LOGGER.warning(
        "Creating missing database tables: %s",
        ", ".join(sorted(missing_tables)),
    )
    try:
        db.create_all()
    except Exception as exc:
        _LOGGER.warning(
            "Could not create missing database tables via create_all(): %s",
            exc,
        )


def _repair_stamped_empty_database(migrations_dir, migrations_exist):
    """Rebuild a database that only has Alembic metadata and no model tables."""
    from sqlalchemy import text
    from flask_migrate import upgrade

    _LOGGER.warning(
        "Database has Alembic revision metadata but no schema tables; "
        "re-running migrations from scratch."
    )
    db.session.execute(text('DELETE FROM alembic_version'))
    db.session.commit()
    if migrations_exist:
        upgrade(directory=migrations_dir)
    else:
        db.create_all()


def _apply_database_schema(migrations_dir):
    """Bring the connected database schema up to date without wiping existing data."""
    from sqlalchemy import inspect as sqla_inspect
    from flask_migrate import stamp, upgrade

    migrations_exist = os.path.isdir(migrations_dir)
    inspector = sqla_inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    expected_tables = _expected_schema_tables()
    schema_tables = expected_tables & existing_tables

    if 'alembic_version' in existing_tables and not schema_tables:
        _repair_stamped_empty_database(migrations_dir, migrations_exist)
    elif not schema_tables:
        if migrations_exist:
            try:
                upgrade(directory=migrations_dir)
            except Exception as exc:
                _LOGGER.info("Database upgrade() failed or database is new: %s", exc)
                db.create_all()
                try:
                    stamp(directory=migrations_dir)
                    _LOGGER.info("Database stamped as head revision after create_all()")
                except Exception as stamp_err:
                    _LOGGER.warning("Could not stamp database: %s", stamp_err)
        else:
            _LOGGER.info("Migrations directory missing. Creating database tables directly...")
            db.create_all()
    elif migrations_exist:
        try:
            upgrade(directory=migrations_dir)
        except Exception as exc:
            _LOGGER.warning("Database upgrade() failed: %s", exc)

    existing_tables = set(sqla_inspect(db.engine).get_table_names())
    _create_missing_tables(expected_tables - existing_tables)


def _ensure_database_schema(migrations_dir):
    """Ensure model tables exist, repairing stamped-but-empty databases."""
    _apply_database_schema(migrations_dir)


def _init_admin_password():
    try:
        if not Settings.get_value('admin_password_hash', None) and not Settings.get_value('admin_password', None):
            Settings.set_admin_password('admin')
            _LOGGER.info("Admin password initialized")
    except Exception as exc:
        _LOGGER.warning("Warning: Could not initialize admin password: %s", exc)


def _backfill_household_multitenancy():
    from src.models import Household, ManagedUser, AgentDevice, ParentAccount, HouseholdParentMembership
    import secrets
    try:
        # 1. Ensure Default Household exists
        default_hh = Household.query.get(1)
        if not default_hh:
            default_hh = Household(id=1, name="Default Household", enrollment_token=secrets.token_hex(32))
            db.session.add(default_hh)
            db.session.commit()
            _LOGGER.info("Default Household (ID: 1) created.")
        else:
            if not default_hh.enrollment_token:
                default_hh.enrollment_token = secrets.token_hex(32)
                db.session.commit()

        # 2. Backfill ManagedUsers without household_id
        unassigned_users = ManagedUser.query.filter(ManagedUser.household_id == None).all()
        if unassigned_users:
            for user in unassigned_users:
                user.household_id = 1
            db.session.commit()
            _LOGGER.info("Backfilled %d ManagedUser(s) to Default Household.", len(unassigned_users))

        # 3. Backfill AgentDevices without household_id
        unassigned_devices = AgentDevice.query.filter(AgentDevice.household_id == None).all()
        if unassigned_devices:
            for device in unassigned_devices:
                device.household_id = 1
            db.session.commit()
            _LOGGER.info("Backfilled %d AgentDevice(s) to Default Household.", len(unassigned_devices))

        # 4. Map the local legacy 'admin' parent account if not using OIDC
        admin_parent = ParentAccount.query.filter_by(email='admin@local').first()
        if not admin_parent:
            admin_parent = ParentAccount(
                email='admin@local',
                name='Local Admin',
                oidc_sub=None
            )
            db.session.add(admin_parent)
            db.session.commit()
            _LOGGER.info("Local Admin ParentAccount created.")

        # Ensure the admin has owner membership in the Default Household
        membership = HouseholdParentMembership.query.filter_by(
            household_id=1,
            parent_account_id=admin_parent.id
        ).first()
        if not membership:
            membership = HouseholdParentMembership(
                household_id=1,
                parent_account_id=admin_parent.id,
                permissions_json={"is_owner": True}
            )
            db.session.add(membership)
            db.session.commit()
            _LOGGER.info("Local Admin assigned as owner of Default Household.")

        # 5. Pre-seed and map OIDC admin emails from ALLOWED_OIDC_ADMINS to the Default Household
        allowed_admins_str = os.environ.get('ALLOWED_OIDC_ADMINS', '')
        if allowed_admins_str:
            emails = [e.strip().lower() for e in allowed_admins_str.split(',') if e.strip()]
            for email in emails:
                if email == 'admin@local':
                    continue
                parent = ParentAccount.query.filter_by(email=email).first()
                if not parent:
                    parent = ParentAccount(
                        email=email,
                        name=email.split('@')[0].capitalize(),
                        oidc_sub=None
                    )
                    db.session.add(parent)
                    db.session.commit()
                    _LOGGER.info("Seeded OIDC Admin ParentAccount for %s", email)

                membership = HouseholdParentMembership.query.filter_by(
                    household_id=1,
                    parent_account_id=parent.id
                ).first()
                if not membership:
                    membership = HouseholdParentMembership(
                        household_id=1,
                        parent_account_id=parent.id,
                        permissions_json={"is_owner": True}
                    )
                    db.session.add(membership)
                    db.session.commit()
                    _LOGGER.info("OIDC Admin %s assigned as owner of Default Household.", email)

    except Exception as exc:
        db.session.rollback()
        _LOGGER.warning("Warning: Failed to backfill household multitenancy: %s", exc)


def _runtime_init_lock_path():
    os.makedirs(app.instance_path, exist_ok=True)
    return os.path.join(app.instance_path, '.runtime_init.lock')


def _sync_postgres_sequences():
    """Sync PostgreSQL sequence generators to match the maximum ID in each table."""
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    is_pg = db_uri.startswith('postgresql://') or db_uri.startswith('postgresql+psycopg2://')
    if not is_pg:
        return

    _LOGGER.info("Syncing PostgreSQL sequences...")
    from sqlalchemy import text
    try:
        for table_name, table in db.metadata.tables.items():
            for col in table.primary_key.columns:
                is_int = False
                try:
                    is_int = col.type.python_type is int
                except Exception:
                    pass

                if is_int:
                    col_name = col.name
                    seq_query = text(f"SELECT pg_get_serial_sequence('{table_name}', '{col_name}')")
                    seq_name = db.session.execute(seq_query).scalar()
                    if seq_name:
                        sync_query = text(
                            f"SELECT setval('{seq_name}', COALESCE(MAX({col_name}), 1), "
                            f"CASE WHEN MAX({col_name}) IS NULL THEN false ELSE true END) "
                            f"FROM {table_name}"
                        )
                        db.session.execute(sync_query)
        db.session.commit()
        _LOGGER.info("Successfully synced PostgreSQL sequences.")
    except Exception as exc:
        db.session.rollback()
        _LOGGER.warning("Warning: Could not sync PostgreSQL sequences: %s", exc)


def _initialize_database():
    """Initialize or upgrade the database schema using a cross-process file lock."""
    from flask_migrate import stamp

    migrations_dir = os.path.join(app.root_path, 'migrations')
    migrations_exist = os.path.isdir(migrations_dir)
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    is_pg = db_uri.startswith('postgresql://') or db_uri.startswith('postgresql+psycopg2://')

    with open(_runtime_init_lock_path(), 'w', encoding='utf-8') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            sqlite_migrated = False
            if is_pg:
                possible_sqlite_paths = [
                    os.path.join(app.instance_path, 'timekpr.db'),
                    os.path.join(app.root_path, 'timekpr.db'),
                    'instance/timekpr.db',
                    'timekpr.db',
                ]
                for path in possible_sqlite_paths:
                    if os.path.exists(path):
                        _LOGGER.info("Found SQLite DB at %s. Initiating migration...", path)
                        db.create_all()
                        try:
                            migrate_data_sqlite_to_pg(path)
                            sqlite_migrated = True
                            if migrations_exist:
                                try:
                                    stamp(directory=migrations_dir)
                                    _LOGGER.info("Stamped PostgreSQL database migration state as head.")
                                except Exception as stamp_err:
                                    _LOGGER.warning("Warning: Failed to stamp PostgreSQL: %s", stamp_err)
                        except Exception as mig_err:
                            _LOGGER.error("Error during SQLite to PostgreSQL migration: %s", mig_err)
                        break

            if not sqlite_migrated:
                if migrations_exist:
                    _LOGGER.info("Ensuring database is up to date (dir: %s)...", migrations_dir)
                _apply_database_schema(migrations_dir)

            _sync_postgres_sequences()
            _init_admin_password()
            _backfill_household_multitenancy()
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def migrate_data_sqlite_to_pg(sqlite_db_path):
    """Migrates all data from an existing SQLite database to the current PostgreSQL database."""
    from sqlalchemy import create_engine, select
    from sqlalchemy import inspect as sqla_inspect
    from src.models import (
        Settings as DbSettings,
        AgentDevice as DbAgentDevice,
        ManagedUser as DbManagedUser,
        ManagedUserDeviceMap as DbManagedUserDeviceMap,
        UserWeeklySchedule as DbUserWeeklySchedule,
        UserDailyTimeInterval as DbUserDailyTimeInterval,
        UserTimeUsage as DbUserTimeUsage,
        BlocklistSource as DbBlocklistSource,
        BlocklistDomain as DbBlocklistDomain,
        ManagedUserBlocklistAssignment as DbManagedUserBlocklistAssignment,
        AgentAlert as DbAgentAlert,
        AppArmorRule as DbAppArmorRule,
        AppUsageHistory as DbAppUsageHistory
    )
    
    _LOGGER.info(f"Starting database migration from SQLite ({sqlite_db_path}) to PostgreSQL...")
    
    sqlite_uri = f"sqlite:///{sqlite_db_path}"
    sqlite_engine = create_engine(sqlite_uri)
    
    try:
        sqlite_inspector = sqla_inspect(sqlite_engine)
        sqlite_tables = sqlite_inspector.get_table_names()
        if not sqlite_tables:
            _LOGGER.info("SQLite database is empty or has no tables. Skipping data migration.")
            sqlite_engine.dispose()
            return
            
        models_to_migrate = [
            DbSettings,
            DbAgentDevice,
            DbManagedUser,
            DbManagedUserDeviceMap,
            DbUserWeeklySchedule,
            DbUserDailyTimeInterval,
            DbUserTimeUsage,
            DbBlocklistSource,
            DbBlockDomain := DbBlocklistDomain,
            DbManagedUserBlocklistAssignment,
            DbAgentAlert,
            DbAppArmorRule,
            DbAppUsageHistory
        ]
        
        with db.session.begin():
            for model in models_to_migrate:
                table_name = model.__tablename__
                if table_name not in sqlite_tables:
                    _LOGGER.info(f"Table '{table_name}' does not exist in SQLite database. Skipping.")
                    continue
                    
                _LOGGER.info(f"Migrating table '{table_name}'...")
                
                batch_size = 10000
                total_inserted = 0
                
                with sqlite_engine.connect() as sqlite_conn:
                    columns = [c for c in model.__table__.columns]
                    query = select(*columns)
                    result = sqlite_conn.execute(query)
                    
                    while True:
                        rows_chunk = result.fetchmany(batch_size)
                        if not rows_chunk:
                            break
                        
                        rows = [dict(row._mapping) for row in rows_chunk]
                        db.session.execute(model.__table__.insert(), rows)
                        total_inserted += len(rows)
                        
                if total_inserted == 0:
                    _LOGGER.info(f"Table '{table_name}' is empty. Skipping.")
                else:
                    _LOGGER.info(f"Successfully migrated {total_inserted} rows for '{table_name}'.")
                
        _LOGGER.info("Database migration completed successfully!")
        
        try:
            sqlite_engine.dispose()
            if os.path.exists(sqlite_db_path):
                os.remove(sqlite_db_path)
                _LOGGER.info(f"Deleted old SQLite database file: {sqlite_db_path}")
        except Exception as e:
            _LOGGER.warning(f"Warning: Failed to delete old SQLite database file: {e}")
            
    except Exception as e:
        _LOGGER.error(f"CRITICAL: SQLite to PostgreSQL migration failed: {e}")
        db.session.rollback()
        sqlite_engine.dispose()
        raise e


def initialize_runtime(start_background_tasks=False):
    """Initialize the database and start background tasks."""
    _LOGGER.info("Runtime initialization started")
    if os.environ.get('TESTING'):
        return

    with _runtime_init_lock:
        with app.app_context():
            _initialize_database()
            from src.agent.pending_commands import backfill_pending_factory_reset_commands

            backfilled = backfill_pending_factory_reset_commands()
            if backfilled:
                _LOGGER.info('Backfilled %d legacy pending factory reset command(s)', backfilled)
        RUNTIME_STATE['initialized'] = True
        _LOGGER.info("Runtime initialization completed")

    if start_background_tasks:
        task_manager.start()
        _LOGGER.info("Background tasks started automatically")


def _should_initialize_on_import():
    import sys
    if os.environ.get('TESTING'):
        return False
    # Do not initialize when running via flask command (CLI)
    if 'flask' in sys.argv[0] or any(arg in sys.argv for arg in ('db', 'migrate', 'upgrade', 'init')):
        return False
    # app.py executed directly handles initialization in __main__.
    if __name__ == '__main__':
        return False
    return True


if _should_initialize_on_import():
    initialize_runtime(start_background_tasks=_env_flag_enabled('TIMEKPR_ENABLE_BACKGROUND_TASKS'))

if __name__ == '__main__':
    debug = bool(int(os.environ.get("DEBUG", "0")))
    use_reloader = debug
    if not use_reloader or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        initialize_runtime(start_background_tasks=True)
    app.run(host='0.0.0.0', port=5000, debug=debug, use_reloader=use_reloader)
