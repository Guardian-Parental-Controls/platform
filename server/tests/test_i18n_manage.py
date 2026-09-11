"""Tests for scripts/i18n management utilities."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS_I18N = Path(__file__).resolve().parents[2] / 'scripts' / 'i18n'
sys.path.insert(0, str(SCRIPTS_I18N))
lib = importlib.import_module('lib')


def test_add_string_with_placeholders(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n'
    en_dir = i18n_root / 'en'
    en_dir.mkdir(parents=True)
    (en_dir / 'server.yaml').write_text(
        'meta:\n  locale: en\n  label: English\nflash:\n  common:\n    ok: OK\n',
        encoding='utf-8',
    )
    monkeypatch.setattr(lib, 'I18N_ROOT', i18n_root)

    lib.add_string('server', 'flash.users.greeting', 'Hello {username}', propagate=False)

    data = lib.load_catalog('en', 'server')
    assert lib.get_nested(data, ['flash', 'users', 'greeting']) == 'Hello {username}'
    assert lib.extract_placeholders('Hello {username}') == frozenset({'username'})


def test_add_locale_copies_catalogs(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n'
    en_dir = i18n_root / 'en'
    en_dir.mkdir(parents=True)
    (en_dir / 'server.yaml').write_text(
        'meta:\n  locale: en\n  label: English\nnav:\n  dashboard: Home\n',
        encoding='utf-8',
    )
    (en_dir / 'agent.yaml').write_text(
        'meta:\n  locale: en\n  label: English\nstrings:\n  app_name: Guardian\n',
        encoding='utf-8',
    )
    monkeypatch.setattr(lib, 'I18N_ROOT', i18n_root)

    lib.add_locale('fr', 'Français', services=('server', 'agent'))

    fr_server = lib.load_catalog('fr', 'server')
    assert fr_server['meta']['locale'] == 'fr'
    assert fr_server['meta']['label'] == 'Français'
    assert fr_server['nav']['dashboard'] == 'Home'
    assert lib.load_catalog('fr', 'agent')['strings']['app_name'] == 'Guardian'


def test_validate_placeholder_mismatch(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n'
    for locale, body in {
        'en': 'meta:\n  locale: en\n  label: English\nmsg:\n  greet: Hello {name}\n',
        'fr': 'meta:\n  locale: fr\n  label: French\nmsg:\n  greet: Bonjour\n',
    }.items():
        (i18n_root / locale).mkdir(parents=True)
        (i18n_root / locale / 'server.yaml').write_text(body, encoding='utf-8')
    monkeypatch.setattr(lib, 'I18N_ROOT', i18n_root)

    errors = lib.validate_catalogs()
    assert any('placeholder mismatch' in error for error in errors)


def test_bundle_android_writes_strings_xml(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n' / 'en'
    i18n_root.mkdir(parents=True)
    (i18n_root / 'agent.yaml').write_text(
        'meta:\n  locale: en\n  label: English\nstrings:\n  app_name: Guardian Agent\n',
        encoding='utf-8',
    )
    repo_root = tmp_path / 'repo'
    android_values = repo_root / 'android-agent' / 'app' / 'src' / 'main' / 'res' / 'values'
    monkeypatch.setattr(lib, 'I18N_ROOT', tmp_path / 'i18n')
    monkeypatch.setattr(lib, 'REPO_ROOT', repo_root)

    paths = lib.bundle_android()
    assert len(paths) == 1
    content = paths[0].read_text(encoding='utf-8')
    assert '<string name="app_name">Guardian Agent</string>' in content


def test_bundle_overlay_writes_js(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n' / 'en'
    i18n_root.mkdir(parents=True)
    (i18n_root / 'agent.yaml').write_text(
        'meta:\n  locale: en\n  label: English\n'
        'overlay:\n  teen:\n    sleep:\n      title: Sleep\n      desc: Rest\n      note: Note\n      target: Device\n'
        'overlay_ui:\n  brand_default: Guardian Space\n',
        encoding='utf-8',
    )
    repo_root = tmp_path / 'repo'
    overlay_dir = repo_root / 'agent' / 'overlay_resources'
    overlay_dir.mkdir(parents=True)
    (overlay_dir / 'blockedv2.html').write_text('<html></html>', encoding='utf-8')
    monkeypatch.setattr(lib, 'I18N_ROOT', tmp_path / 'i18n')
    monkeypatch.setattr(lib, 'REPO_ROOT', repo_root)
    monkeypatch.setattr(lib, 'OVERLAY_RESOURCE_DIRS', (overlay_dir,))

    paths = lib.bundle_overlay()
    js_files = [p for p in paths if p.suffix == '.js']
    assert js_files
    assert 'guardianOverlayI18n' in js_files[0].read_text(encoding='utf-8')


def test_bundle_extension_writes_messages_json(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n' / 'en'
    i18n_root.mkdir(parents=True)
    (i18n_root / 'extension.yaml').write_text(
        'meta:\n  locale: en\n  label: English\n'
        'messages:\n  extensionName:\n    message: Guardian\n',
        encoding='utf-8',
    )
    (i18n_root / 'agent.yaml').write_text(
        'meta:\n  locale: en\n  label: English\n'
        'overlay:\n  teen:\n    sleep:\n      title: Sleep\n      desc: Rest\n      note: Note\n      target: Device\n'
        'overlay_ui:\n  brand_default: Guardian Space\n',
        encoding='utf-8',
    )
    repo_root = tmp_path / 'repo'
    overlay_dir = repo_root / 'agent' / 'overlay_resources'
    extension_dir = repo_root / 'extension'
    overlay_dir.mkdir(parents=True)
    extension_dir.mkdir(parents=True)
    (overlay_dir / 'blockedv2.html').write_text('<html></html>', encoding='utf-8')
    monkeypatch.setattr(lib, 'I18N_ROOT', tmp_path / 'i18n')
    monkeypatch.setattr(lib, 'REPO_ROOT', repo_root)
    monkeypatch.setattr(lib, 'OVERLAY_RESOURCE_DIRS', (overlay_dir, extension_dir))

    lib.bundle_extension()
    messages_path = extension_dir / '_locales' / 'en' / 'messages.json'
    assert messages_path.is_file()
    payload = json.loads(messages_path.read_text(encoding='utf-8'))
    assert payload['extensionName']['message'] == 'Guardian'
    assert (extension_dir / 'overlay-i18n.en.js').is_file()


def test_bundle_rust_writes_json(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n' / 'en'
    i18n_root.mkdir(parents=True)
    (i18n_root / 'agent.yaml').write_text(
        'meta:\n  locale: en\n  label: English\n'
        'desktop:\n  domain_blocked_title: Website Blocked\n',
        encoding='utf-8',
    )
    repo_root = tmp_path / 'repo'
    monkeypatch.setattr(lib, 'I18N_ROOT', tmp_path / 'i18n')
    monkeypatch.setattr(lib, 'RUST_I18N_DIR', repo_root / 'agent' / 'resources' / 'i18n')
    monkeypatch.setattr(lib, 'REPO_ROOT', repo_root)

    paths = lib.bundle_rust()
    assert any(p.name == 'en.json' for p in paths)
    payload = json.loads((repo_root / 'agent' / 'resources' / 'i18n' / 'en.json').read_text())
    assert payload['desktop']['domain_blocked_title'] == 'Website Blocked'


def test_manage_cli_validate(tmp_path, monkeypatch):
    i18n_root = tmp_path / 'i18n'
    en_dir = i18n_root / 'en'
    en_dir.mkdir(parents=True)
    for service in ('server', 'agent', 'extension'):
        (en_dir / f'{service}.yaml').write_text(
            'meta:\n  locale: en\n  label: English\n',
            encoding='utf-8',
        )
    monkeypatch.setattr(lib, 'I18N_ROOT', i18n_root)
    assert lib.validate_catalogs() == []
