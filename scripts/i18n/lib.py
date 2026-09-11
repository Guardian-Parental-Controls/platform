"""Shared utilities for Guardian i18n catalog management."""

from __future__ import annotations

import os
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterator

import yaml

def _env_path(name: str, default: Path) -> Path:
    raw = (os.environ.get(name) or '').strip()
    return Path(raw).expanduser().resolve() if raw else default


REPO_ROOT = _env_path('GUARDIAN_PRODUCT_ROOT', Path(__file__).resolve().parents[2])
I18N_ROOT = _env_path('GUARDIAN_I18N_ROOT', REPO_ROOT / 'i18n')
SERVICES = ('server', 'agent', 'extension')
DEFAULT_LOCALE = 'en'
PLACEHOLDER_RE = re.compile(r'\{(\w+)\}')
TODO_PREFIX = '[TODO] '


def catalog_path(locale: str, service: str) -> Path:
    return I18N_ROOT / locale / f'{service}.yaml'


def discover_locales(service: str = 'server') -> list[str]:
    if not I18N_ROOT.is_dir():
        return [DEFAULT_LOCALE]
    locales = sorted(
        entry.name
        for entry in I18N_ROOT.iterdir()
        if entry.is_dir() and (entry / f'{service}.yaml').is_file()
    )
    return locales or [DEFAULT_LOCALE]


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open('r', encoding='utf-8') as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f'Expected mapping in {path}')
    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        yaml.safe_dump(
            data,
            handle,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
            width=120,
        )


def load_catalog(locale: str, service: str) -> dict[str, Any]:
    return load_yaml(catalog_path(locale, service))


def save_catalog(locale: str, service: str, data: dict[str, Any]) -> None:
    save_yaml(catalog_path(locale, service), data)


def parse_key(key: str) -> list[str]:
    parts = [part.strip() for part in key.split('.') if part.strip()]
    if not parts:
        raise ValueError('Key must be a non-empty dot path (e.g. flash.auth.login_required)')
    return parts


def get_nested(data: dict[str, Any], key_parts: list[str]) -> Any:
    current: Any = data
    for part in key_parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def set_nested(data: dict[str, Any], key_parts: list[str], value: Any) -> None:
    current = data
    for part in key_parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[key_parts[-1]] = value


def delete_nested(data: dict[str, Any], key_parts: list[str]) -> bool:
    current: Any = data
    parents: list[tuple[dict[str, Any], str]] = []
    for part in key_parts:
        if not isinstance(current, dict) or part not in current:
            return False
        parents.append((current, part))
        current = current[part]
    parents[-1][0].pop(parents[-1][1], None)
    return True


def iter_leaf_strings(
    node: Any,
    prefix: str = '',
) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == 'meta':
                continue
            path = f'{prefix}.{key}' if prefix else key
            yield from iter_leaf_strings(value, path)
    elif isinstance(node, str):
        if prefix:
            yield prefix, node


def flatten_strings(data: dict[str, Any], skip_meta: bool = True) -> dict[str, str]:
    flat: dict[str, str] = {}
    for key, value in iter_leaf_strings(data):
        if skip_meta and key == 'meta':
            continue
        flat[key] = value
    return flat


def extract_placeholders(text: str) -> frozenset[str]:
    return frozenset(PLACEHOLDER_RE.findall(text or ''))


def validate_locale_code(code: str) -> str:
    normalized = (code or '').strip().lower().replace('_', '-')
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]{2,8})*', normalized):
        raise ValueError(
            f'Invalid locale code "{code}". Use ISO 639-1 (e.g. en, fr, pt-br).'
        )
    return normalized


def validate_service(service: str) -> str:
    normalized = (service or '').strip().lower()
    if normalized not in SERVICES:
        raise ValueError(f'Unknown service "{service}". Choose from: {", ".join(SERVICES)}')
    return normalized


def add_locale(
    locale: str,
    label: str,
    *,
    copy_from: str = DEFAULT_LOCALE,
    services: tuple[str, ...] = SERVICES,
) -> list[Path]:
    locale = validate_locale_code(locale)
    copy_from = validate_locale_code(copy_from)
    if locale == copy_from:
        raise ValueError('New locale must differ from copy-from locale')

    target_dir = I18N_ROOT / locale
    if target_dir.exists():
        raise FileExistsError(f'Locale directory already exists: {target_dir}')

    created: list[Path] = []
    target_dir.mkdir(parents=True)
    for service in services:
        service = validate_service(service)
        source_path = catalog_path(copy_from, service)
        if not source_path.is_file():
            if service == 'server' and copy_from == DEFAULT_LOCALE:
                raise FileNotFoundError(f'Missing canonical catalog: {source_path}')
            continue
        data = load_yaml(source_path)
        meta = data.setdefault('meta', {})
        meta['locale'] = locale.split('-', 1)[0]
        meta['label'] = label
        dest = catalog_path(locale, service)
        save_yaml(dest, data)
        created.append(dest)
    return created


def add_string(
    service: str,
    key: str,
    value: str,
    *,
    locale: str = DEFAULT_LOCALE,
    overwrite: bool = False,
    propagate: bool = True,
    todo_other_locales: bool = True,
) -> list[tuple[str, str]]:
    service = validate_service(service)
    locale = validate_locale_code(locale)
    key_parts = parse_key(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Value must be a non-empty string')

    updated: list[tuple[str, str]] = []

    def _apply(target_locale: str, target_value: str) -> None:
        path = catalog_path(target_locale, service)
        if not path.is_file():
            raise FileNotFoundError(f'Missing catalog for {target_locale}/{service}: {path}')
        data = load_yaml(path)
        existing = get_nested(data, key_parts)
        if existing is not None and not overwrite:
            raise FileExistsError(
                f'Key "{key}" already exists in {target_locale}/{service}.yaml (use --force)'
            )
        set_nested(data, key_parts, target_value)
        save_yaml(path, data)
        updated.append((target_locale, key))

    _apply(locale, value)

    if propagate:
        placeholders = extract_placeholders(value)
        for other in discover_locales(service):
            if other == locale:
                continue
            other_path = catalog_path(other, service)
            if not other_path.is_file():
                continue
            other_data = load_yaml(other_path)
            if get_nested(other_data, key_parts) is not None and not overwrite:
                continue
            if todo_other_locales:
                translated = f'{TODO_PREFIX}{value}'
            else:
                translated = value
            if placeholders:
                missing = placeholders - extract_placeholders(translated)
                if missing:
                    raise ValueError(
                        f'Locale {other} translation must include placeholders: {sorted(missing)}'
                    )
            set_nested(other_data, key_parts, translated)
            save_yaml(other_path, other_data)
            updated.append((other, key))

    return updated


def validate_catalogs(*, strict: bool = False) -> list[str]:
    errors: list[str] = []

    for service in SERVICES:
        canonical_path = catalog_path(DEFAULT_LOCALE, service)
        if not canonical_path.is_file():
            if service == 'server':
                errors.append(f'Missing canonical catalog: {canonical_path}')
            continue

        canonical = load_yaml(canonical_path)
        canonical_leaves = dict(iter_leaf_strings(canonical))

        for locale in discover_locales(service):
            path = catalog_path(locale, service)
            try:
                data = load_yaml(path)
            except ValueError as exc:
                errors.append(str(exc))
                continue

            meta = data.get('meta') or {}
            if not meta.get('locale'):
                errors.append(f'{path}: meta.locale is required')
            if not meta.get('label'):
                errors.append(f'{path}: meta.label is required')

            locale_leaves = dict(iter_leaf_strings(data))
            if locale == DEFAULT_LOCALE:
                continue

            missing = sorted(set(canonical_leaves) - set(locale_leaves))
            extra = sorted(set(locale_leaves) - set(canonical_leaves))
            if missing:
                msg = f'{path}: missing {len(missing)} key(s) vs {DEFAULT_LOCALE} (e.g. {missing[:3]})'
                errors.append(msg)
            if extra:
                errors.append(f'{path}: {len(extra)} unknown key(s) vs {DEFAULT_LOCALE} (e.g. {extra[:3]})')

            for key, en_value in canonical_leaves.items():
                localized = locale_leaves.get(key)
                if localized is None:
                    continue
                en_ph = extract_placeholders(en_value)
                loc_ph = extract_placeholders(localized)
                if en_ph != loc_ph:
                    errors.append(
                        f'{path}: placeholder mismatch for "{key}" '
                        f'(en={sorted(en_ph)}, {locale}={sorted(loc_ph)})'
                    )
                if strict and localized.startswith(TODO_PREFIX):
                    errors.append(f'{path}: untranslated TODO string for "{key}"')

    return errors


def android_values_dir(locale: str) -> Path:
    code = locale.split('-', 1)[0]
    android_root = (
        REPO_ROOT / 'agent-android'
        if (REPO_ROOT / 'agent-android').exists()
        else REPO_ROOT / 'android-agent'
    )
    if code == DEFAULT_LOCALE:
        return android_root / 'app' / 'src' / 'main' / 'res' / 'values'
    return android_root / 'app' / 'src' / 'main' / 'res' / f'values-{code}'


def android_string_name(key: str) -> str:
    return key.replace('.', '_').replace('-', '_')


def bundle_android(*, dry_run: bool = False) -> list[Path]:
    written: list[Path] = []
    for locale in discover_locales('agent'):
        data = load_catalog(locale, 'agent')
        strings = data.get('strings')
        if not isinstance(strings, dict) or not strings:
            continue

        lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<resources>',
        ]
        for key, value in strings.items():
            if not isinstance(value, str):
                continue
            name = android_string_name(key)
            escaped = (
                value.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace("'", "\\'")
                .replace('"', '&quot;')
            )
            lines.append(f'    <string name="{name}">{escaped}</string>')
        lines.append('</resources>')
        lines.append('')

        out_dir = android_values_dir(locale)
        out_path = out_dir / 'strings.xml'
        if dry_run:
            written.append(out_path)
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path.write_text('\n'.join(lines), encoding='utf-8')
        written.append(out_path)
    return written


def bundle_extension(*, dry_run: bool = False) -> list[Path]:
    """Generate Chrome _locales and sync overlay assets into extension/."""
    written: list[Path] = []
    extension_root = REPO_ROOT / 'extension'
    for locale in discover_locales('extension'):
        data = load_catalog(locale, 'extension')
        messages = data.get('messages')
        if not isinstance(messages, dict) or not messages:
            continue

        chrome_locale = locale if locale != DEFAULT_LOCALE else 'en'
        locale_dir = extension_root / '_locales' / chrome_locale
        out_path = locale_dir / 'messages.json'

        payload: dict[str, dict[str, str]] = {}
        for key, value in messages.items():
            if isinstance(value, dict):
                payload[key] = value
            elif isinstance(value, str):
                payload[key] = {'message': value}

        if dry_run:
            written.append(out_path)
            continue

        locale_dir.mkdir(parents=True, exist_ok=True)
        import json

        out_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8',
        )
        written.append(out_path)

    written.extend(bundle_overlay(dry_run=dry_run))
    return written


def bundle_server(*, dry_run: bool = False) -> list[Path]:
    """Verify server catalogs and stage i18n into the server tree for Docker builds."""
    errors = validate_catalogs()
    if errors:
        raise RuntimeError('i18n validation failed:\n' + '\n'.join(errors))

    stage_root = REPO_ROOT / 'server' / 'i18n'
    written: list[Path] = []
    if dry_run:
        for locale in discover_locales('server'):
            written.append(stage_root / locale / 'server.yaml')
        return written

    if stage_root.exists():
        shutil.rmtree(stage_root)
    shutil.copytree(I18N_ROOT, stage_root)
    for path in stage_root.rglob('*.yaml'):
        written.append(path)
    return written


def list_missing_keys(locale: str, service: str = 'server') -> list[str]:
    locale = validate_locale_code(locale)
    service = validate_service(service)
    canonical = dict(iter_leaf_strings(load_catalog(DEFAULT_LOCALE, service)))
    localized = dict(iter_leaf_strings(load_catalog(locale, service)))
    return sorted(set(canonical) - set(localized))


OVERLAY_RESOURCE_DIRS = (
    REPO_ROOT / 'agent-linux' / 'overlay_resources',
    REPO_ROOT / 'agent-windows' / 'overlay_resources',
    REPO_ROOT / 'agent-common' / 'overlay_resources',
    REPO_ROOT / 'extension',
    REPO_ROOT / 'agent-android' / 'app' / 'src' / 'main' / 'assets',
    REPO_ROOT / 'android-agent' / 'app' / 'src' / 'main' / 'assets',
)

BLOCKED_HTML_NAME = 'blockedv2.html'
RUST_I18N_DIR = REPO_ROOT / 'agent-common' / 'resources' / 'i18n'


def _js_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_overlay_js(locale: str, catalog: dict[str, Any]) -> str:
    overlay = catalog.get('overlay') or {}
    ui = catalog.get('overlay_ui') or {}
    breathe_states = [
        {
            'text': ui.get('breathe_in_text', 'Breathe In'),
            'desc': ui.get('breathe_in_desc', ''),
        },
        {
            'text': ui.get('breathe_hold_text', 'Hold'),
            'desc': ui.get('breathe_hold_desc', ''),
        },
        {
            'text': ui.get('breathe_out_text', 'Breathe Out'),
            'desc': ui.get('breathe_out_desc', ''),
        },
        {
            'text': ui.get('breathe_rest_text', 'Hold'),
            'desc': ui.get('breathe_rest_desc', ''),
        },
    ]
    payload = {
        'locale': locale,
        'contentMap': overlay,
        'ui': ui,
        'breatheStates': breathe_states,
        'presets': {
            'reading': ui.get('preset_reading', ''),
            'homework': ui.get('preset_homework', ''),
            'five_mins': ui.get('preset_five_mins', ''),
            'chores': ui.get('preset_chores', ''),
        },
    }
    return (
        '/* Generated by scripts/i18n/manage.py bundle --target overlay. Do not edit. */\n'
        '(function () {\n'
        "  'use strict';\n"
        f'  window.guardianOverlayI18n = {json.dumps(payload, ensure_ascii=False, indent=2)};\n'
        '})();\n'
    )


def bundle_overlay(*, dry_run: bool = False) -> list[Path]:
    """Generate overlay-i18n.{locale}.js and sync blockedv2.html to all agent surfaces."""
    written: list[Path] = []
    canonical_html = OVERLAY_RESOURCE_DIRS[0] / BLOCKED_HTML_NAME
    if not canonical_html.is_file():
        raise FileNotFoundError(f'Missing canonical overlay HTML: {canonical_html}')

    js_by_locale: dict[str, str] = {}
    for locale in discover_locales('agent'):
        catalog = load_catalog(locale, 'agent')
        if not catalog.get('overlay'):
            continue
        js_by_locale[locale] = _render_overlay_js(locale, catalog)

    if not js_by_locale:
        raise RuntimeError('No overlay section found in agent.yaml catalogs')

    for target_dir in OVERLAY_RESOURCE_DIRS:
        for locale, js_content in js_by_locale.items():
            out_path = target_dir / f'overlay-i18n.{locale}.js'
            if dry_run:
                written.append(out_path)
                continue
            target_dir.mkdir(parents=True, exist_ok=True)
            out_path.write_text(js_content, encoding='utf-8')
            written.append(out_path)

        html_dest = target_dir / BLOCKED_HTML_NAME
        if target_dir != canonical_html.parent:
            if dry_run:
                written.append(html_dest)
            else:
                shutil.copy2(canonical_html, html_dest)
                written.append(html_dest)

    return written


def bundle_rust(*, dry_run: bool = False) -> list[Path]:
    """Generate agent-common/resources/i18n/{locale}.json from desktop: catalogs."""
    written: list[Path] = []
    locales: list[str] = []

    for locale in discover_locales('agent'):
        catalog = load_catalog(locale, 'agent')
        desktop = catalog.get('desktop')
        if not isinstance(desktop, dict) or not desktop:
            continue
        locales.append(locale)
        out_path = RUST_I18N_DIR / f'{locale}.json'
        if dry_run:
            written.append(out_path)
            continue
        RUST_I18N_DIR.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps({'locale': locale, 'desktop': desktop}, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8',
        )
        written.append(out_path)

    manifest_path = RUST_I18N_DIR / 'manifest.json'
    if locales:
        if dry_run:
            written.append(manifest_path)
        else:
            RUST_I18N_DIR.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps({'locales': locales, 'default': DEFAULT_LOCALE}, indent=2) + '\n',
                encoding='utf-8',
            )
            written.append(manifest_path)

    return written


def bundle_agent(*, dry_run: bool = False) -> list[Path]:
    """Bundle all agent-facing artifacts (Android, overlay HTML/JS, Rust desktop JSON)."""
    written: list[Path] = []
    written.extend(bundle_android(dry_run=dry_run))
    written.extend(bundle_overlay(dry_run=dry_run))
    written.extend(bundle_rust(dry_run=dry_run))
    return written
