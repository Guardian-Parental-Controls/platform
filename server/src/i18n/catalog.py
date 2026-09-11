"""YAML-based translation catalog for the server UI."""

from __future__ import annotations

import html
import logging
import os
import re
from typing import Any

import yaml
from flask import g, has_request_context

_LOGGER = logging.getLogger(__name__)

DEFAULT_LOCALE = 'en'
_CATALOG_CACHE: dict[str, dict] = {}
_LOCALE_LABEL_CACHE: dict[str, str] = {}

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


def _resolve_i18n_root() -> str:
    """Locate the i18n catalog directory (repo root, staged server copy, or env override)."""
    env_root = (os.environ.get('GUARDIAN_I18N_ROOT') or '').strip()
    if env_root and os.path.isdir(env_root):
        return os.path.abspath(env_root)

    module_root = os.path.dirname(__file__)
    candidates = [
        os.path.abspath(os.path.join(module_root, '..', '..', 'i18n')),  # server/i18n (Docker / CI stage)
        os.path.join(os.path.dirname(_REPO_ROOT), 'translations', 'i18n'),  # sibling checkout
        os.path.join(_REPO_ROOT, 'i18n'),  # pre-1.0 transition checkout
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return os.path.join(_REPO_ROOT, 'i18n')


_I18N_ROOT = _resolve_i18n_root()


def discover_locales() -> list[str]:
    """Return sorted locale codes that have a server.yaml catalog."""
    if not os.path.isdir(_I18N_ROOT):
        return [DEFAULT_LOCALE]
    locales = []
    for entry in sorted(os.listdir(_I18N_ROOT)):
        if os.path.isfile(os.path.join(_I18N_ROOT, entry, 'server.yaml')):
            locales.append(entry)
    return locales or [DEFAULT_LOCALE]


SUPPORTED_LOCALES = frozenset(discover_locales())


def _normalize_locale_tag(tag: str) -> str:
    return (tag or '').strip().lower().replace('_', '-')


def _locale_candidates(locale: str) -> list[str]:
    normalized = _normalize_locale_tag(locale)
    if not normalized:
        return [DEFAULT_LOCALE]
    candidates = [normalized]
    if '-' in normalized:
        candidates.append(normalized.split('-', 1)[0])
    return candidates


def _pick_supported_locale(locale: str) -> str | None:
    for candidate in _locale_candidates(locale):
        if candidate in SUPPORTED_LOCALES:
            return candidate
    return None


def _parse_accept_language(header_value: str | None) -> str | None:
    if not header_value:
        return None
    entries: list[tuple[float, str]] = []
    for part in header_value.split(','):
        token = part.strip()
        if not token:
            continue
        pieces = token.split(';', 1)
        tag = _normalize_locale_tag(pieces[0])
        quality = 1.0
        if len(pieces) == 2:
            match = re.match(r'q=([0-9.]+)', pieces[1].strip(), re.IGNORECASE)
            if match:
                try:
                    quality = float(match.group(1))
                except ValueError:
                    quality = 0.0
        entries.append((quality, tag))
    entries.sort(key=lambda item: item[0], reverse=True)
    for _, tag in entries:
        matched = _pick_supported_locale(tag)
        if matched:
            return matched
    return None


def resolve_locale(
    session: dict | None,
    accept_language: str | None,
    household_default: str | None,
) -> str:
    """Resolve active locale: session > Accept-Language > household default > en."""
    session_locale = (session or {}).get('locale')
    if session_locale:
        matched = _pick_supported_locale(str(session_locale))
        if matched:
            return matched

    from_header = _parse_accept_language(accept_language)
    if from_header:
        return from_header

    if household_default:
        matched = _pick_supported_locale(str(household_default))
        if matched:
            return matched

    return DEFAULT_LOCALE


def load_catalog(locale: str) -> dict:
    """Load and cache the server.yaml catalog for a locale."""
    matched = _pick_supported_locale(locale) or DEFAULT_LOCALE
    if matched in _CATALOG_CACHE:
        return _CATALOG_CACHE[matched]

    catalog_path = os.path.join(_I18N_ROOT, matched, 'server.yaml')
    try:
        with open(catalog_path, 'r', encoding='utf-8') as handle:
            catalog = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        _LOGGER.error('Missing translation catalog: %s', catalog_path)
        catalog = {}
    except yaml.YAMLError as exc:
        _LOGGER.error('Failed to parse translation catalog %s: %s', catalog_path, exc)
        catalog = {}

    if matched != DEFAULT_LOCALE and not catalog:
        return load_catalog(DEFAULT_LOCALE)

    _CATALOG_CACHE[matched] = catalog
    meta = catalog.get('meta') or {}
    label = meta.get('label')
    if isinstance(label, str) and label.strip():
        _LOCALE_LABEL_CACHE[matched] = label.strip()
    else:
        _LOCALE_LABEL_CACHE.setdefault(matched, matched)
    return catalog


def locale_label(locale: str) -> str:
    load_catalog(locale)
    return _LOCALE_LABEL_CACHE.get(locale, locale)


def _lookup_key(catalog: dict, key: str) -> Any:
    current: Any = catalog
    for part in key.split('.'):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _missing_key_placeholder(key: str) -> str:
    testing = os.environ.get('TESTING') or os.environ.get('FLASK_DEBUG')
    return f'[missing:{key}]' if testing else key


def _normalize_catalog_text(value: str) -> str:
    """Return plain text from catalog strings (decode accidental HTML entities)."""
    if '&' not in value:
        return value
    return html.unescape(value)


def t(key: str, locale: str | None = None, **kwargs: Any) -> str:
    """Translate a dot-path key with optional format interpolation."""
    active_locale = locale
    if active_locale is None and has_request_context():
        active_locale = getattr(g, 'locale', None)
    active_locale = active_locale or DEFAULT_LOCALE

    catalog = load_catalog(active_locale)
    value = _lookup_key(catalog, key)
    if value is None and active_locale != DEFAULT_LOCALE:
        value = _lookup_key(load_catalog(DEFAULT_LOCALE), key)
    if value is None:
        _LOGGER.warning('Missing translation key: %s (locale=%s)', key, active_locale)
        return _missing_key_placeholder(key)
    if not isinstance(value, str):
        _LOGGER.warning('Translation key is not a string: %s', key)
        return _missing_key_placeholder(key)
    value = _normalize_catalog_text(value)
    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, IndexError, ValueError) as exc:
            _LOGGER.warning('Translation interpolation failed for %s: %s', key, exc)
            return value
    return value


def flash_t(key: str, category: str = 'info', locale: str | None = None, **kwargs: Any) -> None:
    """Flash a translated message."""
    from flask import flash

    flash(t(key, locale=locale, **kwargs), category)


def api_message(key: str, locale: str | None = None, **kwargs: Any) -> str:
    """Translate an API response message (api.* keys)."""
    if not key.startswith('api.'):
        key = f'api.{key}'
    return t(key, locale=locale, **kwargs)


def flatten_for_js(catalog: dict | None = None, prefix: str = 'js') -> dict[str, str]:
    """Flatten the js.* subtree for client-side consumption."""
    source = catalog if catalog is not None else load_catalog(DEFAULT_LOCALE)
    branch = source.get(prefix)
    if not isinstance(branch, dict):
        return {}

    flat: dict[str, str] = {}

    def _walk(node: dict, path: str) -> None:
        for key, value in node.items():
            full_key = f'{path}.{key}' if path else key
            if isinstance(value, dict):
                _walk(value, full_key)
            elif isinstance(value, str):
                flat[full_key] = value

    _walk(branch, '')
    return flat
