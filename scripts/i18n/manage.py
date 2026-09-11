#!/usr/bin/env python3
"""Guardian i18n management CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lib import (  # noqa: E402
    DEFAULT_LOCALE,
    I18N_ROOT,
    SERVICES,
    add_locale,
    add_string,
    bundle_android,
    bundle_agent,
    bundle_extension,
    bundle_overlay,
    bundle_rust,
    bundle_server,
    discover_locales,
    list_missing_keys,
    load_catalog,
    validate_catalogs,
    validate_locale_code,
    validate_service,
)


def _cmd_add_locale(args: argparse.Namespace) -> int:
    created = add_locale(
        args.locale,
        args.label,
        copy_from=args.copy_from,
        services=tuple(args.services),
    )
    print(f'Created locale "{args.locale}" ({len(created)} catalog file(s)):')
    for path in created:
        try:
            print(f'  - {path.relative_to(I18N_ROOT.parent)}')
        except ValueError:
            print(f'  - {path}')
    return 0


def _cmd_add_string(args: argparse.Namespace) -> int:
    locales = discover_locales(args.service) if args.all_locales else [args.locale]
    updated: list[tuple[str, str]] = []
    for index, locale in enumerate(locales):
        updated.extend(
            add_string(
                args.service,
                args.key,
                args.value,
                locale=locale,
                overwrite=args.force,
                propagate=args.propagate and index == 0,
                todo_other_locales=not args.no_todo,
            )
        )
    seen = set()
    for locale, key in updated:
        token = (locale, key)
        if token in seen:
            continue
        seen.add(token)
        print(f'Updated {locale}/{args.service}.yaml → {key}')
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_catalogs(strict=args.strict)
    if errors:
        print('i18n validation failed:', file=sys.stderr)
        for error in errors:
            print(f'  - {error}', file=sys.stderr)
        return 1
    print('i18n catalogs OK')
    for service in SERVICES:
        locales = discover_locales(service)
        if locales:
            print(f'  {service}: {", ".join(locales)}')
    return 0


def _cmd_check_usage(args: argparse.Namespace) -> int:
    import json

    from check_usage import format_markdown, format_text, load_changed_files, run_check

    changed_files = load_changed_files(args.changed_files, args.changed_files_list or None)
    report = run_check(
        changed_files=changed_files,
        warn_hardcoded=not args.no_warn_hardcoded,
    )
    print(format_text(report))

    if args.json:
        payload = {
            'failed': report.failed,
            'keys_checked': report.keys_checked,
            'diff_mode': report.diff_mode,
            'catalog_errors': report.catalog_errors,
            'missing_keys': [
                {
                    'key': ref.catalog_key,
                    'file': ref.file,
                    'line': ref.line,
                    'service': ref.service,
                }
                for ref in report.missing_keys
            ],
            'hardcoded': [
                {
                    'file': item.file,
                    'line': item.line,
                    'text': item.text,
                    'kind': item.kind,
                }
                for item in report.hardcoded
            ],
        }
        args.json.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')

    if args.report_md:
        args.report_md.write_text(
            format_markdown(report, changed_files=changed_files) + '\n',
            encoding='utf-8',
        )

    return 1 if report.failed else 0


def _cmd_bundle(args: argparse.Namespace) -> int:
    targets = {
        'all': ('server', 'agent'),
        'server': ('server',),
        'android': ('android',),
        'extension': ('extension',),
        'overlay': ('overlay',),
        'rust': ('rust',),
        'agent': ('agent',),
    }
    selected = targets.get(args.target)
    if not selected:
        print(f'Unknown bundle target: {args.target}', file=sys.stderr)
        return 1

    exit_code = 0
    for target in selected:
        if target == 'server':
            paths = bundle_server(dry_run=args.dry_run)
            action = 'Would stage' if args.dry_run else 'Staged'
            print(f'{action} {len(paths)} server catalog file(s) under server/i18n/')
        elif target == 'android':
            paths = bundle_android(dry_run=args.dry_run)
            action = 'Would write' if args.dry_run else 'Wrote'
            print(f'{action} {len(paths)} Android strings.xml file(s)')
            for path in paths:
                try:
                    print(f'  - {path.relative_to(I18N_ROOT.parent)}')
                except ValueError:
                    print(f'  - {path}')
        elif target == 'extension':
            paths = bundle_extension(dry_run=args.dry_run)
            action = 'Would write' if args.dry_run else 'Wrote'
            print(f'{action} {len(paths)} extension locale file(s)')
            for path in paths:
                try:
                    print(f'  - {path.relative_to(I18N_ROOT.parent)}')
                except ValueError:
                    print(f'  - {path}')
        elif target == 'overlay':
            paths = bundle_overlay(dry_run=args.dry_run)
            action = 'Would write' if args.dry_run else 'Wrote'
            print(f'{action} {len(paths)} overlay asset file(s)')
            for path in paths:
                try:
                    print(f'  - {path.relative_to(I18N_ROOT.parent)}')
                except ValueError:
                    print(f'  - {path}')
        elif target == 'rust':
            paths = bundle_rust(dry_run=args.dry_run)
            action = 'Would write' if args.dry_run else 'Wrote'
            print(f'{action} {len(paths)} Rust i18n JSON file(s)')
            for path in paths:
                try:
                    print(f'  - {path.relative_to(I18N_ROOT.parent)}')
                except ValueError:
                    print(f'  - {path}')
        elif target == 'agent':
            paths = bundle_agent(dry_run=args.dry_run)
            action = 'Would write' if args.dry_run else 'Wrote'
            print(f'{action} {len(paths)} agent artifact file(s) (android + overlay + rust)')
    return exit_code


def _cmd_list_locales(_args: argparse.Namespace) -> int:
    for service in SERVICES:
        locales = discover_locales(service)
        print(f'{service}:')
        for locale in locales:
            meta = load_catalog(locale, service).get('meta') or {}
            label = meta.get('label', locale)
            print(f'  - {locale} ({label})')
    return 0


def _cmd_list_missing(args: argparse.Namespace) -> int:
    missing = list_missing_keys(args.locale, args.service)
    if not missing:
        print(f'{args.locale}/{args.service}: complete vs {DEFAULT_LOCALE}')
        return 0
    print(f'{args.locale}/{args.service}: {len(missing)} missing key(s) vs {DEFAULT_LOCALE}')
    for key in missing:
        print(f'  - {key}')
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Manage Guardian translation catalogs under i18n/.',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    add_locale_parser = sub.add_parser('add-locale', help='Create a new locale from English templates')
    add_locale_parser.add_argument('locale', help='ISO 639-1 locale code (e.g. fr, de, pt-br)')
    add_locale_parser.add_argument('--label', required=True, help='Human-readable language name')
    add_locale_parser.add_argument('--copy-from', default=DEFAULT_LOCALE, help='Source locale (default: en)')
    add_locale_parser.add_argument(
        '--services',
        nargs='+',
        choices=SERVICES,
        default=list(SERVICES),
        help='Catalog files to create (default: all services)',
    )
    add_locale_parser.set_defaults(func=_cmd_add_locale)

    add_string_parser = sub.add_parser(
        'add-string',
        help='Add a dot-path string (supports {parameter} placeholders)',
    )
    add_string_parser.add_argument('service', choices=SERVICES, help='Catalog service file')
    add_string_parser.add_argument('key', help='Dot path (e.g. flash.auth.login_required)')
    add_string_parser.add_argument('value', help='English string; use {name} for parameters')
    add_string_parser.add_argument('--locale', default=DEFAULT_LOCALE, help='Target locale (default: en)')
    add_string_parser.add_argument(
        '--all-locales',
        action='store_true',
        help='Set the same value in every locale that has this service catalog',
    )
    add_string_parser.add_argument(
        '--no-propagate',
        dest='propagate',
        action='store_false',
        help='Do not add TODO copies to other locales when editing English',
    )
    add_string_parser.add_argument(
        '--no-todo',
        action='store_true',
        help='When propagating, copy the English text instead of prefixing [TODO]',
    )
    add_string_parser.add_argument('--force', action='store_true', help='Overwrite an existing key')
    add_string_parser.set_defaults(func=_cmd_add_string, propagate=True)

    validate_parser = sub.add_parser('validate', help='Check catalog structure and locale parity')
    validate_parser.add_argument(
        '--strict',
        action='store_true',
        help='Fail on [TODO] prefixed strings in non-English locales',
    )
    validate_parser.set_defaults(func=_cmd_validate)

    check_usage_parser = sub.add_parser(
        'check-usage',
        help='Validate translation key references and warn on hardcoded UI strings',
    )
    check_usage_parser.add_argument('--json', type=Path, help='Write machine-readable report JSON')
    check_usage_parser.add_argument('--report-md', type=Path, help='Write Markdown report (for PR comments)')
    check_usage_parser.add_argument(
        '--changed-files',
        type=Path,
        help='Newline-separated repo-relative paths; limits checks to these files (CI diff mode)',
    )
    check_usage_parser.add_argument(
        '--changed-file',
        action='append',
        dest='changed_files_list',
        default=[],
        help='Repo-relative changed file (repeatable)',
    )
    check_usage_parser.add_argument('--no-warn-hardcoded', action='store_true')
    check_usage_parser.set_defaults(func=_cmd_check_usage)

    bundle_parser = sub.add_parser(
        'bundle',
        help='Generate deployment artifacts for server, Android agent, or extension',
    )
    bundle_parser.add_argument(
        '--target',
        choices=['server', 'android', 'extension', 'overlay', 'rust', 'agent', 'all'],
        default='all',
        help='Artifact target (default: all → server + agent bundles)',
    )
    bundle_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be written without modifying files',
    )
    bundle_parser.set_defaults(func=_cmd_bundle)

    list_locales_parser = sub.add_parser('list-locales', help='List configured locales per service')
    list_locales_parser.set_defaults(func=_cmd_list_locales)

    list_missing_parser = sub.add_parser(
        'list-missing',
        help='List keys present in English but missing from another locale',
    )
    list_missing_parser.add_argument('locale', help='Locale to compare against English')
    list_missing_parser.add_argument('--service', default='server', choices=SERVICES)
    list_missing_parser.set_defaults(func=_cmd_list_missing)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if hasattr(args, 'locale'):
            args.locale = validate_locale_code(args.locale)
        if hasattr(args, 'service') and isinstance(args.service, str):
            args.service = validate_service(args.service)
        return args.func(args)
    except (ValueError, FileExistsError, FileNotFoundError, RuntimeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
