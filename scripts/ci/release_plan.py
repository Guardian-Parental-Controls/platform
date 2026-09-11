#!/usr/bin/env python3
"""Decide which agent release assets to build for a tagged release."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import Iterable

VERSION_RE = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)')

# Prefixes that trigger each release artifact family.
PLATFORM_PATH_PREFIXES: dict[str, tuple[str, ...]] = {
    'linux': ('agent-linux/', 'agent-common/'),
    'windows': ('agent-windows/', 'agent-common/'),
    'cef': (
        'agent-linux/src/overlay_cef/',
        'agent-linux/overlay_resources/',
        'agent-linux/Cargo.toml',
        'agent-linux/Cargo.lock',
    ),
    'android': (
        'agent-android/',
        'android-agent/',
        'agent-common/',
        'i18n/',
        'scripts/i18n/',
    ),
}

WORKFLOW_PREFIX = '.github/workflows/rust-agent.yml'


def parse_version(tag: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.match((tag or '').strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def same_release_line(left: str, right: str) -> bool:
    left_version = parse_version(left)
    right_version = parse_version(right)
    if left_version is None or right_version is None:
        return False
    return left_version[:2] == right_version[:2]


def version_sort_key(tag: str) -> tuple[int, int, int]:
    parsed = parse_version(tag)
    return parsed if parsed is not None else (0, 0, 0)


def list_version_tags() -> list[str]:
    output = subprocess.check_output(['git', 'tag', '-l', 'v*'], text=True)
    tags = [line.strip() for line in output.splitlines() if line.strip()]
    return sorted(tags, key=version_sort_key)


def previous_version_tag(current_tag: str, tags: Iterable[str] | None = None) -> str | None:
    ordered = list(tags) if tags is not None else list_version_tags()
    if current_tag not in ordered:
        ordered.append(current_tag)
        ordered = sorted(ordered, key=version_sort_key)
    index = ordered.index(current_tag)
    if index == 0:
        return None
    return ordered[index - 1]


def changed_files(base_ref: str, head_ref: str = 'HEAD') -> list[str]:
    output = subprocess.check_output(
        ['git', 'diff', '--name-only', base_ref, head_ref],
        text=True,
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def _matches_any(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path.startswith(prefix) for prefix in prefixes)


def compute_build_plan(
    current_tag: str,
    *,
    previous_tag: str | None = None,
    changed: Iterable[str] | None = None,
) -> dict[str, str | bool]:
    """Return release mode and per-platform build flags."""
    prev = previous_tag if previous_tag is not None else previous_version_tag(current_tag)
    all_platforms = {name: True for name in PLATFORM_PATH_PREFIXES}

    if prev is None or not same_release_line(current_tag, prev):
        builds = dict(all_platforms)
        publish_assets = True
        release_mode = 'full'
    else:
        release_mode = 'patch'
        diff_paths = list(changed) if changed is not None else changed_files(prev)
        if any(path == WORKFLOW_PREFIX or path.startswith(WORKFLOW_PREFIX) for path in diff_paths):
            builds = dict(all_platforms)
        else:
            builds = {
                platform: any(_matches_any(path, prefixes) for path in diff_paths)
                for platform, prefixes in PLATFORM_PATH_PREFIXES.items()
            }
        publish_assets = any(builds.values())

    return {
        'release_mode': release_mode,
        'previous_tag': prev or '',
        'publish_assets': publish_assets,
        **{f'build_{platform}': builds[platform] for platform in PLATFORM_PATH_PREFIXES},
    }


def write_github_output(plan: dict[str, str | bool], output_path: str | None = None) -> None:
    destination = output_path or os.environ.get('GITHUB_OUTPUT')
    if not destination:
        for key, value in plan.items():
            print(f'{key}={value}')
        return

    with open(destination, 'a', encoding='utf-8') as handle:
        for key, value in plan.items():
            handle.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', default=os.environ.get('GITHUB_REF_NAME', ''))
    parser.add_argument('--previous-tag', default='')
    parser.add_argument('--output', default='')
    args = parser.parse_args(argv)

    tag = (args.tag or '').strip()
    if not tag:
        print('Missing release tag', file=sys.stderr)
        return 1

    previous_tag = args.previous_tag.strip() or None
    plan = compute_build_plan(tag, previous_tag=previous_tag)
    write_github_output(plan, args.output or None)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
