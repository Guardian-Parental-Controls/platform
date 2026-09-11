"""Tests for partial agent release planning."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts' / 'ci'))

from release_plan import (  # noqa: E402
    compute_build_plan,
    parse_version,
    previous_version_tag,
    same_release_line,
)


def test_parse_version_accepts_v_prefix():
    assert parse_version('v0.68.5') == (0, 68, 5)


def test_same_release_line_compares_major_minor_only():
    assert same_release_line('v0.68.5', 'v0.68.0') is True
    assert same_release_line('v0.68.5', 'v0.69.0') is False


def test_previous_version_tag_sorts_semver():
    tags = ['v0.67.10', 'v0.68.0', 'v0.68.1', 'v0.69.0']
    assert previous_version_tag('v0.68.1', tags) == 'v0.68.0'
    assert previous_version_tag('v0.68.0', tags) == 'v0.67.10'


def test_patch_release_builds_only_changed_platforms():
    plan = compute_build_plan(
        'v0.68.2',
        previous_tag='v0.68.1',
        changed=['agent-android/app/build.gradle.kts'],
    )
    assert plan['release_mode'] == 'patch'
    assert plan['build_android'] is True
    assert plan['build_linux'] is False
    assert plan['build_windows'] is False
    assert plan['build_cef'] is False
    assert plan['publish_assets'] is True


def test_patch_release_agent_linux_rebuilds_linux_only():
    plan = compute_build_plan(
        'v0.68.2',
        previous_tag='v0.68.1',
        changed=['agent-linux/src/main.rs'],
    )
    assert plan['build_linux'] is True
    assert plan['build_windows'] is False
    assert plan['build_android'] is False
    assert plan['build_cef'] is False


def test_patch_release_agent_common_rebuilds_all_agents():
    plan = compute_build_plan(
        'v0.68.2',
        previous_tag='v0.68.1',
        changed=['agent-common/src/lib.rs'],
    )
    assert plan['build_linux'] is True
    assert plan['build_windows'] is True
    assert plan['build_android'] is True


def test_patch_release_without_agent_changes_skips_all_builds():
    plan = compute_build_plan(
        'v0.68.2',
        previous_tag='v0.68.1',
        changed=['server/app.py', 'docs/readme.md'],
    )
    assert plan['release_mode'] == 'patch'
    assert plan['publish_assets'] is False
    assert plan['build_linux'] is False
    assert plan['build_android'] is False


def test_new_minor_line_builds_everything():
    plan = compute_build_plan(
        'v0.69.0',
        previous_tag='v0.68.10',
        changed=['server/app.py'],
    )
    assert plan['release_mode'] == 'full'
    assert plan['publish_assets'] is True
    assert plan['build_linux'] is True
    assert plan['build_android'] is True
    assert plan['build_windows'] is True
    assert plan['build_cef'] is True


def test_workflow_change_forces_full_platform_matrix_on_patch_line():
    plan = compute_build_plan(
        'v0.68.3',
        previous_tag='v0.68.2',
        changed=['.github/workflows/rust-agent.yml'],
    )
    assert plan['release_mode'] == 'patch'
    assert plan['build_linux'] is True
    assert plan['build_android'] is True
    assert plan['build_windows'] is True
    assert plan['build_cef'] is True
