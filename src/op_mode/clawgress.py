#!/usr/bin/env python3
#
# Clawgress policy operations (op-mode)
#
# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import os

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call, cmd, rc_cmd

POLICY_DIR = '/config/clawgress'
POLICY_PATH = f'{POLICY_DIR}/policy.json'
APPLY_BIN = '/usr/bin/clawgress-policy-apply'


def _load_policy(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def _write_policy(policy: dict, path: str) -> None:
    payload = json.dumps(policy, indent=2, sort_keys=True)
    write_file(path, payload + '\n', user='root', group='root', mode=0o644)


def apply_policy(policy_path: str | None) -> None:
    if policy_path:
        call(f'{APPLY_BIN} --policy {policy_path}')
    else:
        call(f'{APPLY_BIN}')


def import_policy(source_path: str) -> None:
    policy = _load_policy(source_path)
    makedir(POLICY_DIR, user='root', group='root')
    _write_policy(policy, POLICY_PATH)
    apply_policy(POLICY_PATH)


def show_policy(path: str | None) -> None:
    policy_path = path or POLICY_PATH
    policy = _load_policy(policy_path)
    print(json.dumps(policy, indent=2, sort_keys=True))


def show_status() -> None:
    policy_exists = os.path.isfile(POLICY_PATH)
    bind9_active = False
    try:
        output = cmd('systemctl is-active bind9')
        bind9_active = output.strip() == 'active'
    except Exception:
        bind9_active = False

    print(json.dumps({
        'policy_path': POLICY_PATH,
        'policy_present': policy_exists,
        'bind9_active': bind9_active,
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description='Clawgress policy operations')
    subparsers = parser.add_subparsers(dest='command', required=True)

    apply_parser = subparsers.add_parser('apply', help='Apply policy to bind9 RPZ')
    apply_parser.add_argument('--policy', help='Path to policy.json')

    import_parser = subparsers.add_parser('import', help='Import policy.json to /config and apply')
    import_parser.add_argument('--policy', required=True, help='Path to policy.json')

    show_parser = subparsers.add_parser('show', help='Show policy.json')
    show_parser.add_argument('--policy', help='Path to policy.json')

    subparsers.add_parser('status', help='Show Clawgress status')

    args = parser.parse_args()

    if args.command == 'apply':
        apply_policy(args.policy)
        return

    if args.command == 'import':
        import_policy(args.policy)
        return

    if args.command == 'show':
        show_policy(args.policy)
        return

    if args.command == 'status':
        show_status()
        return


if __name__ == '__main__':
    main()
