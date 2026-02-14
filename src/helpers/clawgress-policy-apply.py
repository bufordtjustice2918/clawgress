#!/usr/bin/env python3
#
# Clawgress policy -> bind9 RPZ generator
#
# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import os
import time

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call

POLICY_PATHS = [
    '/config/clawgress/policy.json',
    '/etc/clawgress/policy.json',
]

DEFAULT_POLICY = {
    "version": 1,
    "allow": {
        "domains": [],
        "ips": [],
        "ports": [53, 80, 443],
    },
    "labels": {},
}

BIND_CONFIG_DIR = '/etc/bind'
BIND_WORK_DIR = '/var/cache/bind'
RPZ_DIR = f'{BIND_CONFIG_DIR}/rpz'

ALLOW_ZONE = 'rpz-allow.clawgress'
DENY_ZONE = 'rpz-default-deny.clawgress'

ALLOW_RPZ_FILE = f'{RPZ_DIR}/allow.rpz'
DENY_RPZ_FILE = f'{RPZ_DIR}/default-deny.rpz'
LABELS_FILE = f'{RPZ_DIR}/labels.json'

NAMED_CONF_OPTIONS = f'{BIND_CONFIG_DIR}/named.conf.options'
NAMED_CONF_LOCAL = f'{BIND_CONFIG_DIR}/named.conf.local'


def ensure_default_policy(path):
    makedir(os.path.dirname(path), user='root', group='root')
    if not os.path.isfile(path):
        write_file(path, json.dumps(DEFAULT_POLICY, indent=2, sort_keys=True) + '\n',
                   user='root', group='root', mode=0o644)


def read_policy(path=None):
    if path:
        paths = [path]
    else:
        paths = POLICY_PATHS

    for candidate in paths:
        if os.path.isfile(candidate):
            with open(candidate, 'r', encoding='utf-8') as handle:
                return json.load(handle), candidate

    # Create default policy at primary path if none found
    ensure_default_policy(POLICY_PATHS[0])
    with open(POLICY_PATHS[0], 'r', encoding='utf-8') as handle:
        return json.load(handle), POLICY_PATHS[0]


def normalize_domains(domains):
    normalized = []
    for domain in domains:
        if not domain:
            continue
        domain = domain.strip().strip('.')
        if not domain:
            continue
        normalized.append(domain)
    return sorted(set(normalized))


def build_labels_map(labels, domains):
    cleaned = {}
    if not isinstance(labels, dict):
        labels = {}
    for domain in domains:
        label = labels.get(domain)
        if label:
            cleaned[domain] = label
    return cleaned


def rpz_header(zone_name, serial):
    return (
        f'$TTL 60\n'
        f'@ IN SOA localhost. root.localhost. {serial} 3600 600 86400 60\n'
        f'@ IN NS localhost.\n\n'
        f'; zone: {zone_name}\n'
    )


def render_allow_zone(domains, labels=None):
    serial = time.strftime('%Y%m%d%H')
    lines = [rpz_header(ALLOW_ZONE, serial)]

    labels = labels or {}
    for domain in domains:
        label = labels.get(domain)
        comment = f' ; label={label}' if label else ''
        lines.append(f'{domain} CNAME rpz-passthru.{comment}')
        lines.append(f'*.{domain} CNAME rpz-passthru.{comment}')

    return '\n'.join(lines).rstrip() + '\n'


def render_deny_zone(labels=None):
    serial = time.strftime('%Y%m%d%H')
    lines = [rpz_header(DENY_ZONE, serial)]
    lines.append('; default deny for all other names')
    lines.append('; deny reasons are logged to syslog local1')
    lines.append('* CNAME .')
    return '\n'.join(lines).rstrip() + '\n'


def render_named_options():
    return f"""
options {{
    directory \"{BIND_WORK_DIR}\";
    recursion yes;
    allow-query {{ any; }};
    allow-query-cache {{ any; }};
    listen-on {{ any; }};
    listen-on-v6 {{ any; }};
    response-policy {{
        zone \"{ALLOW_ZONE}\" policy passthru;
        zone \"{DENY_ZONE}\" policy nxdomain;
        log yes;
    }};
}};

logging {{
    channel clawgress_rpz {{
        syslog local0;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    }};

    channel clawgress_deny {{
        syslog local1;
        severity warning;
        print-category yes;
        print-severity yes;
        print-time yes;
    }};

    category rpz {{ clawgress_rpz; clawgress_deny; }};
}};
""".lstrip()


def render_named_local():
    return f"""
zone \"{ALLOW_ZONE}\" {{
    type master;
    file \"{ALLOW_RPZ_FILE}\";
    allow-query {{ any; }};
}};

zone \"{DENY_ZONE}\" {{
    type master;
    file \"{DENY_RPZ_FILE}\";
    allow-query {{ any; }};
}};
""".lstrip()


def apply_policy(policy_path=None, reload_named=True):
    policy, policy_path = read_policy(policy_path)
    allow = policy.get('allow', {})
    domains = normalize_domains(allow.get('domains', []))
    labels = build_labels_map(policy.get('labels', {}), domains)

    makedir(RPZ_DIR, group='bind', user='root')
    makedir(BIND_WORK_DIR, group='bind', user='bind')

    write_file(ALLOW_RPZ_FILE, render_allow_zone(domains, labels), user='root', group='bind', mode=0o644)
    write_file(DENY_RPZ_FILE, render_deny_zone(), user='root', group='bind', mode=0o644)
    write_file(LABELS_FILE, json.dumps(labels, indent=2, sort_keys=True) + '\n', user='root', group='bind', mode=0o644)

    write_file(NAMED_CONF_OPTIONS, render_named_options(), user='root', group='bind', mode=0o644)
    write_file(NAMED_CONF_LOCAL, render_named_local(), user='root', group='bind', mode=0o644)

    if reload_named:
        call('systemctl reload-or-restart bind9')



def main():
    parser = argparse.ArgumentParser(description='Apply Clawgress policy to bind9 RPZ')
    parser.add_argument('--policy', help='Path to policy.json (default: /config/clawgress/policy.json)')
    parser.add_argument('--no-reload', action='store_true', help='Skip bind9 reload/restart')
    args = parser.parse_args()

    apply_policy(policy_path=args.policy, reload_named=not args.no_reload)


if __name__ == '__main__':
    main()
