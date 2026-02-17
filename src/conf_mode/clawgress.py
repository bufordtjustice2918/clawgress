#!/usr/bin/env python3
#
# Clawgress configuration script (conf_mode)
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

import hashlib
import json
import os
import re
import time

from sys import exit

from vyos.config import Config
from vyos.utils.file import makedir, write_file
from vyos.utils.process import call
from vyos.utils.process import rc_cmd
from vyos import ConfigError
from vyos import airbag

airbag.enable()

POLICY_DIR = '/config/clawgress'
POLICY_PATH = f'{POLICY_DIR}/policy.json'
APPLY_BIN = '/usr/bin/clawgress-policy-apply'
FIREWALL_APPLY_BIN = '/usr/bin/clawgress-firewall-apply'
RPZ_ALLOW_PATH = '/etc/bind/rpz/allow.rpz'
RPZ_DENY_PATH = '/etc/bind/rpz/default-deny.rpz'
APPLY_STATE_DIR = '/var/lib/clawgress'
APPLY_STATE_PATH = f'{APPLY_STATE_DIR}/apply-state.json'


def build_time_window(window_config):
    if not isinstance(window_config, dict):
        return None
    days = window_config.get('day') or window_config.get('days') or []
    if isinstance(days, str):
        days = [days]
    start = window_config.get('start')
    end = window_config.get('end')
    if not start or not end:
        return None
    payload = {
        'start': str(start),
        'end': str(end),
    }
    if days:
        payload['days'] = list(days)
    return payload


def _as_values(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return value
    return [value]


def _compute_policy_hash() -> str | None:
    if not os.path.isfile(POLICY_PATH):
        return None
    try:
        with open(POLICY_PATH, 'r', encoding='utf-8') as handle:
            policy = json.load(handle)
        payload = json.dumps(policy, sort_keys=True).encode('utf-8')
        return hashlib.sha256(payload).hexdigest()[:12]
    except Exception:
        return None


def _write_apply_state(state: dict) -> None:
    makedir(APPLY_STATE_DIR, user='root', group='root')
    write_file(
        APPLY_STATE_PATH,
        json.dumps(state, indent=2, sort_keys=True) + '\n',
        user='root',
        group='root',
        mode=0o644,
    )


def _verify_runtime_state(policy_hash: str | None, expected_proxy_backend: str | None = None) -> dict:
    bind9_active = False
    rc, output = rc_cmd('systemctl is-active bind9 2>/dev/null || true')
    if rc == 0:
        bind9_active = output.strip() == 'active'

    nft_output = ''
    rc, nft_output = rc_cmd('nft list table inet clawgress 2>/dev/null || true')
    nft_table_present = rc == 0 and 'table inet clawgress' in (nft_output or '')

    rpz_allow_present = os.path.isfile(RPZ_ALLOW_PATH)
    rpz_default_deny_present = os.path.isfile(RPZ_DENY_PATH)

    rc, _ = rc_cmd('named-checkconf -z /etc/bind/named.conf >/dev/null 2>&1')
    bind_config_valid = rc == 0

    forward_policy_drop = 'chain forward' in nft_output and 'policy drop;' in nft_output
    dns_redirect_present = (
        'udp dport 53 redirect to :53' in nft_output and
        'tcp dport 53 redirect to :53' in nft_output
    )
    policy_hash_present = bool(policy_hash) and (f'policy={policy_hash}' in nft_output)

    counter_matches = re.findall(r'counter packets (\d+) bytes (\d+)', nft_output or '')
    counters = {
        'rules_with_counters': len(counter_matches),
        'packets_total': sum(int(pkt) for pkt, _ in counter_matches),
        'bytes_total': sum(int(num) for _, num in counter_matches),
    }

    checks = {
        'bind9_active': bind9_active,
        'bind_config_valid': bind_config_valid,
        'rpz_allow_present': rpz_allow_present,
        'rpz_default_deny_present': rpz_default_deny_present,
        'nft_table_present': nft_table_present,
        'nft_forward_policy_drop': forward_policy_drop,
        'nft_dns_redirect_present': dns_redirect_present,
        'nft_policy_hash_present': policy_hash_present,
    }
    if expected_proxy_backend == 'haproxy':
        rc, output = rc_cmd('systemctl is-active haproxy 2>/dev/null || true')
        checks['haproxy_active'] = rc == 0 and output.strip() == 'active'
    failed_checks = sorted([name for name, ok in checks.items() if not ok])

    return {
        'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'policy_hash': policy_hash,
        'checks': checks,
        'failed_checks': failed_checks,
        'nft_counters': counters,
    }


def _run_apply_step(command: str, error_message: str) -> None:
    rc = call(command)
    if rc == 0:
        return
    _write_apply_state({
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'success': False,
        'error': f'{error_message} (rc={rc})',
    })
    raise ConfigError(f'{error_message} (rc={rc})')


def get_config(config=None):
    if config is None:
        config = Config()

    base = ['service', 'clawgress']
    clawgress = config.get_config_dict(base, key_mangling=('-', '_'),
                                        get_first_key=True)

    if not clawgress:
        return None

    return clawgress


def verify(clawgress):
    if not clawgress:
        return

    # Verify at least one domain is configured if service is enabled
    if 'enable' in clawgress:
        policy = clawgress.get('policy', {})
        domains = policy.get('domain', {})
        if not domains:
            raise ConfigError('At least one domain must be configured when Clawgress is enabled')

        proxy_cfg = policy.get('proxy', {}) if isinstance(policy, dict) else {}
        if isinstance(proxy_cfg, dict):
            backend = proxy_cfg.get('backend')
            mode = proxy_cfg.get('mode')
            if backend in ('haproxy', 'nginx') and mode != 'sni-allowlist':
                raise ConfigError('proxy backend requires "proxy mode sni-allowlist"')


def generate(clawgress):
    if not clawgress:
        # Service disabled - clean up if needed
        return

    # Build policy.json from VyOS configuration
    policy = {
        'version': 1,
        'allow': {
            'domains': [],
            'ips': [],
            'ports': [],
        },
        'labels': {},
    }

    # Process domains with labels
    policy_config = clawgress.get('policy', {})

    time_window = build_time_window(policy_config.get('time_window') or {})
    if time_window:
        policy['time_window'] = time_window

    domain_time_windows = {}
    domains = policy_config.get('domain', {})
    for domain, domain_config in domains.items():
        policy['allow']['domains'].append(domain)
        if 'label' in domain_config:
            policy['labels'][domain] = domain_config['label']
        window = build_time_window(domain_config.get('time_window') or {})
        if window:
            domain_time_windows[domain] = window

    if domain_time_windows:
        policy['domain_time_windows'] = domain_time_windows

    # Process IPs
    ips = policy_config.get('ip')
    for ip in _as_values(ips):
        policy['allow']['ips'].append(ip)

    # Process ports (default to 53, 80, 443 if not specified)
    ports = policy_config.get('port')
    port_values = _as_values(ports)
    if port_values:
        policy['allow']['ports'] = [int(p) for p in port_values]
    else:
        policy['allow']['ports'] = [53, 80, 443]

    proxy_config = policy_config.get('proxy', {}) or {}
    proxy_mode = proxy_config.get('mode')
    proxy_backend = proxy_config.get('backend')
    proxy_domains = _as_values(proxy_config.get('domain'))
    if proxy_mode in ('disabled', 'sni-allowlist') or proxy_domains or proxy_backend in ('none', 'haproxy', 'nginx'):
        policy['proxy'] = {
            'mode': proxy_mode if proxy_mode in ('disabled', 'sni-allowlist') else 'disabled',
            'domains': proxy_domains,
        }
        if proxy_backend in ('none', 'haproxy', 'nginx'):
            policy['proxy']['backend'] = proxy_backend

    hosts_config = policy_config.get('host', {})
    if hosts_config:
        policy['hosts'] = {}
        for host_name, host_config in hosts_config.items():
            if not isinstance(host_config, dict):
                continue
            sources = host_config.get('source') or host_config.get('sources')
            if not sources:
                continue
            if isinstance(sources, str):
                sources = [sources]
            host_entry = {
                'sources': list(sources),
            }

            exfil = host_config.get('exfil', {}) or {}
            domain_caps = {}
            domains_config = exfil.get('domain', {}) or {}
            for domain, cap_config in domains_config.items():
                if not isinstance(cap_config, dict):
                    continue
                bytes_value = cap_config.get('bytes')
                period = cap_config.get('period')
                try:
                    bytes_value = int(bytes_value)
                except (TypeError, ValueError):
                    continue
                if bytes_value <= 0 or not period:
                    continue
                domain_caps[domain] = {
                    'bytes': bytes_value,
                    'period': period,
                }

            if domain_caps:
                host_entry['exfil'] = {
                    'domains': domain_caps,
                }

            host_proxy_config = host_config.get('proxy', {}) or {}
            host_proxy_mode = host_proxy_config.get('mode')
            host_proxy_backend = host_proxy_config.get('backend')
            host_proxy_domains = _as_values(host_proxy_config.get('domain'))
            if (
                host_proxy_mode in ('disabled', 'sni-allowlist')
                or host_proxy_domains
                or host_proxy_backend in ('none', 'haproxy', 'nginx')
            ):
                host_entry['proxy'] = {
                    'mode': host_proxy_mode if host_proxy_mode in ('disabled', 'sni-allowlist') else 'disabled',
                    'domains': host_proxy_domains,
                }
                if host_proxy_backend in ('none', 'haproxy', 'nginx'):
                    host_entry['proxy']['backend'] = host_proxy_backend

            policy['hosts'][host_name] = host_entry

    # Optional rate limits
    rate_limit_kbps = policy_config.get('rate_limit_kbps')
    if rate_limit_kbps is not None:
        try:
            rate_limit_kbps = int(rate_limit_kbps)
        except (TypeError, ValueError):
            rate_limit_kbps = None
        if rate_limit_kbps and rate_limit_kbps > 0:
            policy.setdefault('limits', {})['egress_kbps'] = rate_limit_kbps

    # Write policy.json
    makedir(POLICY_DIR, user='root', group='root')
    payload = json.dumps(policy, indent=2, sort_keys=True) + '\n'
    write_file(POLICY_PATH, payload, user='root', group='root', mode=0o644)


def apply(clawgress):
    if not clawgress or 'enable' not in clawgress:
        # Service disabled - stop bind9 if running
        call('systemctl stop bind9 2>/dev/null || true')
        call('nft delete table inet clawgress 2>/dev/null || true')
        _write_apply_state({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'success': True,
            'disabled': True,
        })
        return

    # Apply policy to bind9 and nftables
    _run_apply_step(f'{APPLY_BIN}', f'Clawgress apply failed: {APPLY_BIN}')
    _run_apply_step(f'{FIREWALL_APPLY_BIN}', f'Clawgress apply failed: {FIREWALL_APPLY_BIN}')

    # Ensure resolver service is running; bind9.service can be an alias on
    # some images and "enable" may fail for aliases.
    _run_apply_step(
        'systemctl enable --now named || systemctl restart bind9 || systemctl restart named',
        'Clawgress apply failed: unable to enable/start bind9',
    )

    expected_proxy_backend = None
    policy_cfg = (clawgress or {}).get('policy', {}) if isinstance(clawgress, dict) else {}
    proxy_cfg = policy_cfg.get('proxy', {}) if isinstance(policy_cfg, dict) else {}
    proxy_mode = proxy_cfg.get('mode')
    proxy_backend = proxy_cfg.get('backend')
    if proxy_mode == 'sni-allowlist' and proxy_backend in ('haproxy', 'nginx'):
        expected_proxy_backend = proxy_backend

    policy_hash = _compute_policy_hash()
    verification = _verify_runtime_state(policy_hash, expected_proxy_backend=expected_proxy_backend)
    success = not verification['failed_checks']
    _write_apply_state({
        'timestamp': verification['checked_at'],
        'success': success,
        'policy_hash': policy_hash,
        'verification': verification,
    })
    if not success:
        failed_checks = ', '.join(verification['failed_checks'])
        raise ConfigError(f'Clawgress apply verification failed: {failed_checks}')


if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
