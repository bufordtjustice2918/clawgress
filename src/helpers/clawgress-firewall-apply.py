#!/usr/bin/env python3
#
# Clawgress policy -> nftables egress/forced DNS rules
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
import ipaddress
import hashlib
import re
import tempfile
import shutil

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call, cmd

POLICY_PATHS = [
    '/config/clawgress/policy.json',
    '/etc/clawgress/policy.json',
]

NFT_DIR = '/etc/nftables.d'
NFT_FILE = f'{NFT_DIR}/clawgress.nft'
HAPROXY_DIR = '/run/haproxy'
HAPROXY_CFG = f'{HAPROXY_DIR}/haproxy.cfg'
HAPROXY_ALLOWLIST = f'{HAPROXY_DIR}/clawgress-allowlist.lst'
HAPROXY_BACKEND_MAP = f'{HAPROXY_DIR}/clawgress-backend.map'
HAPROXY_MARKER = f'{HAPROXY_DIR}/clawgress.managed'
HAPROXY_OVERRIDE_DIR = '/run/systemd/system/haproxy.service.d'
HAPROXY_OVERRIDE = f'{HAPROXY_OVERRIDE_DIR}/10-override.conf'
HAPROXY_LISTEN_PORT = 10443


def sni_match_supported() -> bool:
    """Return True if this platform's nft userspace/parser supports tls sni matches."""
    test_ruleset = (
        "table inet clawgress_sni_check {\n"
        "  chain forward {\n"
        "    type filter hook forward priority 0; policy accept;\n"
        "    tcp dport 443 tls sni . \"example.com\" accept\n"
        "  }\n"
        "}\n"
    )
    path = None
    try:
        with tempfile.NamedTemporaryFile('w', prefix='clawgress-sni-check-', suffix='.nft', delete=False) as handle:
            handle.write(test_ruleset)
            path = handle.name
        rc = call(f'nft --check -f {path} >/dev/null 2>&1')
        return rc == 0
    finally:
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def read_policy(path=None):
    if path:
        paths = [path]
    else:
        paths = POLICY_PATHS

    for candidate in paths:
        if os.path.isfile(candidate):
            with open(candidate, 'r', encoding='utf-8') as handle:
                return json.load(handle), candidate

    raise FileNotFoundError(
        f'No policy.json found in: {", ".join(paths)}'
    )


def normalize_ports(ports):
    cleaned = []
    for port in ports or []:
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            cleaned.append(port)
    return sorted(set(cleaned))


def normalize_ips(ips):
    v4 = []
    v6 = []
    for raw in ips or []:
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            v4.append(str(net))
        else:
            v6.append(str(net))
    return sorted(set(v4)), sorted(set(v6))


def normalize_rate_limit_kbps(rate_kbps):
    if rate_kbps is None:
        return None
    try:
        rate_kbps = int(rate_kbps)
    except (TypeError, ValueError):
        return None
    if rate_kbps <= 0:
        return None
    return rate_kbps


def normalize_domains(domains):
    cleaned = []
    for domain in domains or []:
        if not domain:
            continue
        domain = domain.strip().strip('.').lower()
        if not domain:
            continue
        cleaned.append(domain)
    return sorted(set(cleaned))


def normalize_sni_domains(domains):
    normalized = []
    for domain in normalize_domains(domains):
        if domain.startswith('*.'):
            normalized.append(domain)
            normalized.append(domain[2:])
            continue
        normalized.append(domain)
        if '.' in domain:
            normalized.append(f'*.{domain}')
    return sorted(set(normalized))


DAY_ORDER = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
DAY_INDEX = {day: idx for idx, day in enumerate(DAY_ORDER)}
DAY_ALIASES = {
    'mon': 'Monday',
    'monday': 'Monday',
    'tue': 'Tuesday',
    'tues': 'Tuesday',
    'tuesday': 'Tuesday',
    'wed': 'Wednesday',
    'wednesday': 'Wednesday',
    'thu': 'Thursday',
    'thur': 'Thursday',
    'thurs': 'Thursday',
    'thursday': 'Thursday',
    'fri': 'Friday',
    'friday': 'Friday',
    'sat': 'Saturday',
    'saturday': 'Saturday',
    'sun': 'Sunday',
    'sunday': 'Sunday',
}
TIME_RE = re.compile(r'^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$')
TIME_UNITS = {'second', 'minute', 'hour', 'day'}
PROXY_BACKENDS = {'none', 'haproxy', 'nginx'}


def normalize_domain_key(domain):
    if not domain:
        return None
    domain = str(domain).strip().strip('.').lower()
    return domain or None


def sni_domain_key(domain):
    if not domain:
        return None
    if domain.startswith('*.'):
        domain = domain[2:]
    return normalize_domain_key(domain)


def normalize_days(days):
    if not days:
        return []
    if isinstance(days, str):
        days = [days]
    cleaned = []
    for day in days:
        if not day:
            continue
        key = str(day).strip().lower()
        if key in DAY_ALIASES:
            cleaned.append(DAY_ALIASES[key])
            continue
        key = key[:3]
        if key in DAY_ALIASES:
            cleaned.append(DAY_ALIASES[key])
    return sorted(set(cleaned), key=lambda d: DAY_INDEX.get(d, 0))


def normalize_time_window(window):
    if not isinstance(window, dict):
        return None
    days = normalize_days(window.get('days') or window.get('day') or [])
    start = window.get('start')
    end = window.get('end')
    if start and not TIME_RE.match(str(start)):
        start = None
    if end and not TIME_RE.match(str(end)):
        end = None
    if (start and not end) or (end and not start):
        return None
    if not days and not (start and end):
        return None
    return {
        'days': days,
        'start': str(start) if start else None,
        'end': str(end) if end else None,
    }


def normalize_domain_time_windows(domain_windows):
    normalized = {}
    if not isinstance(domain_windows, dict):
        return normalized
    for domain, window in domain_windows.items():
        key = normalize_domain_key(domain)
        time_window = normalize_time_window(window)
        if key and time_window:
            normalized[key] = time_window
    return normalized


def normalize_exfil_caps(exfil_caps):
    normalized = {}
    if not isinstance(exfil_caps, dict):
        return normalized
    domains = exfil_caps.get('domains') if 'domains' in exfil_caps else exfil_caps
    if not isinstance(domains, dict):
        return normalized
    for domain, cap in domains.items():
        if not isinstance(cap, dict):
            continue
        try:
            byte_limit = int(cap.get('bytes'))
        except (TypeError, ValueError):
            continue
        if byte_limit <= 0:
            continue
        period = str(cap.get('period') or '').strip().lower()
        if period not in TIME_UNITS:
            continue
        key = normalize_domain_key(domain)
        if not key:
            continue
        normalized[key] = f' limit rate {byte_limit} bytes/{period}'
    return normalized


def render_time_clause(window):
    if not window:
        return ''
    clauses = []
    days = window.get('days') or []
    if days:
        day_values = ', '.join(day for day in days)
        clauses.append(f'meta day {{ {day_values} }}')
    start = window.get('start')
    end = window.get('end')
    if start and end:
        start = str(start)
        end = str(end)
        if start <= end:
            clauses.append(f'meta hour "{start}"-"{end}"')
        else:
            end_of_day = '23:59:59' if (start.count(':') == 2 or end.count(':') == 2) else '23:59'
            clauses.append(f'meta hour {{ "{start}"-"{end_of_day}", "00:00"-"{end}" }}')
    if not clauses:
        return ''
    return ' ' + ' '.join(clauses)


def sanitize_chain_name(name):
    safe = re.sub(r'[^A-Za-z0-9_]', '_', name)
    if not safe:
        safe = 'host'
    return f'clawgress_host_{safe}'


def resolve_proxy_settings(proxy, allow):
    proxy = proxy or {}
    proxy_mode = (proxy.get('mode') or '').lower()
    proxy_backend = str(proxy.get('backend') or 'none').strip().lower()
    if proxy_backend not in PROXY_BACKENDS:
        proxy_backend = 'none'
    sni_domains = []
    if proxy_mode == 'sni-allowlist':
        domain_source = proxy.get('domains') or allow.get('domains', [])
        sni_domains = normalize_sni_domains(domain_source)
    return proxy_mode, sni_domains, proxy_backend


def render_allow_rules(lines, v4, v6, ports, sni_domains, limit_clause,
                       time_clause='', domain_time_windows=None, domain_exfil_limits=None):
    port_set = ', '.join(str(p) for p in ports) if ports else ''
    v4_set = ', '.join(v4)
    v6_set = ', '.join(v6)

    domain_time_windows = domain_time_windows or {}
    domain_exfil_limits = domain_exfil_limits or {}

    for domain in sni_domains or []:
        domain_key = sni_domain_key(domain)
        window_clause = render_time_clause(domain_time_windows.get(domain_key))
        domain_limit_clause = domain_exfil_limits.get(domain_key, '')
        effective_limit_clause = domain_limit_clause or limit_clause
        lines.append(
            f'    tcp dport 443{time_clause}{window_clause} tls sni . "{domain}"{effective_limit_clause} counter accept'
        )

    if v4_set and port_set:
        lines.append(f'    ip daddr {{ {v4_set} }} tcp dport {{ {port_set} }}{time_clause}{limit_clause} counter accept')
        lines.append(f'    ip daddr {{ {v4_set} }} udp dport {{ {port_set} }}{time_clause}{limit_clause} counter accept')
    elif v4_set:
        lines.append(f'    ip daddr {{ {v4_set} }}{time_clause}{limit_clause} counter accept')

    if v6_set and port_set:
        lines.append(f'    ip6 daddr {{ {v6_set} }} tcp dport {{ {port_set} }}{time_clause}{limit_clause} counter accept')
        lines.append(f'    ip6 daddr {{ {v6_set} }} udp dport {{ {port_set} }}{time_clause}{limit_clause} counter accept')
    elif v6_set:
        lines.append(f'    ip6 daddr {{ {v6_set} }}{time_clause}{limit_clause} counter accept')


def _normalize_backend_domains(domains):
    normalized = []
    for domain in domains or []:
        key = sni_domain_key(domain)
        if key:
            normalized.append(key)
    return sorted(set(normalized))


def render_haproxy_cfg(domains, policy_hash='') -> str:
    backend_lines = []
    for idx, domain in enumerate(domains, start=1):
        backend_name = f'clawgress_bk_{idx}'
        backend_lines.extend([
            f'backend {backend_name}',
            '    mode tcp',
            f'    server sni_target {domain}:443 resolvers clawgress_dns init-addr libc,none resolve-prefer ipv4',
            '',
        ])

    backend_text = '\n'.join(backend_lines).rstrip()
    if backend_text:
        backend_text = f'\n{backend_text}'

    return f"""### Clawgress managed HAProxy config ###
### policy_hash={policy_hash} ###
global
    log /dev/log local0
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode tcp
    log global
    option dontlognull
    timeout connect 10s
    timeout client 60s
    timeout server 60s

resolvers clawgress_dns
    nameserver localdns 127.0.0.1:53
    accepted_payload_size 8192

frontend clawgress_tls_sni
    bind 0.0.0.0:{HAPROXY_LISTEN_PORT}
    bind [::]:{HAPROXY_LISTEN_PORT} v6only
    mode tcp
    option tcplog
    tcp-request inspect-delay 5s
    tcp-request content set-var(txn.clawgress_sni) req.ssl_sni,lower
    tcp-request content accept if {{ req.ssl_hello_type 1 }}
    acl clawgress_sni_found var(txn.clawgress_sni) -m found
    acl clawgress_sni_allowed var(txn.clawgress_sni) -m str -f {HAPROXY_ALLOWLIST}
    log-format "clawgress_sni src=%ci sni=%[var(txn.clawgress_sni)] policy={policy_hash}"
    tcp-request content reject if clawgress_sni_found !clawgress_sni_allowed
    use_backend %[var(txn.clawgress_sni),map({HAPROXY_BACKEND_MAP},clawgress_reject)]
    default_backend clawgress_reject

backend clawgress_reject
    mode tcp
    server reject_target 127.0.0.1:1{backend_text}
"""


def _write_haproxy_override() -> None:
    override_content = """[Unit]
StartLimitIntervalSec=0
After=vyos-router.service
ConditionPathExists=/run/haproxy/haproxy.cfg

[Service]
EnvironmentFile=
Environment=
Environment="CONFIG=/run/haproxy/haproxy.cfg" "PIDFILE=/run/haproxy.pid" "EXTRAOPTS=-S /run/haproxy-master.sock"
ExecStart=
ExecStart=/usr/sbin/haproxy -Ws -f /run/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock
Restart=always
RestartSec=10
"""
    makedir(HAPROXY_OVERRIDE_DIR, user='root', group='root')
    write_file(HAPROXY_OVERRIDE, override_content, user='root', group='root', mode=0o644)


def disable_haproxy_backend():
    if not os.path.isfile(HAPROXY_MARKER):
        return
    call('systemctl stop haproxy >/dev/null 2>&1 || true')
    for path in [HAPROXY_CFG, HAPROXY_ALLOWLIST, HAPROXY_BACKEND_MAP, HAPROXY_MARKER, HAPROXY_OVERRIDE]:
        if os.path.isfile(path):
            os.unlink(path)
    if os.path.isdir(HAPROXY_OVERRIDE_DIR):
        try:
            if not os.listdir(HAPROXY_OVERRIDE_DIR):
                shutil.rmtree(HAPROXY_OVERRIDE_DIR, ignore_errors=True)
        except Exception:
            pass
    call('systemctl daemon-reload >/dev/null 2>&1 || true')


def apply_haproxy_backend(domains, policy_hash='') -> bool:
    domains = _normalize_backend_domains(domains)
    if not domains:
        return False
    makedir(HAPROXY_DIR, user='root', group='root')
    write_file(HAPROXY_CFG, render_haproxy_cfg(domains, policy_hash), user='root', group='root', mode=0o644)
    write_file(HAPROXY_ALLOWLIST, '\n'.join(domains) + '\n', user='root', group='root', mode=0o644)
    map_lines = [f'{domain} clawgress_bk_{idx}' for idx, domain in enumerate(domains, start=1)]
    write_file(HAPROXY_BACKEND_MAP, '\n'.join(map_lines) + '\n', user='root', group='root', mode=0o644)
    write_file(HAPROXY_MARKER, f'policy_hash={policy_hash}\n', user='root', group='root', mode=0o644)
    _write_haproxy_override()
    call('systemctl daemon-reload')
    def _dump_haproxy_diagnostics():
        print('ERROR: Failed to restart haproxy for Clawgress backend.')
        for name, command in (
            ('haproxy-config-check', f'haproxy -c -f {HAPROXY_CFG} 2>&1 || true'),
            ('haproxy-systemctl-status', 'systemctl status haproxy --no-pager -l 2>&1 || true'),
            ('haproxy-journal', 'journalctl -u haproxy.service --no-pager -n 120 2>&1 || true'),
        ):
            print(f'--- {name} ---')
            try:
                output = cmd(command).strip()
                print(output if output else '(no output)')
            except Exception as exc:
                print(f'(failed to capture {name}: {exc})')

    rc = call('systemctl restart haproxy')
    if rc != 0:
        _dump_haproxy_diagnostics()
        return False
    rc = call('systemctl is-active --quiet haproxy')
    if rc != 0:
        _dump_haproxy_diagnostics()
        return False
    return rc == 0


def render_nft(v4, v6, ports, policy_hash='', rate_limit_kbps=None, sni_domains=None,
               host_policies=None, time_window=None, domain_time_windows=None, proxy_redirect_port=None):
    reason = f'clawgress-deny: reason=egress-default-deny policy={policy_hash} '

    limit_clause = ''
    if rate_limit_kbps:
        rate_kbytes = max(1, rate_limit_kbps // 8)
        limit_clause = f' limit rate {rate_kbytes} kbytes/second'

    time_window = normalize_time_window(time_window or {})
    time_clause = render_time_clause(time_window)
    domain_time_windows = normalize_domain_time_windows(domain_time_windows or {})

    lines = [
        'table inet clawgress {',
        '  chain prerouting {',
        '    type nat hook prerouting priority -100; policy accept;',
        '    udp dport 53 redirect to :53',
        '    tcp dport 53 redirect to :53',
        '  }',
        '  chain forward {',
        '    type filter hook forward priority 0; policy drop;',
        '    ct state established,related accept',
        '    udp dport 53 accept',
        '    tcp dport 53 accept',
    ]
    if proxy_redirect_port:
        lines.insert(5, f'    tcp dport 443 redirect to :{int(proxy_redirect_port)}')

    for host in host_policies or []:
        if host.get('source_v4'):
            src_v4 = ', '.join(host['source_v4'])
            lines.append(f'    ip saddr {{ {src_v4} }} jump {host["chain"]}')
        if host.get('source_v6'):
            src_v6 = ', '.join(host['source_v6'])
            lines.append(f'    ip6 saddr {{ {src_v6} }} jump {host["chain"]}')

    render_allow_rules(lines, v4, v6, ports, sni_domains, limit_clause,
                       time_clause, domain_time_windows)

    lines.extend([
        f'    log prefix "{reason}" level info',
        '    drop',
        '  }',
    ])

    for host in host_policies or []:
        host_limit_clause = ''
        if host.get('rate_limit_kbps'):
            rate_kbytes = max(1, host['rate_limit_kbps'] // 8)
            host_limit_clause = f' limit rate {rate_kbytes} kbytes/second'

        host_time_window = normalize_time_window(host.get('time_window') or time_window or {})
        host_time_clause = render_time_clause(host_time_window)
        host_domain_time_windows = dict(domain_time_windows)
        host_domain_time_windows.update(
            normalize_domain_time_windows(host.get('domain_time_windows') or {})
        )
        host_exfil_limits = host.get('exfil_limits') or {}

        host_reason = (
            f'clawgress-deny: reason=egress-host-deny host={host["name"]} '
            f'policy={policy_hash} '
        )
        lines.append(f'  chain {host["chain"]} {{')
        lines.append('    ct state established,related accept')
        lines.append('    udp dport 53 accept')
        lines.append('    tcp dport 53 accept')
        render_allow_rules(
            lines,
            host['allow_v4'],
            host['allow_v6'],
            host['ports'],
            host['sni_domains'],
            host_limit_clause,
            host_time_clause,
            host_domain_time_windows,
            host_exfil_limits,
        )
        lines.append(f'    log prefix "{host_reason}" level info')
        lines.append('    drop')
        lines.append('  }')

    lines.append('}')

    return '\n'.join(lines) + '\n'


def apply_policy(policy_path=None):
    policy, policy_path = read_policy(policy_path)
    policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True).encode('utf-8')).hexdigest()[:12]
    allow = policy.get('allow', {})
    ports = normalize_ports(allow.get('ports', [53, 80, 443]))
    v4, v6 = normalize_ips(allow.get('ips', []))

    proxy = policy.get('proxy', {}) or {}
    proxy_mode, sni_domains, proxy_backend = resolve_proxy_settings(proxy, allow)
    sni_supported = sni_match_supported()
    proxy_redirect_port = None
    if proxy_backend != 'haproxy':
        disable_haproxy_backend()

    if proxy_mode == 'sni-allowlist':
        if proxy_backend == 'haproxy':
            backend_domains = _normalize_backend_domains(sni_domains or allow.get('domains', []))
            if backend_domains and apply_haproxy_backend(backend_domains, policy_hash):
                proxy_redirect_port = HAPROXY_LISTEN_PORT
                sni_domains = []
            else:
                print(
                    'WARNING: Clawgress HAProxy backend could not be started; '
                    'falling back to nft DNS/IP/port policy enforcement.'
                )
        if proxy_redirect_port is None:
            if sni_domains and sni_supported:
                # Enforce HTTPS via SNI allowlist rules only.
                ports = [port for port in ports if port != 443]
            else:
                # Platform cannot parse tls sni expressions; keep 443 in normal
                # allowlist path so commit/apply remains functional.
                sni_domains = []
                print(
                    'WARNING: nftables TLS SNI matching unsupported on this platform; '
                    'falling back to DNS/IP/port policy enforcement.'
                )

    time_window = normalize_time_window(policy.get('time_window') or {})
    domain_time_windows = normalize_domain_time_windows(policy.get('domain_time_windows') or {})

    limits = policy.get('limits', {})
    rate_limit_kbps = normalize_rate_limit_kbps(limits.get('egress_kbps'))

    host_policies = []
    hosts = policy.get('hosts', {}) or {}
    if isinstance(hosts, dict):
        host_items = hosts.items()
    elif isinstance(hosts, list):
        host_items = [(host.get('name', f'host-{idx}'), host) for idx, host in enumerate(hosts, start=1)]
    else:
        host_items = []

    for host_name, host_policy in host_items:
        if not isinstance(host_policy, dict):
            continue
        sources = host_policy.get('sources') or host_policy.get('source_ips') or host_policy.get('source-ips')
        v4_sources, v6_sources = normalize_ips(sources or [])
        if not v4_sources and not v6_sources:
            continue

        host_allow = host_policy.get('allow', {}) or {}
        merged_allow = {
            'domains': host_allow.get('domains', allow.get('domains', [])),
            'ips': host_allow.get('ips', allow.get('ips', [])),
            'ports': host_allow.get('ports', allow.get('ports', [53, 80, 443])),
        }
        host_ports = normalize_ports(merged_allow.get('ports', [53, 80, 443]))
        host_v4, host_v6 = normalize_ips(merged_allow.get('ips', []))

        host_proxy = host_policy.get('proxy', {}) or {}
        host_proxy_mode, host_sni_domains, _host_proxy_backend = resolve_proxy_settings(host_proxy, merged_allow)
        if host_proxy_mode == 'sni-allowlist':
            if host_sni_domains and sni_supported:
                host_ports = [port for port in host_ports if port != 443]
            else:
                host_sni_domains = []

        host_limits = host_policy.get('limits', {}) or {}
        host_rate_limit_kbps = normalize_rate_limit_kbps(
            host_limits.get('egress_kbps', limits.get('egress_kbps'))
        )

        host_time_window = normalize_time_window(host_policy.get('time_window') or {})
        host_domain_time_windows = dict(domain_time_windows)
        host_domain_time_windows.update(
            normalize_domain_time_windows(host_policy.get('domain_time_windows') or {})
        )
        host_exfil_limits = normalize_exfil_caps(host_policy.get('exfil', {}))

        host_policies.append({
            'name': host_name,
            'chain': sanitize_chain_name(host_name),
            'source_v4': v4_sources,
            'source_v6': v6_sources,
            'allow_v4': host_v4,
            'allow_v6': host_v6,
            'ports': host_ports,
            'sni_domains': host_sni_domains,
            'rate_limit_kbps': host_rate_limit_kbps,
            'time_window': host_time_window,
            'domain_time_windows': host_domain_time_windows,
            'exfil_limits': host_exfil_limits,
        })

    makedir(NFT_DIR, user='root', group='root')
    write_file(
        NFT_FILE,
        render_nft(
            v4,
            v6,
            ports,
            policy_hash,
            rate_limit_kbps,
            sni_domains,
            host_policies,
            time_window=time_window,
            domain_time_windows=domain_time_windows,
            proxy_redirect_port=proxy_redirect_port,
        ),
        user='root',
        group='root',
        mode=0o644,
    )
    call(f'nft -f {NFT_FILE}')


def main():
    parser = argparse.ArgumentParser(description='Apply Clawgress policy to nftables')
    parser.add_argument('--policy', help='Path to policy.json (default: /config/clawgress/policy.json)')
    args = parser.parse_args()

    apply_policy(policy_path=args.policy)


if __name__ == '__main__':
    main()
