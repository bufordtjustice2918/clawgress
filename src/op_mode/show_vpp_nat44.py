#!/usr/bin/env python3
#
# Copyright (C) 2025 VyOS Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import json
import sys
from tabulate import tabulate

import vyos.opmode
from vyos.configquery import ConfigTreeQuery

from vyos.vpp import VPPControl


protocol_map = {
    0: 'all',
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
}


def _verify(func):
    """Decorator checks if config for VPP NAT44 exists"""
    from functools import wraps

    @wraps(func)
    def _wrapper(*args, **kwargs):
        config = ConfigTreeQuery()
        base = 'vpp nat44'
        if not config.exists(base):
            raise vyos.opmode.UnconfiguredSubsystem(f'{base} is not configured')

        return func(*args, **kwargs)

    return _wrapper


def _get_raw_output_sessions(vpp_api):
    users: list[dict] = vpp_api.nat44_user_dump()
    sessions_list: list[dict] = []
    for user in users:
        ip_address = str(user._asdict().get('ip_address'))
        user_sessions_dump = vpp_api.nat44_user_session_v3_dump(ip_address=ip_address)
        user_sessions = [
            json.loads(json.dumps(session._asdict(), default=str))
            for session in user_sessions_dump
        ]
        sessions_list.extend(user_sessions)
    return sorted(sessions_list, key=lambda x: x["inside_ip_address"])


def _get_formatted_output_sessions(sessions_list):
    print('NAT44 ED sessions:')
    print(f'---------------  {len(sessions_list)} sessions  ---------------')
    for session in sessions_list:
        in_ip_addr = session.get('inside_ip_address')
        in_port = session.get('inside_port')
        out_ip_addr = session.get('outside_ip_address')
        out_port = session.get('outside_port')
        protocol = protocol_map[session.get('protocol')].upper()
        last_heard = session.get('last_heard')
        time_since_last_heard = session.get('time_since_last_heard')
        total_bytes = session.get('total_bytes')
        total_pkts = session.get('total_pkts')
        ext_host_address = session.get('ext_host_address')
        ext_host_port = session.get('ext_host_port')
        is_timed_out = session.get('is_timed_out')

        print(f'   i2o {in_ip_addr} proto {protocol} port {in_port}')
        print(f'   o2i {out_ip_addr} proto {protocol} port {out_port}')
        print(f'      external host {ext_host_address}:{ext_host_port}')
        print(
            f'      i2o flow: match: saddr {in_ip_addr} sport {in_port} daddr {ext_host_address} dport {ext_host_port} proto {protocol} rewrite: saddr {out_ip_addr}'
            + (
                f' sport {out_port}'
                if protocol != 'ICMP'
                else f' daddr {ext_host_address} icmp-id {ext_host_port}'
            )
        )
        print(
            f'      o2i flow: match: saddr {ext_host_address} sport {ext_host_port} daddr {out_ip_addr} dport {out_port} proto {protocol} rewrite: '
            + (
                f'daddr {in_ip_addr} dport {in_port}'
                if protocol != 'ICMP'
                else f' saddr {ext_host_address} daddr {in_ip_addr} icmp-id {ext_host_port}'
            )
        )
        print(f'      last heard {last_heard}')
        print(f'      time since last heard {time_since_last_heard}')
        print(f'      total packets {total_pkts}, total bytes {total_bytes}')
        if is_timed_out:
            print('      session timed out')
        print('\n')


def _get_raw_output_static_rules(vpp_api):
    nat_static_dump = vpp_api.nat44_static_mapping_dump()
    rules_list = [
        json.loads(json.dumps(rule._asdict(), default=str)) for rule in nat_static_dump
    ]
    return rules_list


def _get_formatted_output_rules(rules_list):
    data_entries = []
    for rule in rules_list:
        external_address = rule.get('external_ip_address')
        external_port = rule.get('external_port') or ''
        local_address = rule.get('local_ip_address')
        local_port = rule.get('local_port') or ''
        protocol = protocol_map[rule.get('protocol', 0)]

        values = [external_address, external_port, local_address, local_port, protocol]
        data_entries.append(values)
    headers = [
        'External address',
        'External port',
        'Local address',
        'Local port',
        'Protocol',
    ]
    out = sorted(data_entries, key=lambda x: x[2])
    return tabulate(out, headers=headers, tablefmt='simple')


@_verify
def show_sessions(raw: bool):
    vpp = VPPControl()
    sessions_list: list[dict] = _get_raw_output_sessions(vpp.api)

    if raw:
        return sessions_list

    else:
        return _get_formatted_output_sessions(sessions_list)


@_verify
def show_summary(raw: bool):
    vpp = VPPControl()
    return vpp.cli_cmd('show nat44 summary').reply


@_verify
def show_static(raw: bool):
    vpp = VPPControl()
    rules_list: list[dict] = _get_raw_output_static_rules(vpp.api)

    if raw:
        return rules_list

    else:
        return _get_formatted_output_rules(rules_list)


if __name__ == '__main__':
    try:
        res = vyos.opmode.run(sys.modules[__name__])
        if res:
            print(res)
    except (ValueError, vyos.opmode.Error) as e:
        print(e)
        sys.exit(1)
