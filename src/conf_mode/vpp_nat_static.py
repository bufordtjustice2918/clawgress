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

from vyos.configdiff import Diff
from vyos.configdiff import get_config_diff
from vyos.configdict import node_changed
from vyos.config import Config
from vyos import ConfigError
from vyos.vpp.nat.nat44 import Nat44Static


protocol_map = {
    'all': 0,
    'icmp': 1,
    'tcp': 6,
    'udp': 17,
}


def get_config(config=None) -> dict:
    if config:
        conf = config
    else:
        conf = Config()

    base = ['vpp', 'nat44', 'static']

    # Get config_dict with default values
    config = conf.get_config_dict(
        base,
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
        with_defaults=True,
        with_recursive_defaults=True,
    )

    # Get effective config as we need full dictionary per interface delete
    effective_config = conf.get_config_dict(
        base,
        key_mangling=('-', '_'),
        effective=True,
        get_first_key=True,
        no_tag_node_value_mangle=True,
    )

    if not config:
        config['remove'] = True

    in_iface_add = []
    in_iface_del = []
    out_iface_add = []
    out_iface_del = []

    changed_rules = node_changed(
        conf,
        base + ['rule'],
        key_mangling=('-', '_'),
        recursive=True,
        expand_nodes=Diff.DELETE | Diff.ADD,
    )
    diff = get_config_diff(conf)

    for rule in changed_rules:
        base_rule = base + ['rule', rule]
        tmp = node_changed(
            conf,
            base_rule,
            key_mangling=('-', '_'),
            recursive=True,
            expand_nodes=Diff.DELETE | Diff.ADD,
        )

        if 'inside_interface' in tmp:
            new, old = diff.get_value_diff(base_rule + ['inside-interface'])
            in_iface_add.append(new) if new else None
            in_iface_del.append(old) if old else None
        if 'outside_interface' in tmp:
            new, old = diff.get_value_diff(base_rule + ['outside-interface'])
            out_iface_add.append(new) if new else None
            out_iface_del.append(old) if old else None

    final_in_iface_add = list(set(in_iface_add) - set(in_iface_del))
    final_in_iface_del = list(set(in_iface_del) - set(in_iface_add))
    final_out_iface_add = list(set(out_iface_add) - set(out_iface_del))
    final_out_iface_del = list(set(out_iface_del) - set(out_iface_add))

    config.update(
        {
            'in_iface_add': final_in_iface_add,
            'in_iface_del': final_in_iface_del,
            'out_iface_add': final_out_iface_add,
            'out_iface_del': final_out_iface_del,
            'changed_rules': changed_rules,
        }
    )

    if effective_config:
        config.update({'effective': effective_config})

    return config


def verify(config):
    if 'remove' in config:
        return None

    required_keys = {'inside_interface', 'outside_interface'}
    for rule, rule_config in config['rule'].items():
        missing_keys = required_keys - rule_config.keys()
        if missing_keys:
            raise ConfigError(
                f"Required options are missing: {', '.join(missing_keys).replace('_', '-')} in rule {rule}"
            )

        if not rule_config.get('local', {}).get('address'):
            raise ConfigError(f'Local settings require address in rule {rule}')

        if not rule_config.get('external', {}).get('address'):
            raise ConfigError(f'External settings require address in rule {rule}')

        has_local_port = 'port' in rule_config.get('local', {})
        has_external_port = 'port' in rule_config.get('external', {})

        if not has_external_port == has_local_port:
            raise ConfigError(
                'Source and destination ports must either both be specified, or neither must be specified'
            )


def generate(config):
    pass


def apply(config):
    n = Nat44Static()

    # Delete inside interfaces
    for interface in config['in_iface_del']:
        n.delete_inside_interface(interface)
    # Delete outside interfaces
    for interface in config['out_iface_del']:
        n.delete_outside_interface(interface)
    # Delete NAT static mapping rules
    for rule in config['changed_rules']:
        if rule in config.get('effective', {}).get('rule', {}):
            rule_config = config['effective']['rule'][rule]
            n.delete_nat44_static_mapping(
                local_ip=rule_config.get('local').get('address'),
                external_ip=rule_config.get('external', {}).get('address', ''),
                local_port=int(rule_config.get('local', {}).get('port', 0)),
                external_port=int(rule_config.get('external', {}).get('port', 0)),
                protocol=protocol_map[rule_config.get('protocol', 'all')],
            )

    if 'remove' in config:
        return None

    # Add NAT44 static mapping rules
    n.enable_nat44_ed()
    for interface in config['in_iface_add']:
        n.add_inside_interface(interface)
    for interface in config['out_iface_add']:
        n.add_outside_interface(interface)
    for rule in config['changed_rules']:
        if rule in config.get('rule', {}):
            rule_config = config['rule'][rule]
            n.add_nat44_static_mapping(
                local_ip=rule_config.get('local').get('address'),
                external_ip=rule_config.get('external', {}).get('address', ''),
                local_port=int(rule_config.get('local', {}).get('port', 0)),
                external_port=int(rule_config.get('external', {}).get('port', 0)),
                protocol=protocol_map[rule_config.get('protocol', 'all')],
            )


if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
