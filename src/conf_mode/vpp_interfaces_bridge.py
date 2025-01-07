#!/usr/bin/env python3
#
# Copyright (C) 2023-2024 VyOS Inc.
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

import os

from vyos.config import Config
from vyos.configdict import leaf_node_changed
from vyos import ConfigError
from vyos.vpp.interface import BridgeInterface
from vyos.vpp.utils import iftunnel_transform


def get_config(config=None, recursive_defaults=True) -> dict:
    """Get Bridge interface configuration

    Args:
        config (vyos.config.Config, optional): The VyOS configuration dictionary
        recursive_defaults (bool, optional): Include recursive defaults
    Returns:
        dict: Bridge interface configuration
    """
    if config:
        conf = config
    else:
        conf = Config()

    base = ['vpp', 'interfaces', 'bridge']
    vpp_interfaces = ['vpp', 'settings', 'interface']

    ifname = os.environ['VYOS_TAGNODE_VALUE']

    # Get config_dict with default values
    config = conf.get_config_dict(
        base + [ifname],
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
        with_defaults=True,
        with_recursive_defaults=recursive_defaults,
    )

    # Get effective config as we need full dicitonary per interface delete
    effective_config = conf.get_config_dict(
        base + [ifname],
        key_mangling=('-', '_'),
        effective=True,
        get_first_key=True,
        no_tag_node_value_mangle=True,
    )

    if effective_config:
        config.update({'effective': effective_config})

    if not conf.exists(base + [ifname]):
        config['remove'] = True

    # Get global vpp interfaces for verify
    config['vpp_interfaces'] = conf.get_config_dict(
        vpp_interfaces,
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
    )

    # determine which members have been removed
    interfaces_removed = leaf_node_changed(conf, base + [ifname, 'member', 'interface'])
    if interfaces_removed:
        config['members_removed'] = interfaces_removed

    config['ifname'] = ifname

    return config


def verify(config):
    if 'remove' in config:
        return None

    # Check if interface exists in vpp before adding to bridge-domain

    allowed_prefixes = ('gre', 'geneve', 'vxlan')

    if 'member' in config:
        for member in config.get('member', {}).get('interface', []):
            # Check if the interface is explicitly listed or starts with allowed prefixes
            if not (
                member in config.get('vpp_interfaces', [])
                or member.startswith(allowed_prefixes)
            ):
                raise ConfigError(
                    f"Interface '{member}' not found in 'vpp settings interface' or does not start with allowed prefixes {allowed_prefixes}"
                )


def generate(config):
    pass


def apply(config):
    ifname = config.get('ifname')
    # vxlan10 in the vpp is vxlan_tunnel10
    interface_transform_filter = ('geneve', 'vxlan')
    # update members
    if 'members_removed' in config:
        i = BridgeInterface(ifname)
        for member in config.get('members_removed'):
            if member.startswith(interface_transform_filter):
                member = iftunnel_transform(member)
            i.detach_member(member=member)

    # Delete bridge domain
    if 'effective' in config:
        ifname = config.get('ifname')
        i = BridgeInterface(ifname)
        i.delete()

    if 'remove' in config:
        return None

    # Add bridge domain
    members = config.get('member', {}).get('interface', '')
    i = BridgeInterface(ifname)
    i.add()
    # Add members to bridge
    if members:
        br = BridgeInterface(ifname)
        for member in members:
            if member.startswith(interface_transform_filter):
                member = iftunnel_transform(member)
            br.add_member(member=member)

    return None


if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
