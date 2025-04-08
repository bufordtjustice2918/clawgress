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

from vyos.config import Config
from vyos import ConfigError
from vyos.vpp.nat.nat44 import Nat44


def get_config(config=None) -> dict:
    if config:
        conf = config
    else:
        conf = Config()

    base = ['vpp', 'nat44', 'source']

    # Get config_dict with default values
    config = conf.get_config_dict(
        base,
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
        with_defaults=True,
        with_recursive_defaults=True,
    )

    # Get effective config as we need full dicitonary per interface delete
    effective_config = conf.get_config_dict(
        base,
        key_mangling=('-', '_'),
        effective=True,
        get_first_key=True,
        no_tag_node_value_mangle=True,
    )

    if not config:
        config['remove'] = True

    if effective_config:
        config.update({'effective': effective_config})

    return config


def verify(config):
    if 'remove' in config:
        return None

    required_keys = {'inside_interface', 'outside_interface'}
    if not all(key in config for key in required_keys):
        missing_keys = required_keys - set(config.keys())
        raise ConfigError(
            f"Required options are missing: {', '.join(missing_keys).replace('_', '-')}"
        )

    if not config.get('translation', {}).get('address'):
        raise ConfigError('Translation requires address')

    if config.get('translation', {}).get('address') == 'masquerade':
        raise ConfigError('Masquerade is not implemented')


def generate(config):
    pass


def apply(config):
    # Delete NAT source
    if 'effective' in config:
        remove_config = config.get('effective')
        interface_in = remove_config.get('inside_interface')
        interface_out = remove_config.get('outside_interface')
        translation_address = remove_config.get('translation', {}).get('address')

        n = Nat44(interface_in, interface_out, translation_address)
        n.delete_nat44_out_interface()
        n.delete_nat44_interface_inside()
        n.delete_nat44_address_range()

    if 'remove' in config:
        return None

    # Add NAT44
    interface_in = config.get('inside_interface')
    interface_out = config.get('outside_interface')
    translation_address = config.get('translation', {}).get('address')

    n = Nat44(interface_in, interface_out, translation_address)
    n.enable_nat44_ed()
    n.enable_nat44_forwarding()
    n.add_nat44_out_interface()
    # n.add_nat44_interface_inside()
    n.add_nat44_address_range()


if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
