# Used for verifying configuration vpp interfaces
#
# Copyright (C) 2023 VyOS Inc.
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

from vyos import ConfigError

from vyos.vpp.control_host import get_eth_driver


def verify_vpp_remove_kernel_interface(config: dict):
    """Common verify for removed kernel-interfaces.
    Verify that removed kernel interface are not used in 'vpp kernel-interfaces'.

    Example:
      delete vpp interfaces gre|vxlan <tag>X kernel-interface vpp-tunX
      set vpp kernel-interface vpp-tunX
    """
    if (
        'remove' in config
        and 'kernel_interface_removed' in config
        and 'vpp_kernel_interfaces' in config
    ):
        removed_interfaces = config['kernel_interface_removed']
        used_interfaces = config['vpp_kernel_interfaces']

        for interface in removed_interfaces:
            if interface in used_interfaces:
                raise ConfigError(
                    f'"{interface}" is still in use within "vpp kernel-interfaces". '
                    'Please remove it before proceeding.'
                )


def verify_vpp_change_kernel_interface(config: dict):
    """Common verify for changed kernel-interface

    Example:
      set vpp interfaces gre|vxlan <tag> kernel-interface vpp-tunX'
      commit
      set vpp interfaces gre|vxlan <tag> kernel-interface vpp-tunY'
      commit

    check if we have kernel interface config 'vpp kernel-interface vpp-tunX'
    """
    kernel_interface_removed = config.get('kernel_interface_removed', [])
    vpp_kernel_interfaces = config.get('vpp_kernel_interfaces', {})

    for interface in kernel_interface_removed:
        if interface in vpp_kernel_interfaces:
            raise ConfigError(
                f'interface "{interface}" is still in use within "vpp kernel-interfaces". '
                f'Please remove it "vpp kernel-interface {interface}" before proceeding.'
            )


def verify_vpp_exists_kernel_interface(config: dict):
    """Verify is a kernel-interface already created by another VPP LCP pair

    Example:
      set vpp interfaces vxlan vxlan10 kernel-interface vpp-tun10'
      commit
      set vpp interfaces vxlan vxlan20 kernel-interface vpp-tun10'
      commit
    """
    kernel_interface = config.get('kernel_interface', '')
    vpp_interface = config.get('ifname', '')
    candidate_kernel_interfaces = config.get('candidate_kernel_interfaces', [])

    for candidate_kernel_iface in candidate_kernel_interfaces:
        if (
            vpp_interface != candidate_kernel_iface[0]
            and kernel_interface == candidate_kernel_iface[1]
        ):
            raise ConfigError(
                f'Kernel interface "{kernel_interface}" is already configured for {candidate_kernel_iface[0]}. '
                'Duplicates are not allowed.'
            )


def verify_vpp_remove_xconnect_interface(config: dict):
    if not config.get('remove'):
        return
    for xconn_member, xconn_iface in config.get('xconn_members').items():
        if xconn_member == config.get('ifname'):
            raise ConfigError(
                f'interface "{xconn_member}" is still in use within "vpp interfaces xconnect". '
                f'Please remove it from "vpp interface xconnect {xconn_iface}" before proceeding.'
            )


def verify_vpp_tunnel_source_address(config: dict):
    from vyos.utils.network import is_intf_addr_assigned

    address = config.get('source_address')
    for iface in config.get('vpp_ether_vif_ifaces', []):
        if is_intf_addr_assigned(iface, address):
            return True

    raise ConfigError(
        f'Source address "{address}" is not assigned on any Ethernet or VIF interface!'
    )


def verify_dev_driver(iface_name: str, driver_type: str) -> bool:
    # Lists of drivers compatible with DPDK and XDP
    drivers_dpdk: list[str] = [
        'atlantic',
        'bnx2x',
        'e1000',
        'ena',
        'gve',
        'hv_netvsc',
        'i40e',
        'ice',
        'igc',
        'ixgbe',
        'liquidio',
        'mlx4_core',
        'mlx5_core',
        'qede',
        'sfc',
        'tap',
        'tun',
        'virtio_net',
        'vmxnet3',
    ]

    drivers_xdp: list[str] = [
        'atlantic',
        'ena',
        'gve',
        'hv_netvsc',
        'i40e',
        'ice',
        'igb',
        'igc',
        'ixgbe',
        'mlx4_core',
        'mlx5_core',
        'qede',
        'sfc',
        'tap',
        'tun',
        'virtio_net',
        'vmxnet3',
    ]

    driver: str = get_eth_driver(iface_name)

    if driver_type == 'dpdk':
        if driver in drivers_dpdk:
            return True
    elif driver_type == 'xdp':
        if driver in drivers_xdp:
            return True
    else:
        raise ConfigError(f'"Driver type {driver_type} is wrong')

    return False
