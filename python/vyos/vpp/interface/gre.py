# VyOS implementation of VPP GRE interface
#
# Copyright (C) 2023-2025 VyOS Inc.
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

from vyos.vpp import VPPControl


def show():
    """Show GRE interface
    Example:
      from vyos.vpp.interface import gre
      gre.show()
    """
    return vpp.api.gre_tunnel_dump()


class GREInterface:
    def __init__(self, ifname, source_address, remote, kernel_interface: str = ''):
        self.instance = int(ifname.removeprefix('gre'))
        self.ifname = ifname
        self.src_address = source_address
        self.dst_address = remote
        self.kernel_interface = kernel_interface
        self.vpp = VPPControl()

    def add(self):
        """Create GRE interface
        https://github.com/FDio/vpp/blob/stable/2306/src/plugins/gre/gre.api
        Example:
            from vyos.vpp.interface import GREInterface
            a = GREInterface(ifname='gre0', source_address='192.0.2.1', remote='203.0.113.25')
            a.add()
        """
        self.vpp.api.gre_tunnel_add_del(
            is_add=True,
            tunnel={
                'src': self.src_address,
                'dst': self.dst_address,
                'instance': self.instance,
            },
        )

    def delete(self):
        """Delete GRE interface
        Example:
            from vyos.vpp.interface import GREInterface
            a = GREInterface(ifname='gre0', source_address='192.0.2.1', remote='203.0.113.25')
            a.delete()
        """
        return self.vpp.api.gre_tunnel_add_del(
            is_add=False, tunnel={'src': self.src_address, 'dst': self.dst_address}
        )

    def kernel_add(self):
        """Add LCP pair
        Example:
            from vyos.vpp.interface import GREInterface
            a = GREInterface(ifname='gre0', source_address='192.0.2.1', remote='203.0.113.25')
            a.kernel_add()
        """
        self.vpp.lcp_pair_add(self.ifname, self.kernel_interface, 'tun')

    def kernel_delete(self):
        """Delete LCP pair
        Example:
            from vyos.vpp.interface import GREInterface
            a = GREInterface(ifname='gre0', source_address='192.0.2.1', remote='203.0.113.25')
            a.kernel_delete()
        """
        self.vpp.lcp_pair_del(self.ifname, self.kernel_interface)
