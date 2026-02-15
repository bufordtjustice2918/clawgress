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

import importlib.util
import os
import unittest


def load_firewall_module():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    module_path = os.path.join(base_dir, 'helpers', 'clawgress-firewall-apply.py')
    spec = importlib.util.spec_from_file_location('clawgress_firewall_apply', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestClawgressFirewallApply(unittest.TestCase):
    def setUp(self):
        self.module = load_firewall_module()

    def test_render_nft_rate_limit(self):
        output = self.module.render_nft(
            v4=['1.2.3.0/24'],
            v6=['2001:db8::/32'],
            ports=[80, 443],
            policy_hash='deadbeef',
            rate_limit_kbps=8000,
        )
        self.assertIn('limit rate 1000 kbytes/second', output)

    def test_render_nft_no_rate_limit(self):
        output = self.module.render_nft(
            v4=['1.2.3.0/24'],
            v6=[],
            ports=[80],
            policy_hash='deadbeef',
        )
        self.assertNotIn('limit rate', output)

    def test_render_nft_sni_allowlist(self):
        output = self.module.render_nft(
            v4=[],
            v6=[],
            ports=[80],
            policy_hash='deadbeef',
            sni_domains=['api.openai.com', '*.example.com'],
        )
        self.assertIn('tls sni', output)
        self.assertIn('api.openai.com', output)

    def test_render_nft_host_policy(self):
        output = self.module.render_nft(
            v4=[],
            v6=[],
            ports=[],
            policy_hash='deadbeef',
            host_policies=[{
                'name': 'agent-1',
                'chain': 'clawgress_host_agent_1',
                'source_v4': ['192.168.1.10/32'],
                'source_v6': [],
                'allow_v4': ['1.2.3.0/24'],
                'allow_v6': [],
                'ports': [443],
                'sni_domains': ['api.openai.com'],
                'rate_limit_kbps': None,
            }],
        )
        self.assertIn('jump clawgress_host_agent_1', output)
        self.assertIn('chain clawgress_host_agent_1', output)

    def test_resolve_proxy_settings_prefers_proxy_domains(self):
        proxy = {
            'mode': 'sni-allowlist',
            'domains': ['api.openai.com']
        }
        allow = {
            'domains': ['example.com']
        }
        mode, domains = self.module.resolve_proxy_settings(proxy, allow)
        self.assertEqual(mode, 'sni-allowlist')
        self.assertIn('api.openai.com', domains)
        self.assertIn('*.api.openai.com', domains)
        self.assertNotIn('example.com', domains)

    def test_render_nft_host_policy_rate_limit(self):
        output = self.module.render_nft(
            v4=[],
            v6=[],
            ports=[],
            policy_hash='deadbeef',
            host_policies=[{
                'name': 'agent-2',
                'chain': 'clawgress_host_agent_2',
                'source_v4': ['192.168.1.20/32'],
                'source_v6': [],
                'allow_v4': ['203.0.113.0/24'],
                'allow_v6': [],
                'ports': [443],
                'sni_domains': [],
                'rate_limit_kbps': 16000,
            }],
        )
        self.assertIn('limit rate 2000 kbytes/second', output)
