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

    def test_render_nft_time_window(self):
        output = self.module.render_nft(
            v4=['1.2.3.0/24'],
            v6=[],
            ports=[80],
            policy_hash='deadbeef',
            time_window={'days': ['mon', 'tue'], 'start': '09:00', 'end': '17:00'},
        )
        self.assertIn('meta day { Monday, Tuesday }', output)
        self.assertIn('meta hour "09:00"-"17:00"', output)

    def test_render_nft_domain_time_window(self):
        output = self.module.render_nft(
            v4=[],
            v6=[],
            ports=[80],
            policy_hash='deadbeef',
            sni_domains=['api.openai.com'],
            domain_time_windows={
                'api.openai.com': {'days': ['fri'], 'start': '10:00', 'end': '11:00'}
            },
        )
        self.assertIn('tls sni . "api.openai.com"', output)
        self.assertIn('meta day { Friday }', output)
        self.assertIn('meta hour "10:00"-"11:00"', output)

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
        mode, domains, backend, mtls = self.module.resolve_proxy_settings(proxy, allow)
        self.assertEqual(mode, 'sni-allowlist')
        self.assertEqual(backend, 'none')
        self.assertFalse(mtls['enabled'])
        self.assertIn('api.openai.com', domains)
        self.assertIn('*.api.openai.com', domains)
        self.assertNotIn('example.com', domains)

    def test_resolve_proxy_settings_accepts_backend(self):
        proxy = {
            'mode': 'sni-allowlist',
            'backend': 'haproxy',
            'domains': ['api.openai.com']
        }
        mode, domains, backend, mtls = self.module.resolve_proxy_settings(proxy, {'domains': []})
        self.assertEqual(mode, 'sni-allowlist')
        self.assertEqual(backend, 'haproxy')
        self.assertFalse(mtls['enabled'])
        self.assertIn('api.openai.com', domains)

    def test_resolve_proxy_settings_accepts_mtls(self):
        proxy = {
            'mode': 'sni-allowlist',
            'backend': 'haproxy',
            'domains': ['api.openai.com'],
            'mtls': {
                'enabled': True,
                'ca_certificate': '/config/auth/agents-ca.pem',
                'server_certificate': '/config/auth/proxy.pem',
            },
        }
        mode, domains, backend, mtls = self.module.resolve_proxy_settings(proxy, {'domains': []})
        self.assertEqual(mode, 'sni-allowlist')
        self.assertEqual(backend, 'haproxy')
        self.assertTrue(mtls['enabled'])
        self.assertEqual(mtls['ca_certificate'], '/config/auth/agents-ca.pem')
        self.assertEqual(mtls['server_certificate'], '/config/auth/proxy.pem')
        self.assertIn('api.openai.com', domains)

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

    def test_render_nft_host_policy_exfil_caps(self):
        output = self.module.render_nft(
            v4=[],
            v6=[],
            ports=[],
            policy_hash='deadbeef',
            host_policies=[{
                'name': 'agent-3',
                'chain': 'clawgress_host_agent_3',
                'source_v4': ['192.168.1.30/32'],
                'source_v6': [],
                'allow_v4': [],
                'allow_v6': [],
                'ports': [443],
                'sni_domains': ['api.openai.com'],
                'rate_limit_kbps': None,
                'domain_time_windows': {},
                'exfil_limits': {
                    'api.openai.com': ' limit rate 1048576 bytes/hour'
                },
            }],
        )
        self.assertIn('limit rate 1048576 bytes/hour', output)

    def test_render_nft_proxy_redirect(self):
        output = self.module.render_nft(
            v4=['1.2.3.0/24'],
            v6=[],
            ports=[443],
            policy_hash='deadbeef',
            proxy_redirect_port=10443,
        )
        self.assertIn('tcp dport 443 redirect to :10443', output)

    def test_render_haproxy_cfg_contains_domains(self):
        output = self.module.render_haproxy_cfg(['api.openai.com', 'api.anthropic.com'], 'deadbeef')
        self.assertIn('clawgress_tls_sni', output)
        self.assertIn('api.openai.com:443', output)
        self.assertIn('api.anthropic.com:443', output)

    def test_render_haproxy_cfg_mtls_enabled(self):
        output = self.module.render_haproxy_cfg(
            ['api.openai.com'],
            'deadbeef',
            {
                'enabled': True,
                'ca_certificate': '/config/auth/agents-ca.pem',
                'server_certificate': '/config/auth/proxy.pem',
            },
        )
        self.assertIn('verify required', output)
        self.assertIn('ca-file /config/auth/agents-ca.pem', output)
        self.assertIn('crt /config/auth/proxy.pem', output)
        self.assertIn('ssl verify none sni str(api.openai.com)', output)
        self.assertIn('client_dn=%[ssl_c_s_dn]', output)
