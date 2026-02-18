# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.

import unittest


class TestClawgressPolicyModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from src.services.api.rest.models import ClawgressPolicyModel
        except ImportError as exc:
            raise unittest.SkipTest(f'model import unavailable in this env: {exc}') from exc
        cls.model = ClawgressPolicyModel

    def _valid_payload(self):
        return {
            'key': 'id_key',
            'policy': {
                'version': 1,
                'allow': {
                    'domains': ['api.openai.com'],
                    'ips': ['1.2.3.0/24'],
                    'ports': [53, 443],
                },
                'labels': {
                    'api.openai.com': 'llm_provider'
                },
                'proxy': {
                    'mode': 'sni-allowlist',
                    'backend': 'none',
                    'domains': ['api.openai.com']
                },
                'hosts': {
                    'agent-1': {
                        'sources': ['192.168.10.10/32'],
                        'exfil': {
                            'domains': {
                                'api.openai.com': {
                                    'bytes': 1048576,
                                    'period': 'hour'
                                }
                            }
                        }
                    }
                }
            },
            'apply': True,
        }

    def test_accepts_valid_policy(self):
        payload = self._valid_payload()
        obj = self.model(**payload)
        self.assertEqual(obj.policy['version'], 1)

    def test_rejects_invalid_domain_chars(self):
        payload = self._valid_payload()
        payload['policy']['allow']['domains'] = ['bad"domain.com']
        with self.assertRaises(Exception):
            self.model(**payload)

    def test_rejects_invalid_host_name(self):
        payload = self._valid_payload()
        payload['policy']['hosts'] = {'bad host': {'sources': ['192.168.10.10/32']}}
        with self.assertRaises(Exception):
            self.model(**payload)

    def test_rejects_invalid_exfil_period(self):
        payload = self._valid_payload()
        payload['policy']['hosts']['agent-1']['exfil']['domains']['api.openai.com']['period'] = 'week'
        with self.assertRaises(Exception):
            self.model(**payload)

    def test_rejects_invalid_cidr(self):
        payload = self._valid_payload()
        payload['policy']['hosts']['agent-1']['sources'] = ['192.168.999.10/32']
        with self.assertRaises(Exception):
            self.model(**payload)

    def test_accepts_proxy_backend(self):
        payload = self._valid_payload()
        payload['policy']['proxy']['backend'] = 'haproxy'
        obj = self.model(**payload)
        self.assertEqual(obj.policy['proxy']['backend'], 'haproxy')

    def test_accepts_host_proxy_backend(self):
        payload = self._valid_payload()
        payload['policy']['hosts']['agent-1']['proxy'] = {
            'mode': 'sni-allowlist',
            'backend': 'haproxy',
            'domains': ['api.openai.com'],
        }
        obj = self.model(**payload)
        self.assertEqual(obj.policy['hosts']['agent-1']['proxy']['backend'], 'haproxy')

    def test_rejects_invalid_proxy_backend(self):
        payload = self._valid_payload()
        payload['policy']['proxy']['backend'] = 'envoy'
        with self.assertRaises(Exception):
            self.model(**payload)

    def test_rejects_nginx_backend_mvpv21(self):
        payload = self._valid_payload()
        payload['policy']['proxy']['backend'] = 'nginx'
        with self.assertRaises(Exception):
            self.model(**payload)


class TestClawgressTelemetryModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from src.services.api.rest.models import ClawgressTelemetryModel
        except ImportError as exc:
            raise unittest.SkipTest(f'model import unavailable in this env: {exc}') from exc
        cls.model = ClawgressTelemetryModel

    def test_accepts_windowed_view(self):
        obj = self.model(key='id_key', view='agents', window='5m')
        self.assertEqual(obj.window, '5m')

    def test_rejects_missing_target_for_domain(self):
        with self.assertRaises(Exception):
            self.model(key='id_key', view='domain', window='1h')

    def test_accepts_export_redact_flag(self):
        obj = self.model(key='id_key', view='export', window='24h', redact=False)
        self.assertFalse(obj.redact)
