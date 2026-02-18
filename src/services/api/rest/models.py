# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.


# pylint: disable=too-few-public-methods

import json
import re
import ipaddress
from html import escape
from enum import Enum
from typing import List
from typing import Union
from typing import Dict
from typing import Self
from typing import Any
from typing import ClassVar
from typing import Pattern

from pydantic import BaseModel
from pydantic import StrictStr
from pydantic import StrictInt
from pydantic import StrictBool
from pydantic import field_validator
from pydantic import model_validator
from fastapi.responses import HTMLResponse


def error(code, msg):
    msg = escape(msg, quote=False)
    resp = {'success': False, 'error': msg, 'data': None}
    resp = json.dumps(resp)
    return HTMLResponse(resp, status_code=code)


def success(data):
    resp = {'success': True, 'data': data, 'error': None}
    resp = json.dumps(resp)
    return HTMLResponse(resp)


# Pydantic models for validation
# Pydantic will cast when possible, so use StrictStr validators added as
# needed for additional constraints
# json_schema_extra adds anotations to OpenAPI to add examples


class ApiModel(BaseModel):
    key: StrictStr


class BasePathModel(BaseModel):
    op: StrictStr
    path: List[StrictStr]

    @field_validator('path')
    @classmethod
    def check_non_empty(cls, path: str) -> str:
        if not len(path) > 0:
            raise ValueError('path must be non-empty')
        return path


class BaseConfigureModel(BasePathModel):
    value: StrictStr = None


class ConfigureModel(ApiModel, BaseConfigureModel):
    confirm_time: StrictInt = 0

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'set | delete | comment',
                'path': ['config', 'mode', 'path'],
            }
        }


class ConfirmModel(ApiModel):
    op: StrictStr

class ConfigureListModel(ApiModel):
    commands: List[BaseConfigureModel]
    confirm_time: StrictInt = 0

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'commands': 'list of commands',
            }
        }


class BaseConfigSectionModel(BasePathModel):
    section: Dict


class ConfigSectionModel(ApiModel, BaseConfigSectionModel):
    pass


class ConfigSectionListModel(ApiModel):
    commands: List[BaseConfigSectionModel]


class BaseConfigSectionTreeModel(BaseModel):
    op: StrictStr
    mask: Dict
    config: Dict


class ConfigSectionTreeModel(ApiModel, BaseConfigSectionTreeModel):
    pass


class RetrieveModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]
    configFormat: StrictStr = None

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'returnValue | returnValues | exists | showConfig',
                'path': ['config', 'mode', 'path'],
                'configFormat': 'json (default) | json_ast | raw',
            }
        }


class ConfigFileModel(ApiModel):
    op: StrictStr
    file: StrictStr = None
    string: StrictStr = None
    confirm_time: StrictInt = 0
    destructive: bool = False

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'save | load | merge | confirm',
                'file': 'filename',
                'string': 'config_string'
            }
        }


class ClawgressPolicyModel(ApiModel):
    policy: Dict
    apply: StrictBool = True

    _domain_re: ClassVar[Pattern[str]] = re.compile(
        r'^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',
        re.IGNORECASE,
    )
    _host_name_re: ClassVar[Pattern[str]] = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
    _label_re: ClassVar[Pattern[str]] = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
    _time_re: ClassVar[Pattern[str]] = re.compile(r'^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$')
    _time_periods: ClassVar[set[str]] = {'second', 'minute', 'hour', 'day'}

    @classmethod
    def _validate_domain(cls, domain: str, field_name: str) -> None:
        if not isinstance(domain, str):
            raise ValueError(f'{field_name} must contain string values')
        if not cls._domain_re.match(domain.strip()):
            raise ValueError(f'invalid domain "{domain}" in {field_name}')

    @classmethod
    def _validate_domains(cls, values: Any, field_name: str) -> None:
        if values is None:
            return
        if not isinstance(values, list):
            raise ValueError(f'{field_name} must be a list')
        for value in values:
            cls._validate_domain(value, field_name)

    @classmethod
    def _validate_ips(cls, values: Any, field_name: str) -> None:
        if values is None:
            return
        if not isinstance(values, list):
            raise ValueError(f'{field_name} must be a list')
        for value in values:
            if not isinstance(value, str):
                raise ValueError(f'{field_name} must contain string CIDR values')
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f'invalid CIDR "{value}" in {field_name}') from exc

    @classmethod
    def _validate_ports(cls, values: Any, field_name: str) -> None:
        if values is None:
            return
        if not isinstance(values, list):
            raise ValueError(f'{field_name} must be a list')
        for value in values:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f'{field_name} must contain integer ports')
            if value < 1 or value > 65535:
                raise ValueError(f'port "{value}" out of range in {field_name}')

    @classmethod
    def _validate_time_window(cls, window: Any, field_name: str) -> None:
        if window is None:
            return
        if not isinstance(window, dict):
            raise ValueError(f'{field_name} must be an object')

        days = window.get('days')
        if days is not None:
            if not isinstance(days, list):
                raise ValueError(f'{field_name}.days must be a list')
            for day in days:
                if not isinstance(day, str):
                    raise ValueError(f'{field_name}.days must contain strings')

        for key in ('start', 'end'):
            value = window.get(key)
            if value is None:
                continue
            if not isinstance(value, str) or not cls._time_re.match(value):
                raise ValueError(f'{field_name}.{key} must use HH:MM or HH:MM:SS format')

    @classmethod
    def _validate_domain_time_windows(cls, value: Any, field_name: str) -> None:
        if value is None:
            return
        if not isinstance(value, dict):
            raise ValueError(f'{field_name} must be an object')
        for domain, window in value.items():
            cls._validate_domain(domain, field_name)
            cls._validate_time_window(window, f'{field_name}.{domain}')

    @classmethod
    def _validate_allow(cls, allow: Any, field_name: str) -> None:
        if not isinstance(allow, dict):
            raise ValueError(f'{field_name} must be an object')
        cls._validate_domains(allow.get('domains'), f'{field_name}.domains')
        cls._validate_ips(allow.get('ips'), f'{field_name}.ips')
        cls._validate_ports(allow.get('ports'), f'{field_name}.ports')

    @classmethod
    def _validate_exfil(cls, exfil: Any, field_name: str) -> None:
        if exfil is None:
            return
        if not isinstance(exfil, dict):
            raise ValueError(f'{field_name} must be an object')
        domains = exfil.get('domains')
        if domains is None:
            return
        if not isinstance(domains, dict):
            raise ValueError(f'{field_name}.domains must be an object')
        for domain, cfg in domains.items():
            cls._validate_domain(domain, f'{field_name}.domains')
            if not isinstance(cfg, dict):
                raise ValueError(f'{field_name}.domains.{domain} must be an object')
            bytes_value = cfg.get('bytes')
            period = cfg.get('period')
            if not isinstance(bytes_value, int) or isinstance(bytes_value, bool) or bytes_value <= 0:
                raise ValueError(f'{field_name}.domains.{domain}.bytes must be a positive integer')
            if not isinstance(period, str) or period.lower() not in cls._time_periods:
                raise ValueError(
                    f'{field_name}.domains.{domain}.period must be one of '
                    f'{sorted(cls._time_periods)}'
                )

    @classmethod
    def _validate_proxy(cls, proxy: Any, field_name: str) -> None:
        if proxy is None:
            return
        if not isinstance(proxy, dict):
            raise ValueError(f'{field_name} must be an object')
        mode = proxy.get('mode')
        if mode is not None and mode not in ('disabled', 'sni-allowlist'):
            raise ValueError(f'{field_name}.mode must be "disabled" or "sni-allowlist"')
        backend = proxy.get('backend')
        if backend is not None and backend not in ('none', 'haproxy'):
            raise ValueError(f'{field_name}.backend must be "none" or "haproxy"')
        cls._validate_domains(proxy.get('domains'), f'{field_name}.domains')

        mtls = proxy.get('mtls')
        if mtls is None:
            return
        if not isinstance(mtls, dict):
            raise ValueError(f'{field_name}.mtls must be an object')
        enabled = mtls.get('enabled', False)
        if not isinstance(enabled, bool):
            raise ValueError(f'{field_name}.mtls.enabled must be a boolean')
        ca_certificate = mtls.get('ca_certificate')
        server_certificate = mtls.get('server_certificate')
        if ca_certificate is not None and (not isinstance(ca_certificate, str) or not ca_certificate.startswith('/')):
            raise ValueError(f'{field_name}.mtls.ca_certificate must be an absolute path')
        if server_certificate is not None and (not isinstance(server_certificate, str) or not server_certificate.startswith('/')):
            raise ValueError(f'{field_name}.mtls.server_certificate must be an absolute path')
        if enabled:
            if backend != 'haproxy' or mode != 'sni-allowlist':
                raise ValueError(f'{field_name}.mtls requires proxy mode "sni-allowlist" and backend "haproxy"')
            if not ca_certificate or not server_certificate:
                raise ValueError(f'{field_name}.mtls requires ca_certificate and server_certificate when enabled')

    @classmethod
    def _validate_hosts(cls, hosts: Any, field_name: str) -> None:
        if hosts is None:
            return
        if not isinstance(hosts, dict):
            raise ValueError(f'{field_name} must be an object')
        for host_name, host_cfg in hosts.items():
            if not isinstance(host_name, str) or not cls._host_name_re.match(host_name):
                raise ValueError(f'invalid host name "{host_name}" in {field_name}')
            if not isinstance(host_cfg, dict):
                raise ValueError(f'{field_name}.{host_name} must be an object')

            sources = host_cfg.get('sources')
            if sources is not None:
                cls._validate_ips(sources, f'{field_name}.{host_name}.sources')

            allow = host_cfg.get('allow')
            if allow is not None:
                cls._validate_allow(allow, f'{field_name}.{host_name}.allow')

            limits = host_cfg.get('limits')
            if limits is not None:
                if not isinstance(limits, dict):
                    raise ValueError(f'{field_name}.{host_name}.limits must be an object')
                egress_kbps = limits.get('egress_kbps')
                if egress_kbps is not None:
                    if (
                        not isinstance(egress_kbps, int)
                        or isinstance(egress_kbps, bool)
                        or egress_kbps <= 0
                    ):
                        raise ValueError(
                            f'{field_name}.{host_name}.limits.egress_kbps '
                            f'must be a positive integer'
                        )

            proxy = host_cfg.get('proxy')
            if proxy is not None:
                cls._validate_proxy(proxy, f'{field_name}.{host_name}.proxy')

            cls._validate_time_window(host_cfg.get('time_window'), f'{field_name}.{host_name}.time_window')
            cls._validate_domain_time_windows(
                host_cfg.get('domain_time_windows'),
                f'{field_name}.{host_name}.domain_time_windows',
            )
            cls._validate_exfil(host_cfg.get('exfil'), f'{field_name}.{host_name}.exfil')

    @field_validator('policy')
    @classmethod
    def validate_policy(cls, policy: Any) -> Dict:
        if not isinstance(policy, dict):
            raise ValueError('policy must be an object')

        allowed_top_level = {
            'version',
            'allow',
            'labels',
            'time_window',
            'domain_time_windows',
            'proxy',
            'hosts',
            'limits',
        }
        unknown = sorted(set(policy.keys()) - allowed_top_level)
        if unknown:
            raise ValueError(f'unsupported policy fields: {", ".join(unknown)}')

        version = policy.get('version')
        if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
            raise ValueError('policy.version must be a positive integer')

        cls._validate_allow(policy.get('allow'), 'policy.allow')

        labels = policy.get('labels')
        if labels is not None:
            if not isinstance(labels, dict):
                raise ValueError('policy.labels must be an object')
            for domain, label in labels.items():
                cls._validate_domain(domain, 'policy.labels')
                if not isinstance(label, str) or not cls._label_re.match(label):
                    raise ValueError(f'invalid label "{label}" for domain "{domain}"')

        cls._validate_time_window(policy.get('time_window'), 'policy.time_window')
        cls._validate_domain_time_windows(policy.get('domain_time_windows'), 'policy.domain_time_windows')

        proxy = policy.get('proxy')
        if proxy is not None:
            cls._validate_proxy(proxy, 'policy.proxy')

        limits = policy.get('limits')
        if limits is not None:
            if not isinstance(limits, dict):
                raise ValueError('policy.limits must be an object')
            egress_kbps = limits.get('egress_kbps')
            if egress_kbps is not None:
                if not isinstance(egress_kbps, int) or isinstance(egress_kbps, bool) or egress_kbps <= 0:
                    raise ValueError('policy.limits.egress_kbps must be a positive integer')

        cls._validate_hosts(policy.get('hosts'), 'policy.hosts')
        return policy

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'policy': {
                    'version': 1,
                    'allow': {
                        'domains': ['api.openai.com'],
                        'ips': ['1.2.3.0/24'],
                        'ports': [53, 80, 443],
                    },
                    'labels': {
                        'api.openai.com': 'llm-provider'
                    },
                    'time_window': {
                        'days': ['mon', 'tue'],
                        'start': '09:00',
                        'end': '17:00'
                    },
                    'domain_time_windows': {
                        'api.openai.com': {
                            'days': ['fri'],
                            'start': '10:00',
                            'end': '12:00'
                        }
                    },
                    'proxy': {
                        'mode': 'sni-allowlist',
                        'backend': 'none',
                        'domains': ['api.openai.com'],
                        'mtls': {
                            'enabled': False,
                            'ca_certificate': '/config/auth/agents-ca.pem',
                            'server_certificate': '/config/auth/proxy.pem',
                        },
                    },
                    'hosts': {
                        'agent-1': {
                            'sources': ['192.168.10.10/32'],
                            'allow': {
                                'domains': ['api.openai.com'],
                                'ports': [443]
                            },
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
                'apply': True
            }
        }


class ClawgressTelemetryModel(ApiModel):
    view: StrictStr = None
    target: StrictStr = None
    window: StrictStr = '1h'
    redact: StrictBool = True

    _valid_views: ClassVar[set[str]] = {'agents', 'domains', 'agent', 'domain', 'denies', 'export'}
    _valid_windows: ClassVar[set[str]] = {'1m', '5m', '1h', '24h'}

    @model_validator(mode='after')
    def validate_view(self) -> Self:
        if self.view is not None and self.view not in self._valid_views:
            raise ValueError(f'view must be one of {sorted(self._valid_views)}')
        if self.window not in self._valid_windows:
            raise ValueError(f'window must be one of {sorted(self._valid_windows)}')
        if self.view in {'agent', 'domain'} and not self.target:
            raise ValueError('target is required when view is "agent" or "domain"')
        if self.view not in {'agent', 'domain'} and self.target:
            raise ValueError('target is only valid for view "agent" or "domain"')
        return self

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'view': 'agents',
                'window': '1h',
                'redact': True
            }
        }


class ImageOp(str, Enum):
    add = 'add'
    delete = 'delete'
    show = 'show'
    set_default = 'set_default'


class ImageModel(ApiModel):
    op: ImageOp
    url: StrictStr = None
    name: StrictStr = None

    @model_validator(mode='after')
    def check_data(self) -> Self:
        if self.op == 'add':
            if not self.url:
                raise ValueError('Missing required field "url"')
        elif self.op in ['delete', 'set_default']:
            if not self.name:
                raise ValueError('Missing required field "name"')

        return self

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'add | delete | show | set_default',
                'url': 'imagelocation',
                'name': 'imagename',
            }
        }


class ImportPkiModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]
    passphrase: StrictStr = None

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'import_pki',
                'path': ['op', 'mode', 'path'],
                'passphrase': 'passphrase',
            }
        }


class ContainerImageModel(ApiModel):
    op: StrictStr
    name: StrictStr = None

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'add | delete | show',
                'name': 'imagename',
            }
        }


class GenerateModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'generate',
                'path': ['op', 'mode', 'path'],
            }
        }


class ShowModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'show',
                'path': ['op', 'mode', 'path'],
            }
        }


class RebootModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'reboot',
                'path': ['op', 'mode', 'path'],
            }
        }


class RenewModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'renew',
                'path': ['op', 'mode', 'path'],
            }
        }


class ResetModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'reset',
                'path': ['op', 'mode', 'path'],
            }
        }


class PoweroffModel(ApiModel):
    op: StrictStr
    path: List[StrictStr]

    class Config:
        json_schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'poweroff',
                'path': ['op', 'mode', 'path'],
            }
        }


class TracerouteModel(ApiModel):
    op: StrictStr
    host: StrictStr

    class Config:
        schema_extra = {
            'example': {
                'key': 'id_key',
                'op': 'traceroute',
                'host': 'host',
            }
        }


class InfoQueryParams(BaseModel):
    model_config = {"extra": "forbid"}

    version: bool = True
    hostname: bool = True


class Success(BaseModel):
    success: bool
    data: Union[str, bool, Dict]
    error: str


class Error(BaseModel):
    success: bool = False
    data: Union[str, bool, Dict]
    error: str


responses = {
    200: {'model': Success},
    400: {'model': Error},
    422: {'model': Error, 'description': 'Validation Error'},
    500: {'model': Error},
}
