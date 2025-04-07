# Copyright 2025 VyOS maintainers and contributors <maintainers@vyos.io>
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
#
#

import tempfile
import shutil

from vyos.proto import vyconf_client
from vyos.migrate import ConfigMigrate
from vyos.migrate import ConfigMigrateError
from vyos.component_version import append_system_version


def output(o):
    out = ''
    for res in (o.output, o.error, o.warning):
        if res is not None:
            out = out + res
    return out


class VyconfSession:
    def __init__(self, token: str = None):
        if token is None:
            out = vyconf_client.send_request('setup_session')
            self.__token = out.output
        else:
            self.__token = token

    def set(self, path: list[str]) -> tuple[str, int]:
        out = vyconf_client.send_request('set', token=self.__token, path=path)
        return output(out), out.status

    def delete(self, path: list[str]) -> tuple[str, int]:
        out = vyconf_client.send_request('delete', token=self.__token, path=path)
        return output(out), out.status

    def commit(self) -> tuple[str, int]:
        out = vyconf_client.send_request('commit', token=self.__token)
        return output(out), out.status

    def discard(self) -> tuple[str, int]:
        out = vyconf_client.send_request('discard', token=self.__token)
        return output(out), out.status

    def session_changed(self) -> bool:
        out = vyconf_client.send_request('session_changed', token=self.__token)
        return not bool(out.status)

    def load_config(self, file: str, migrate: bool = False) -> tuple[str, int]:
        # pylint: disable=consider-using-with
        if migrate:
            tmp = tempfile.NamedTemporaryFile()
            shutil.copy2(file, tmp.name)
            config_migrate = ConfigMigrate(tmp.name)
            try:
                config_migrate.run()
            except ConfigMigrateError as e:
                tmp.close()
                return repr(e), 1
            file = tmp.name
        else:
            tmp = ''

        out = vyconf_client.send_request('load', token=self.__token, location=file)
        if tmp:
            tmp.close()

        return output(out), out.status

    def save_config(self, file: str, append_version: bool = False) -> tuple[str, int]:
        out = vyconf_client.send_request('save', token=self.__token, location=file)
        if append_version:
            append_system_version(file)
        return output(out), out.status

    def show_config(self, path: list[str] = None) -> tuple[str, int]:
        if path is None:
            path = []
        out = vyconf_client.send_request('show_config', token=self.__token, path=path)
        return output(out), out.status

    def __del__(self):
        out = vyconf_client.send_request('teardown', token=self.__token)
        if out.status:
            print(f'Could not tear down session {self.__token}: {output(out)}')
