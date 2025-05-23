#!/usr/bin/env python3
#
# Copyright (C) 2025 VyOS maintainers and contributors
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
#
#


import argparse
import sys
import os

from vyos.configsession import ConfigSession
from vyos.config import Config
from vyos.configdiff import get_config_diff
from vyos.xml_ref import is_leaf


def type_str_to_list(value):
    if isinstance(value, str):
        return value.split()
    raise argparse.ArgumentTypeError('path must be a whitespace separated string')


parser = argparse.ArgumentParser()
parser.add_argument('path', type=type_str_to_list, help='section to reload/rollback')
parser.add_argument('--pid', help='pid of config session')

group = parser.add_mutually_exclusive_group()
group.add_argument('--reload', action='store_true', help='retry proposed commit')
group.add_argument(
    '--rollback', action='store_true', default=True, help='rollback to stable commit'
)

args = parser.parse_args()

path = args.path
reload = args.reload
rollback = args.rollback
pid = args.pid

try:
    if is_leaf(path):
        sys.exit('path is leaf node: neither allowed nor useful')
except ValueError:
    sys.exit('nonexistent path: neither allowed nor useful')

test = Config()
if not test.in_session():
    sys.exit('reset_section not available outside of a config session')

diff = get_config_diff(test)
if not diff.is_node_changed(path):
    # No discrepancies at path after commit, hence no error to revert.
    sys.exit()

del diff
del test


session_id = int(pid) if pid else os.getppid()

# check hint left by vyshim when ConfigError is from apply stage
hint_name = f'/tmp/apply_{session_id}'
if not os.path.exists(hint_name):
    # no apply error; exit
    sys.exit()
else:
    # cleanup hint and continue with reset
    os.unlink(hint_name)

session = ConfigSession(session_id, shared=True)

session_env = session.get_session_env()
config = Config(session_env)

effective = not bool(reload)

d = config.get_config_dict(path, effective=effective, get_first_key=True)

session.discard()

session.delete(path)
session.commit()

if not d:
    # nothing more to do in either case of reload/rollback
    sys.exit()

session.set_section(path, d)
session.commit()
