#!/usr/bin/python3

# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import shlex
import argparse

from vyos.defaults import directories
from vyos.remote import get_remote_config
from vyos.config import Config
from vyos.configtree import ConfigTree
from vyos.configtree import mask_inclusive
from vyos.configtree import merge
from vyos.migrate import ConfigMigrate
from vyos.migrate import ConfigMigrateError
from vyos.load_config import load_explicit


parser = argparse.ArgumentParser()
parser.add_argument('config_file', help='config file to merge from')
parser.add_argument(
    '--destructive', action='store_true', help='replace values with those of merge file'
)
parser.add_argument('--paths', nargs='+', help='only merge from listed paths')
parser.add_argument(
    '--migrate', action='store_true', help='migrate config file before merge'
)

args = parser.parse_args()

file_name = args.config_file
paths = [shlex.split(s) for s in args.paths] if args.paths else []

configdir = directories['config']

protocols = ['scp', 'sftp', 'http', 'https', 'ftp', 'tftp']

if any(file_name.startswith(f'{x}://') for x in protocols):
    file_path = get_remote_config(file_name)
    if not file_path:
        sys.exit(f'No such file {file_name}')
else:
    full_path = os.path.realpath(file_name)
    if os.path.isfile(full_path):
        file_path = full_path
    else:
        file_path = os.path.join(configdir, file_name)
        if not os.path.isfile(file_path):
            sys.exit(f'No such file {file_name}')

if args.migrate:
    migrate = ConfigMigrate(file_path)
    try:
        migrate.run()
    except ConfigMigrateError as e:
        sys.exit(e)

with open(file_path) as f:
    merge_str = f.read()

merge_ct = ConfigTree(merge_str)

if paths:
    mask = ConfigTree('')
    for p in paths:
        mask.set(p)

    merge_ct = mask_inclusive(merge_ct, mask)

config = Config()

if config.vyconf_session is not None:
    out, err = config.vyconf_session.merge_config(
        file_path, destructive=args.destructive
    )
    if err:
        sys.exit(out)
    print(out)
else:
    session_ct = config.get_config_tree()
    merge_res = merge(session_ct, merge_ct, destructive=args.destructive)

    load_explicit(merge_res)


if config.session_changed():
    print("Merge complete. Use 'commit' to make changes effective.")
else:
    print('No configuration changes to commit.')
