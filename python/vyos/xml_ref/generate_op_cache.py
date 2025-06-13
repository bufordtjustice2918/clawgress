#!/usr/bin/env python3
#
# Copyright (C) 2024-2025 VyOS maintainers and contributors
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

import io
import re
import sys
import glob
import atexit

from argparse import ArgumentParser
from os.path import join
from os.path import abspath
from os.path import dirname
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element
from functools import cmp_to_key
from typing import TypeAlias
from typing import Optional

from op_definition import NodeData
from op_definition import OpKey  # pylint: disable=unused-import # noqa: F401
from op_definition import OpData  # pylint: disable=unused-import # noqa: F401
from op_definition import key_name
from op_definition import key_type

_here = dirname(__file__)

sys.path.append(join(_here, '..'))
# pylint: disable=wrong-import-position,wrong-import-order
from defaults import directories  # noqa: E402


op_ref_cache = abspath(join(_here, 'op_cache.py'))

OptElement: TypeAlias = Optional[Element]


# It is expected that the node_data help txt contained in top-level nodes,
# shared across files, e.g.'show', will reveal inconsistencies; to list
# differences, use --check-xml-consistency
CHECK_XML_CONSISTENCY = False
err_buf = io.StringIO()


def write_err_buf():
    err_buf.seek(0)
    out = err_buf.read()
    print(out)
    err_buf.close()


def translate_exec(s: str) -> str:
    s = s.replace('${vyos_op_scripts_dir}', directories['op_mode'])
    s = s.replace('${vyos_libexec_dir}', directories['base'])
    return s


def translate_position(s: str, pos: list[str]) -> str:
    pos = pos.copy()
    pat: re.Pattern = re.compile(r'(?:\")?\${?([0-9]+)}?(?:\")?')
    t: str = pat.sub(r'_place_holder_\1_', s)

    # preferred to .format(*list) to avoid collisions with braces
    for i, p in enumerate(pos):
        t = t.replace(f'_place_holder_{i+1}_', p)

    return t


def translate_command(s: str, pos: list[str]) -> str:
    s = translate_exec(s)
    s = translate_position(s, pos)
    return s


def translate_op_script(s: str) -> str:
    s = s.replace('${vyos_completion_dir}', directories['completion_dir'])
    s = s.replace('${vyos_op_scripts_dir}', directories['op_mode'])
    return s


def compare_keys(a, b):
    match key_type(a), key_type(b):
        case None, None:
            if key_name(a) == key_name(b):
                return 0
            return -1 if key_name(a) < key_name(b) else 1
        case None, _:
            return -1
        case _, None:
            return 1
        case _, _:
            if key_name(a) == key_name(b):
                if key_type(a) == key_type(b):
                    return 0
                return -1 if key_type(a) < key_type(b) else 1
            return -1 if key_name(a) < key_name(b) else 1


def sort_func(obj: dict, key_func):
    if not obj or not isinstance(obj, dict):
        return obj
    k_list = list(obj.keys())
    if not isinstance(k_list[0], tuple):
        return obj
    k_list = sorted(k_list, key=key_func)
    v_list = map(lambda t: sort_func(obj[t], key_func), k_list)
    return dict(zip(k_list, v_list))


def sort_op_data(obj):
    key_func = cmp_to_key(compare_keys)
    return sort_func(obj, key_func)


def insert_node(
    n: Element, d: dict, path: list[str] = None, parent: NodeData = None
) -> None:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    prop: OptElement = n.find('properties')
    children: OptElement = n.find('children')
    command: OptElement = n.find('command')
    # name is not None as required by schema
    name: str = n.get('name', 'schema_error')
    node_type: str = n.tag
    if path is None:
        path = []

    path.append(name)
    if node_type == 'tagNode':
        path.append(f'{name}-tag_value')

    help_prop: OptElement = None if prop is None else prop.find('help')
    help_text = None if help_prop is None else help_prop.text
    command_text = None if command is None else command.text
    if command_text is not None:
        command_text = translate_command(command_text, path)

    comp_help = {}
    if prop is not None:
        che = prop.findall('completionHelp')

        for c in che:
            comp_list_els = c.findall('list')
            comp_path_els = c.findall('path')
            comp_script_els = c.findall('script')

            comp_lists = []
            for i in comp_list_els:
                comp_lists.append(i.text)

            comp_paths = []
            for i in comp_path_els:
                comp_paths.append(i.text)

            comp_scripts = []
            for i in comp_script_els:
                comp_script_str = translate_op_script(i.text)
                comp_scripts.append(comp_script_str)

            if comp_lists:
                comp_help['list'] = comp_lists
            if comp_paths:
                comp_help['path'] = comp_paths
            if comp_scripts:
                comp_help['script'] = comp_scripts

    cur_node_data = NodeData()
    cur_node_data.name = name
    cur_node_data.node_type = node_type
    cur_node_data.comp_help = comp_help
    cur_node_data.help_text = help_text
    cur_node_data.command = command_text
    cur_node_data.path = path

    value = {('node_data', None): cur_node_data}
    key = (name, node_type)

    cur_value = d.setdefault(key, value)

    if parent and key not in parent.children:
        parent.children.append(key)

    if (
        CHECK_XML_CONSISTENCY
        and cur_value[('node_data', None)] != value[('node_data', None)]
    ):
        err_buf.write(
            f"prev: {cur_value[('node_data', None)]}; new: {value[('node_data', None)]}\n"
        )

    if children is not None:
        inner_nodes = children.iterfind('*')
        for inner_n in inner_nodes:
            inner_path = path[:]
            insert_node(inner_n, d[key], inner_path, cur_node_data)


def parse_file(file_path, d):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for n in root.iterfind('*'):
        insert_node(n, d)


def main():
    # pylint: disable=global-statement
    global CHECK_XML_CONSISTENCY

    parser = ArgumentParser(description='generate dict from xml defintions')
    parser.add_argument(
        '--xml-dir',
        type=str,
        required=True,
        help='transcluded xml op-mode-definition file',
    )
    parser.add_argument(
        '--check-xml-consistency',
        action='store_true',
        help='check consistency of node data across files',
    )

    args = vars(parser.parse_args())

    if args['check_xml_consistency']:
        CHECK_XML_CONSISTENCY = True
        atexit.register(write_err_buf)

    xml_dir = abspath(args['xml_dir'])

    d = {}

    for fname in sorted(glob.glob(f'{xml_dir}/*.xml')):
        parse_file(fname, d)

    d = sort_op_data(d)

    with open(op_ref_cache, 'w') as f:
        f.write('from vyos.xml_ref.op_definition import NodeData\n')
        f.write(f'op_reference = {str(d)}')


if __name__ == '__main__':
    main()
