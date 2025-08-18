#!/usr/bin/env python3
#
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

import os
import shutil
import sys

from argparse import ArgumentParser
from cryptography.fernet import Fernet
from tempfile import NamedTemporaryFile
from tempfile import TemporaryDirectory

from vyos.system.image import is_live_boot
from vyos.tpm import clear_tpm_key
from vyos.tpm import read_tpm_key
from vyos.tpm import write_tpm_key
from vyos.utils.io import ask_input, ask_yes_no
from vyos.utils.process import cmd, run
from vyos.defaults import directories

persistpath_cmd = '/opt/vyatta/sbin/vyos-persistpath'
# mount_path is /opt/vyatta/etc/config as of this writing
mount_path = directories['config']
mount_path_old = f'{mount_path}.old'
dm_device = '/dev/mapper/vyos_config'

def is_opened():
    return os.path.exists(dm_device)

def get_current_image():
    with open('/proc/cmdline', 'r') as f:
        args = f.read().split(" ")
        for arg in args:
            if 'vyos-union' in arg:
                k, v = arg.split("=")
                path_split = v.split("/")
                return path_split[-1]
    return None

def load_config(key):
    if not key:
        return

    persist_path = cmd(persistpath_cmd).strip()
    image_name = get_current_image()
    image_path = os.path.join(persist_path, 'luks', image_name)

    if is_opened():
        print('Encrypted config volume is already mounted')
        return

    with NamedTemporaryFile(dir='/dev/shm', delete=False) as f:
        f.write(key)
        key_file = f.name

    cmd(f'cryptsetup -q open {image_path} vyos_config --key-file={key_file}')

    run(f'umount {mount_path}')
    cmd(f'mount /dev/mapper/vyos_config {mount_path}')
    cmd(f'chgrp -R vyattacfg {mount_path}')

    os.unlink(key_file)

    return True

def encrypt_config(key, recovery_key=None, is_tpm=True):
    # Clear and write key to TPM
    if is_tpm:
        try:
            clear_tpm_key()
        except:
            pass
        write_tpm_key(key)

    persist_path = cmd(persistpath_cmd).strip()
    size = ask_input('Enter size of encrypted config partition (MB): ', numeric_only=True, default=512)

    luks_folder = os.path.join(persist_path, 'luks')

    if not os.path.isdir(luks_folder):
        os.mkdir(luks_folder)

    image_name = get_current_image()
    image_path = os.path.join(luks_folder, image_name)

    try:
        # Create file for encrypted config
        cmd(f'fallocate -l {size}M {image_path}')

        # Write TPM key for slot #1
        with NamedTemporaryFile(dir='/dev/shm', delete=False) as f:
            f.write(key)
            key_file = f.name

        # Format and add main key to volume
        cmd(f'cryptsetup -q luksFormat {image_path} {key_file}')

        if recovery_key:
            # Write recovery key for slot 2
            with NamedTemporaryFile(dir='/dev/shm', delete=False) as f:
                f.write(recovery_key)
                recovery_key_file = f.name

            cmd(f'cryptsetup -q luksAddKey {image_path} {recovery_key_file} --key-file={key_file}')

        # Open encrypted volume and format with ext4
        cmd(f'cryptsetup -q open {image_path} vyos_config --key-file={key_file}')
        cmd('mkfs.ext4 /dev/mapper/vyos_config')
    except Exception as e:
        print('An error occurred while creating the encrypted config volume, aborting.')

        if os.path.exists('/dev/mapper/vyos_config'):
            run('cryptsetup -q close vyos_config')

        if os.path.exists(image_path):
            os.unlink(image_path)

        raise e

    with TemporaryDirectory() as d:
        cmd(f'mount /dev/mapper/vyos_config {d}')

        # Move mount_path to encrypted volume
        shutil.copytree(mount_path, d, copy_function=shutil.move, dirs_exist_ok=True)
        cmd(f'chgrp -R vyattacfg {d}')
        cmd(f'umount {d}')

    os.unlink(key_file)

    if recovery_key:
        os.unlink(recovery_key_file)

    run(f'umount {mount_path}')
    cmd(f'mount /dev/mapper/vyos_config {mount_path}')
    cmd(f'chgrp vyattacfg {mount_path}')

    return True

def config_backup_folder(base):
    # Get next available backup folder
    if not os.path.exists(base):
        return base

    idx = 1
    while os.path.exists(f'{base}.{idx}'):
        idx += 1
    return f'{base}.{idx}'

def decrypt_config(key):
    if not key:
        return

    persist_path = cmd(persistpath_cmd).strip()
    image_name = get_current_image()
    image_path = os.path.join(persist_path, 'luks', image_name)

    key_file = None

    if not is_opened():
        with NamedTemporaryFile(dir='/dev/shm', delete=False) as f:
            f.write(key)
            key_file = f.name

        cmd(f'cryptsetup -q open {image_path} vyos_config --key-file={key_file}')

    # unmount encrypted volume mount point
    if os.path.ismount(mount_path):
        cmd(f'umount {mount_path}')

    # If /opt/vyatta/etc/config is populated, move to /opt/vyatta/etc/config.old
    if len(os.listdir(mount_path)) > 0:
        backup_path = config_backup_folder(mount_path_old)
        print(f'Moving existing {mount_path} folder to {backup_path}')
        shutil.move(mount_path, backup_path)

    # Temporarily mount encrypted volume and migrate files to
    # /opt/vyatta/etc/config on rootfs
    with TemporaryDirectory() as d:
        cmd(f'mount /dev/mapper/vyos_config {d}')

        # Move encrypted volume to /opt/vyatta/etc/config
        shutil.copytree(d, mount_path, copy_function=shutil.move, dirs_exist_ok=True)
        cmd(f'chgrp -R vyattacfg {mount_path}')

        cmd(f'umount {d}')

    # Close encrypted volume
    cmd('cryptsetup -q close vyos_config')

    # Remove encrypted volume image file and key
    if key_file:
        os.unlink(key_file)
    os.unlink(image_path)

    try:
        clear_tpm_key()
    except:
        pass

    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Must specify action.")
        sys.exit(1)

    if is_live_boot():
        print("Config encryption not available on live-ISO environment")
        sys.exit(1)

    parser = ArgumentParser(description='Config encryption')
    parser.add_argument('--disable', help='Disable encryption', action="store_true")
    parser.add_argument('--enable', help='Enable encryption', action="store_true")
    parser.add_argument('--load', help='Load encrypted config volume', action="store_true")
    args = parser.parse_args()

    if args.disable or args.load:
        persist_path = cmd(persistpath_cmd).strip()
        image_name = get_current_image()
        image_path = os.path.join(persist_path, 'luks', image_name)

        if not os.path.exists(image_path):
            print('Encrypted config volume does not exist, aborting.')
            sys.exit(0)
    elif args.enable and is_opened():
        print('An encrypted config volume is already mapped, aborting.')
        sys.exit(0)

    tpm_exists = os.path.exists('/sys/class/tpm/tpm0')

    key = None
    recovery_key = None
    need_recovery = False

    question_key_str = 'recovery key' if tpm_exists else 'key'

    if tpm_exists:
        if args.enable:
            key = Fernet.generate_key()
        elif args.disable or args.load:
            try:
                key = read_tpm_key()
                need_recovery = False
            except:
                print('Failed to read key from TPM, recovery key required')
                need_recovery = True
    else:
        need_recovery = True

    if args.enable and not tpm_exists:
        print('WARNING: VyOS will boot into a default config when encrypted without a TPM')
        print('You will need to manually login with default credentials and use "encryption load"')
        print(f'to mount the encrypted volume and use "load {mount_path}/config.boot"')

        if not ask_yes_no('Are you sure you want to proceed?'):
            sys.exit(0)

    if need_recovery or (args.enable and not ask_yes_no(f'Automatically generate a {question_key_str}?', default=True)):
        while True:
            recovery_key = ask_input(f'Enter {question_key_str}:', default=None).encode()

            if len(recovery_key) >= 32:
                break

            print('Invalid key - must be at least 32 characters, try again.')
    else:
        recovery_key = Fernet.generate_key()

    try:
        if args.disable:
            decrypt_config(key or recovery_key)

            print('Encrypted config volume has been disabled')
            print(f'Contents have been migrated to {mount_path} on rootfs')
        elif args.load:
            load_config(key or recovery_key)

            print('Encrypted config volume has been mounted')
            print(f'Use "load {mount_path}/config.boot" to load configuration')
        elif args.enable and tpm_exists:
            encrypt_config(key, recovery_key)

            print('Encrypted config volume has been enabled with TPM')
            print('Backup the recovery key in a safe place!')
            print('Recovery key: ' + recovery_key.decode())
        elif args.enable:
            encrypt_config(recovery_key, is_tpm=False)

            print('Encrypted config volume has been enabled without TPM')
            print('Backup the key in a safe place!')
            print('Key: ' + recovery_key.decode())
    except Exception as e:
        word = 'decrypt' if args.disable or args.load else 'encrypt'
        print(f'Failed to {word} config: {e}')
