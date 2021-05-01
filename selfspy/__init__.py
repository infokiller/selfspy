#!/usr/bin/env python

# Copyright 2012 David Fendrich

# This file is part of Selfspy

# Selfspy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Selfspy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Selfspy.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import configparser
import os
import sys
import hashlib

from Crypto.Cipher import Blowfish
from lockfile import LockFile

from selfspy.activity_store import ActivityStore
from selfspy.password_dialog import get_password
from selfspy import check_password
from selfspy import config as cfg
import selfspy.models
import selfspy.encryption


def parse_config():
    conf_parser = argparse.ArgumentParser(
        description=__doc__,
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    conf_parser.add_argument(
        "-c",
        "--config",
        help=
        "Config file with defaults. Command line parameters will override those given in the config file. The config file must start with a \"[Defaults]\" section, followed by [argument]=[value] on each line.",
        metavar="FILE")
    args, _ = conf_parser.parse_known_args()

    defaults = {}
    if args.config:
        if not os.path.exists(args.config):
            raise EnvironmentError(
                "Config file %s doesn't exist." % args.config)
        config = configparser.SafeConfigParser()
        config.read([args.config])
        defaults = dict(config.items('Defaults'))
    else:
        xdg_config_dir = os.environ.get('XDG_CONFIG_HOME',
                                        os.path.expandvars('${HOME}/.config'))
        config_file_path = os.path.join(xdg_config_dir, 'selfspy.conf')
        if os.path.exists(config_file_path):
            config = configparser.SafeConfigParser()
            config.read([config_file_path])
            defaults = dict(config.items('Defaults'))

    parser = argparse.ArgumentParser(
        description=
        'Monitor your computer activities and store them in an encrypted database for later analysis or disaster recovery.',
        parents=[conf_parser])
    parser.set_defaults(**defaults)
    parser.add_argument(
        '-p',
        '--password',
        help=
        'Encryption password. If you want to keep your database unencrypted, specify -p "" here. If you don\'t specify a password in the command line arguments or in a config file, a dialog will pop up, asking for the password. The most secure is to not use either command line or config file but instead type it in on startup.'
    )
    parser.add_argument(
        '-d',
        '--data-dir',
        help=
        'Data directory for selfspy, where the database is stored. Remember that Selfspy must have read/write access. Default is %s'
        % cfg.DATA_DIR,
        default=cfg.DATA_DIR)

    parser.add_argument(
        '-n',
        '--no-text',
        action='store_true',
        default=True,
        help=
        'Do not store what you type. This will make your database smaller and less sensitive to security breaches. Process name, window titles, window geometry, mouse clicks, number of keys pressed and key timings will still be stored, but not the actual letters. Key timings are stored to enable activity calculation in selfstats. If this switch is used, you will never be asked for password.'
    )
    parser.add_argument(
        '-r',
        '--no-repeat',
        action='store_true',
        help='Do not store special characters as repeated characters.')

    parser.add_argument(
        '--change-password',
        action="store_true",
        help='Change the password used to encrypt the keys columns and exit.')

    return parser.parse_args()


def _make_legacy_encrypter(password):
    if password == "":
        return None
    return Blowfish.new(hashlib.md5(password.encode('utf8')).digest())


def main():
    try:
        args = vars(parse_config())
    except EnvironmentError as ex:
        print(str(ex))
        sys.exit(1)
    print(args)

    args['data_dir'] = os.path.expanduser(args['data_dir'])

    try:
        os.makedirs(args['data_dir'])
    except OSError:
        pass

    lockname = os.path.join(args['data_dir'], cfg.LOCK_FILE)
    cfg.LOCK = LockFile(lockname)
    if cfg.LOCK.is_locked():
        print('%s is locked! I am probably already running.' % lockname)
        print('If you can find no selfspy process running, it is a stale lock '
              'and you can safely remove it.')
        print('Shutting down.')
        sys.exit(1)

    try_db_conversion = False
    salt_file_path = os.path.join(args['data_dir'], cfg.SALT_FILE)
    if os.path.exists(salt_file_path):
        with open(salt_file_path, 'rb') as f:
            salt = f.read()
    else:
        try_db_conversion = True
        print(
            'No salt file found, generating salt and attempting db conversion')
        salt = os.urandom(16)
        with open(salt_file_path, 'wb') as f:
            f.write(salt)

    def check_with_encrypter(password):
        encrypter = selfspy.encryption.make_encrypter(salt, password)
        return check_password.check(args['data_dir'], encrypter)

    digest_path = os.path.join(args['data_dir'], check_password.DIGEST_NAME)
    if try_db_conversion and os.path.exists(digest_path):
        os.remove(digest_path)

    if args['password'] is None:
        args['password'] = get_password(verify=check_with_encrypter)

    encrypter = selfspy.encryption.make_encrypter(salt, args['password'])

    if try_db_conversion:
        selfspy.models.ENCRYPTER = _make_legacy_encrypter(args['password'])
        sessionmaker = selfspy.models.initialize(
            os.path.join(args['data_dir'], cfg.DBNAME))
        session = sessionmaker()
        try:
            for key in session.query(selfspy.models.Keys).all():
                dtext = key.decrypt_text()
                dkeys = key.decrypt_keys()
                key.encrypt_text(dtext, encrypter)
                key.encrypt_keys(dkeys, encrypter)
            for window in session.query(selfspy.models.Window).all():
                window.set_title(window.title, encrypter)
            session.commit()
        except Exception as e:
            session.rollback()
            raise
    sessionmaker = selfspy.models.initialize(
        os.path.join(args['data_dir'], cfg.DBNAME))
    session = sessionmaker()
    # Test that all window titles can be decrypted
    # for window in session.query(selfspy.models.Window).all():
    #     encrypter.decrypt(window.title.encode('utf8')).decode('utf8')

    if not check_password.check(args['data_dir'], encrypter):
        print('Password failed')
        sys.exit(1)

    if args['change_password']:
        new_password = get_password(message="New Password: ")
        new_encrypter = selfspy.encryption.make_encrypter(salt, new_password)
        print('Re-encrypting your keys...')
        astore = ActivityStore(
            os.path.join(args['data_dir'], cfg.DBNAME),
            encrypter,
            store_text=(not args['no_text']),
            repeat_char=(not args['no_repeat']))
        astore.change_password(new_encrypter)
        # delete the old password.digest
        os.remove(os.path.join(args['data_dir'], check_password.DIGEST_NAME))
        check_password.check(args['data_dir'], new_encrypter)
        # don't assume we want the logger to run afterwards
        print('Exiting...')
        sys.exit(0)

    astore = ActivityStore(
        os.path.join(args['data_dir'], cfg.DBNAME),
        encrypter,
        store_text=(not args['no_text']),
        repeat_char=(not args['no_repeat']))
    try:
        cfg.LOCK.acquire()
        try:
            astore.run()
        except SystemExit:
            astore.close()
    finally:
        cfg.LOCK.release()


if __name__ == '__main__':
    main()
