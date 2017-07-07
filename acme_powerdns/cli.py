#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Copyright (c) 2017, Adfinis SyGroup AG
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys

from acme_powerdns import config, directory_handling, dns


def renew_certificates(args=None):
    cfg = config.Config()
    cfg.argparse(args)

    if cfg.get()['updater'] == 'powerdns':
        updater = dns.PowerDNS_API(
            cfg.get()['powerdns']['server'],
            cfg.get()['powerdns']['username'],
            cfg.get()['powerdns']['password'],
        )
    elif cfg.get()['updater'] == 'nsupdate':
        updater = dns.NSUpdate(
            cfg.get()['nsupdate']['server'],
            cfg.get()['nsupdate']['tsig']['keyid'],
            cfg.get()['nsupdate']['tsig']['key'],
            cfg.get()['nsupdate']['tsig']['algo'],
            cfg.get()['nsupdate']['zone'],
        )
    else:
        sys.stderr.write('False configuration option: updater="{0}"\n'.format(
            cfg.get()['updater'],
        ))
        sys.exit(1)

    directories = cfg.get()['directories']
    for directory in directories:
        dir_handle = directory_handling.DirectoryHandling(
            cfg.get()['directory_url'],
            directory['account_key'],
            directory['csr'],
            directory['cert'],
            cfg.get()['days'],
            updater,
        )
        dir_handle.handle()


def main():
    renew_certificates()
    sys.exit(0)


if __name__ == '__main__':
    main()
