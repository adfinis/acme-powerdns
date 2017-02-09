#!/usr/bin/env python
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

import argparse
import logging
import sys

import yaml


class Config:
    """Load configuration file and validate settings.
    """

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self._logging = logging.getLogger(__name__)

    def argparse(self, args):
        """Parse arguments from cli.

        :param list args: argument list from program call.
        """

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="",
        )
        parser.add_argument(
            "-c", "--config",
            required=False,
            metavar="FILE",
            default="/etc/acme-powerdns/config.yml",
            help="Configuration file",
        )
        parser.add_argument(
            "-l", "--loglevel",
            required=False,
            default='INFO',
            help="""Set the loglevel.
            Possible values are:
            DEBUG, INFO, WARN, ERROR, CRITICAL
            """
        )
        if args:
            argp = parser.parse_args(args)
        else:
            argp = parser.parse_args()

        # set log level
        self._logging.setLevel(argp.loglevel)

        # load configuration
        try:
            self._logging.debug("Load configuration file {0}".format(
                argp.config,
            ))
            with open(argp.config, 'r') as f:
                self._conf = yaml.safe_load(f)
        except BaseException as e:
            self._logging.critical(
                "Error while loading and parsing config {0}".format(
                    argp.config,
                )
            )
            sys.exit(1)

    def get(self):
        """Get configuration.

        :returns: configuration dictionary.
        :rtype: dict
        """
        return self._conf
