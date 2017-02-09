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

import logging

from dns import query, tsig, tsigkeyring, update


class NSUpdate:

    def __init__(self, server, keyid, key, algo, zone):
        self._logging = logging.getLogger(__name__)
        self._server = server
        self._algo = algo
        self._keyid = keyid
        self._key = key
        self._zone = zone
        self._keyring = tsigkeyring.from_text({
            keyid: key
        })

    def create(self, record, rdata):
        self._logging.info(
            'add record [{0}] in zone [{1}] on [{2}] with rdata [{3}]'.format(
                record,
                self._zone,
                self._server,
                rdata,
            )
        )
        data = update.Update(
            self._zone,
            keyname=self._keyid,
            keyring=self._keyring,
            keyalgorithm=getattr(tsig, self._algo),
        )
        data.add(
            '{0}.'.format(record),
            60,
            'TXT',
            rdata,
        )
        response = query.udp(
            data,
            self._server,
        )
        return response

    def delete(self, record, rdata):
        self._logging.info(
            'delete record [{0}] in zone [{1}] on [{2}]'.format(
                record,
                self._zone,
                self._server,
            )
        )
        data = update.Update(
            self._zone,
            keyname=self._keyid,
            keyring=self._keyring,
            keyalgorithm=getattr(tsig, self._algo),
        )
        data.delete(
            '{0}.'.format(record),
            'TXT',
            rdata,
        )
        response = query.udp(
            data,
            self._server,
        )
        return response
