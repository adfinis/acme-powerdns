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

from dns import query, tsig, tsigkeyring, update


class NSUpdate:

    def __init__(self, logging, keyid, key, algo):
        self._logging = logging
        self._algo = algo
        self._keyid = keyid
        self._key = key
        self._keyring = tsigkeyring.from_text({
            keyid: key
        })

    def create(self, server, zone, record, rdata):
        self._logging.info(
            'add record [{0}] in zone [{1}] on [{2}] with rdata [{3}]'.format(
                record,
                zone,
                server,
                rdata,
            )
        )
        data = update.Update(
            zone,
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
            server,
        )
        return response

    def delete(self, server, zone, record, rdata):
        self._logging.info(
            'delete record [{0}] in zone [{1}] on [{2}]'.format(
                record,
                zone,
                server,
            )
        )
        data = update.Update(
            zone,
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
            server,
        )
        return response
