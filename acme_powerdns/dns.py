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

import logging

import requests
from dns import query, tsig, tsigkeyring, update


class NSUpdate:

    def __init__(
            self,
            server,
            keyid,
            key,
            algo,
            zone,
            loglevel=logging.INFO,
    ):
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(loglevel)
        self._server  = server
        self._algo    = algo
        self._keyid   = keyid
        self._key     = key
        self._zone    = zone
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


class PowerDNS_API:

    def __init__(
            self,
            server,
            username,
            password,
            domain,
            loglevel=logging.INFO,
    ):
        self._logging   = logging.getLogger(__name__)
        self._logging.setLevel(loglevel)
        self._server    = '{0}'.format(server)
        self._username  = '{0}'.format(username)
        self._password  = '{0}'.format(password)
        self._domain    = '{0}'.format(domain)

        try:
            r = requests.post(
                '{0}/api-token-auth/'.format(self._server),
                data={
                    'username': self._username,
                    'password': self._password,
                },
            )
            if not r.ok:
                self._logging.error('{0} returned {1}'.format(
                    r.url,
                    r.status_code,
                ))
            self._logging.debug('Token response: {0}'.format(r.json()))
            self._token = r.json()['token']
            self._logging.info('Token: {0}'.format(self._token))
        except BaseException as e:
            self._logging.error('{0}'.format(e))

    def create(self, record, rdata):
        r = requests.post(
            '{0}/v1/records/'.format(self._server),
            headers={
                'Authorization': 'JWT {0}'.format(self._token),
            },
            data={
                'name': '{0}'.format(record),
                'type': 'TXT',
                'content': '{0}'.format(rdata),
                'domain': '{0}'.format(self._domain),
            },
        )
        self._logging.debug('Record created: {0}'.format(r.json()))

    def delete(self, record, rdata):
        """Retrieve full record"""
        r = requests.post(
            '{0}/v1/records/'.format(self._server),
            headers={
                'Authorization': 'JWT {0}'.format(self._token),
            },
            data={
                'domain': self._domain,
                'name': record,
            },
        )
        self._logging.debug('Record to delete: {0}'.format(r.json()))
        record_id = r.json()['id']

        """Remove record by id"""
        r = requests.delete(
            '{0}/v1/records/{1}/'.format(self._server, record_id),
            headers={
                'Authorization': 'JWT {0}'.format(self._token),
            },
        )
        self._logging.debug('Record ID deleted: {0}'.format(record_id))
