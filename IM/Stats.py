# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
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

import os.path
import datetime
import json
import yaml
import logging

from IM.db import DataBase
from IM.auth import Authentication
from IM.config import Config
from IM.VirtualMachine import VirtualMachine


class Stats():

    logger = logging.getLogger('InfrastructureManager')
    """Logger object."""

    @staticmethod
    def _get_data(str_data, auth=None):
        dic = json.loads(str_data)
        resp = {'creation_date': None}
        if 'creation_date' in dic and dic['creation_date']:
            resp['creation_date'] = str(datetime.datetime.fromtimestamp(float(dic['creation_date'])))
        auth = Authentication.deserialize(dic['auth'])
        resp['icon'] = None
        im_auth = auth.getAuthInfo("InfrastructureManager")[0]
        if 'extra_info' in dic and dic['extra_info'] and "TOSCA" in dic['extra_info']:
            try:
                tosca = yaml.safe_load(dic['extra_info']['TOSCA'])
                icon = tosca.get("metadata", {}).get("icon", "")
                resp['icon'] = os.path.basename(icon)[:-4]
            except Exception:
                Stats.logger.exception("Error loading TOSCA.")

        resp['vm_count'] = 0
        resp['cpu_count'] = 0
        resp['memory_size'] = 0
        resp['cloud_type'] = None
        resp['cloud_host'] = None
        resp['hybrid'] = False
        for vm_data in dic['vm_list']:
            vm = VirtualMachine.deserialize(vm_data)

            # only get the cloud of the first VM
            if not resp['cloud_type']:
                resp['cloud_type'] = vm.cloud.type
            if not resp['cloud_host']:
                resp['cloud_host'] = vm.cloud.get_url()
            elif resp['cloud_host'] != vm.cloud.get_url():
                resp['hybrid'] = True

            vm_sys = vm.info.systems[0]
            if vm_sys.getValue('cpu.count'):
                resp['cpu_count'] += vm_sys.getValue('cpu.count')
            if vm_sys.getValue('memory.size'):
                resp['memory_size'] += vm_sys.getFeature('memory.size').getValue('M')
            resp['vm_count'] += 1

        if auth is None or im_auth.compare(auth):
            resp['im_user'] = im_auth.get('username', "")
            return resp
        else:
            return None

    @staticmethod
    def get_stats(init_date="1970-01-01", auth=None):
        """
        Get the statistics from the IM DB.

        Args:

        - init_date(str): Only will be returned infrastructure created afther this date.
        - auth(Authentication): parsed authentication tokens.

        Return: a list of dict with the stats.
        """
        stats = []
        db = DataBase(Config.DATA_DB)
        if db.connect():
            res = db.select("SELECT data, date, id FROM inf_list WHERE date > '%s' order by rowid desc;" % init_date)
            for elem in res:
                data = elem[0]
                date = elem[1]
                inf_id = elem[2]
                res = Stats._get_data(data.decode(), auth)
                if res:
                    res['inf_id'] = inf_id
                    res['last_date'] = str(date)
                    stats.append(res)
                
            db.close()
            return stats
        else:
            Stats.logger.error("ERROR connecting with the database!.")
            return None
