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

import sys

sys.path.append("..")
sys.path.append(".")

from IM.InfrastructureInfo import InfrastructureInfo
from IM.VirtualMachine import VirtualMachine
from IM.auth import Authentication
from radl.radl_json import parse_radl as parse_radl_json
from IM.config import Config
from IM.db import DataBase
import time
import json


class DB150to151():
    @staticmethod
    def deserialize_vm(str_data):
        dic = json.loads(str_data)
        if dic['cloud']:
            dic['cloud'] = IM.CloudInfo.CloudInfo.deserialize(dic['cloud'])
        if dic['info']:
            dic['info'] = parse_radl_json(dic['info'])
        if dic['requested_radl']:
            dic['requested_radl'] = parse_radl_json(dic['requested_radl'])

        newvm = VirtualMachine(None, None, None, None, None, None, dic['im_id'])
        newvm.__dict__.update(dic)
        # If we load a VM that is not configured, set it to False
        # because the configuration process will be lost
        if newvm.configured is None:
            newvm.configured = False
        return newvm

    @staticmethod
    def deserialize_info(str_data):
        newinf = InfrastructureInfo()
        dic = json.loads(str_data)
        vm_list = dic['vm_list']
        vm_master_id = dic['vm_master']
        dic['vm_master'] = None
        dic['vm_list'] = []
        if dic['auth']:
            dic['auth'] = Authentication.deserialize(dic['auth'])
        if dic['radl']:
            dic['radl'] = parse_radl_json(dic['radl'])
        if 'extra_info' in dic and dic['extra_info'] and "TOSCA" in dic['extra_info']:
            dic['extra_info']['TOSCA'] = Tosca.deserialize(dic['extra_info']['TOSCA'])
        newinf.__dict__.update(dic)
        newinf.cloud_connector = None
        # Set the ConfManager object and the lock to the data loaded
        newinf.cm = None
        newinf.conf_threads = []
        for vm_data in vm_list:
            vm = DB150to151.deserialize_vm(vm_data)
            vm.inf = newinf
            if vm.im_id == vm_master_id:
                newinf.vm_master = vm
            newinf.vm_list.append(vm)
        return newinf

    @staticmethod
    def get_data_from_db(db_url):
        db = DataBase(db_url)
        if db.connect():
            inf_list = {}
            res = db.select("select * from inf_list where deleted = 0 order by id desc")
            if len(res) > 0:
                for elem in res:
                    try:
                        inf = DB150to151.deserialize_info(elem[3])
                        inf_list[inf.id] = inf
                    except:
                        sys.stderr.write("ERROR reading infrastructure from database, ignoring it!.")
            else:
                sys.stderr.write("No data in database!.")

            db.close()
            return inf_list
        else:
            sys.stderr.write("ERROR connecting with the database!.")
            sys.exit(-1)

    @staticmethod
    def rename_old_data():
        db = DataBase(Config.DATA_DB)
        if db.connect():
            if db.table_exists("inf_list"):
                now = str(int(time.time() * 100))
                if db.db_type == DataBase.SQLITE:
                    db.execute('ALTER TABLE inf_list RENAME TO inf_list_%s;' % now)
                    db.close()
                elif db.db_type == DataBase.MYSQL:
                    db.execute('RENAME TABLE inf_list TO inf_list_%s;' % now)
                    db.close()
                else:
                    db.close()
                    sys.stderr.write("ERROR connecting with the database!.")
                    sys.exit(-1)
            else:
                db.close()
        else:
            sys.stderr.write("ERROR connecting with the database!.")
            sys.exit(-1)


if __name__ == "__main__":
    if not Config.DATA_DB:
        sys.stderr.write("No DATA_DB defined in the im.cfg file!!")
        sys.exit(-1)

    sys.stdout.write("Reading data from DB: %s.\n" % Config.DATA_DB)
    sys.stdout.write("Previous table inf_list will be renamed to inf_list_XXXXXX.\n")

    import IM.InfrastructureList
    inf_list = DB150to151.get_data_from_db(Config.DATA_DB)
    DB150to151.rename_old_data()
    # To create the new table
    sys.stdout.write("Saving data.\n")
    IM.InfrastructureList.InfrastructureList.init_table()
    IM.InfrastructureList.InfrastructureList.infrastructure_list = inf_list
    for inf_id in IM.InfrastructureList.InfrastructureList.infrastructure_list.keys():
        IM.InfrastructureList.InfrastructureList.save_data(inf_id)
