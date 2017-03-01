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

from IM.config import Config
from IM.db import DataBase
import cPickle as pickle
import time
import threading


class DB14to15():
    @staticmethod
    def load_data(data_file):
        """ Load Data from DB or file """
        try:
            if data_file:
                data_file = open(data_file, 'rb')
                inf_list = pickle.load(data_file)
                data_file.close()
            else:
                inf_list = DB14to15.get_data_from_db(Config.DATA_DB)
            return inf_list
        except Exception, ex:
            sys.stderr.write("ERROR loading data: " + str(ex) + ".\nCorrect or delete it!! ")
            sys.exit(-1)

    @staticmethod
    def get_data_from_db(db_url):
        db = DataBase(db_url)
        if db.connect():
            if not db.table_exists("inf_list"):
                return {}
            else:
                inf_list = {}
                res = db.select("select * from inf_list order by id desc")
                if len(res) > 0:
                    for elem in res:
                        # inf_id = elem[0]
                        # date = elem[1]
                        try:
                            inf = pickle.loads(elem[2])
                            inf_list[inf.id] = inf
                        except:
                            sys.stderr.write("ERROR reading infrastructure from database, ignoring it!.")
                else:
                    sys.stderr.write("ERROR getting inf_list from database!.")
                    sys.exit(-1)

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

    @staticmethod
    def complete_data():
        # complete data to avoid error in deserialize functions
        for inf_id in IM.InfrastructureList.InfrastructureList.infrastructure_list.keys():
            IM.InfrastructureList.InfrastructureList.infrastructure_list[inf_id]._lock = threading.Lock()
            IM.InfrastructureList.InfrastructureList.infrastructure_list[inf_id].cm = None
            IM.InfrastructureList.InfrastructureList.infrastructure_list[inf_id].ctxt_tasks = None
            IM.InfrastructureList.InfrastructureList.infrastructure_list[inf_id].conf_threads = None
            for vm in IM.InfrastructureList.InfrastructureList.infrastructure_list[inf_id].vm_list:
                vm._lock = threading.Lock()
                vm.cloud_connector = None
                vm.inf = None

if __name__ == "__main__":
    if not Config.DATA_DB:
        sys.stderr.write("No DATA_DB defined in the im.cfg file!!")
        sys.exit(-1)

    data_file = None
    if len(sys.argv) > 1:
        data_file = sys.argv[1]
        sys.stdout.write("Using %s as 1.4.X datafile.\n" % data_file)
        sys.stdout.write("Saving new data to DB: %s.|n" % Config.DATA_DB)
    else:
        sys.stdout.write("No datafile defined. Reading data from DB: %s.\n" % Config.DATA_DB)
        sys.stdout.write("Previous table inf_list will be renamed to inf_list_XXXXXX.")

    import IM.InfrastructureList
    inf_list = DB14to15.load_data(data_file)
    DB14to15.rename_old_data()
    # To create the new table
    IM.InfrastructureList.InfrastructureList.load_data()
    IM.InfrastructureList.InfrastructureList.infrastructure_list = inf_list
    DB14to15.complete_data()
    for inf_id in IM.InfrastructureList.InfrastructureList.infrastructure_list.keys():
        IM.InfrastructureList.InfrastructureList.save_data(inf_id)
