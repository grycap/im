
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
import cPickle as pickle
import logging
import threading

from IM.db import DataBase
from IM.config import Config

'''
Created on 17 nov. 2016

@author: micafer
'''


class InfrastructureList():
    """
    Class to manage the list of infrastructures and the serialization of the data
    """

    infrastructure_list = {}
    """Map from string to :py:class:`InfrastructureInfo`."""

    logger = logging.getLogger('InfrastructureManager')
    """Logger object."""

    _lock = threading.Lock()
    """Threading Lock to avoid concurrency problems."""

    _exiting = False
    """Flag to notice that the IM is going to exit."""

    @staticmethod
    def add_infrastructure(inf):
        """Add a new Infrastructure."""

        with InfrastructureList._lock:
            InfrastructureList.infrastructure_list[inf.id] = inf

    @staticmethod
    def remove_inf(del_inf):
        """Remove destroyed infrastructure."""

        with InfrastructureList._lock:
            del InfrastructureList.infrastructure_list[del_inf.id]

    @staticmethod
    def get_inf_ids():
        """ Get the IDs of the Infrastructures """
        return InfrastructureList.infrastructure_list.keys()

    @staticmethod
    def get_infrastructure(inf_id):
        """ Get the infrastructure object """
        if inf_id in InfrastructureList.infrastructure_list:
            return InfrastructureList.infrastructure_list[inf_id]
        else:
            return None

    @staticmethod
    def deserialize_infrastructure(str_inf):
        """ Get the infrastructure object from serialized data """
        try:
            return pickle.loads(str_inf)
        except Exception, ex:
            InfrastructureList.logger.exception("Error importing the infrastructure, incorrect data")
            raise Exception("Error importing the infrastructure, incorrect data: " + str(ex))

    @staticmethod
    def serialize_infrastructure(inf_data):
        """ Serialize an infrastructure into a string """
        return pickle.dumps(inf_data)

    @staticmethod
    def stop():
        """ Stop securely the IM service """
        # Acquire the lock to avoid writing data to the DATA_FILE
        with InfrastructureList._lock:
            InfrastructureList._exiting = True
            # Stop all the Ctxt threads of the Infrastructures
            for inf in InfrastructureList.infrastructure_list.values():
                inf.stop()

    @staticmethod
    def load_data():
        """ Load Data from DB or file """
        with InfrastructureList._lock:
            try:
                if Config.DATA_DB:
                    inf_list = InfrastructureList._get_data_from_db(
                        Config.DATA_DB)
                    InfrastructureList.infrastructure_list = inf_list
                else:
                    data_file = open(Config.DATA_FILE, 'rb')
                    InfrastructureList.infrastructure_list = pickle.load(
                        data_file)
                    data_file.close()
            except Exception, ex:
                InfrastructureList.logger.exception("ERROR loading data. Correct or delete it!!")
                sys.stderr.write("ERROR loading data: " + str(ex) + ".\nCorrect or delete it!! ")
                sys.exit(-1)

    @staticmethod
    def save_data(inf_id=None):
        """
        Save data to DB or file

        Args:

        - inf_id(str): ID of the infrastructure to save. If None all will be saved.
        """
        with InfrastructureList._lock:
            # to avoid writing data to the file if the IM is exiting
            if not InfrastructureList._exiting:
                try:
                    if Config.DATA_DB:
                        res = InfrastructureList._save_data_to_db(Config.DATA_DB,
                                                                  InfrastructureList.infrastructure_list,
                                                                  inf_id)
                        if not res:
                            InfrastructureList.logger.error("ERROR saving data.\nChanges not stored!!")
                            sys.stderr.write("ERROR saving data.\nChanges not stored!!")
                    else:
                        data_file = open(Config.DATA_FILE, 'wb')
                        pickle.dump(
                            InfrastructureList.infrastructure_list, data_file)
                        data_file.close()
                except Exception, ex:
                    InfrastructureList.logger.exception("ERROR saving data. Changes not stored!!")
                    sys.stderr.write("ERROR saving data: " + str(ex) + ".\nChanges not stored!!")

    @staticmethod
    def _get_data_from_db(db_url):
        db = DataBase(db_url)
        if db.connect():
            if not db.table_exists("inf_list"):
                db.execute(
                    "CREATE TABLE inf_list(id VARCHAR(255) PRIMARY KEY, date TIMESTAMP, data LONGBLOB)")
                db.close()
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
                            if not inf.deleted:
                                inf_list[inf.id] = inf
                        except:
                            InfrastructureList.logger.exception(
                                "ERROR reading infrastructure from database, ignoring it!.")
                else:
                    InfrastructureList.logger.error("ERROR getting inf_list from database!.")

                db.close()
                return inf_list
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")
            return {}

    @staticmethod
    def _save_data_to_db(db_url, inf_list, inf_id=None):
        db = DataBase(db_url)
        if db.connect():
            infs_to_save = inf_list
            if inf_id:
                infs_to_save = {inf_id: inf_list[inf_id]}

            for inf in infs_to_save.values():
                res = db.execute(
                    "replace into inf_list set id = %s, data = %s, date = now()", (inf.id, pickle.dumps(inf)))

            db.close()
            return res
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")
            return None

    @staticmethod
    def _reinit():
        """Restart the class attributes to initial values."""
        InfrastructureList.infrastructure_list = {}
        InfrastructureList._lock = threading.Lock()
