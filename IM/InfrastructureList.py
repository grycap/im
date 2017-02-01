
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
import logging
import threading

from IM.db import DataBase
from IM.config import Config
import IM.InfrastructureInfo

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
        return InfrastructureList._get_inf_ids_from_db()

    @staticmethod
    def get_infrastructure(inf_id):
        """ Get the infrastructure object """
        if inf_id in InfrastructureList.get_inf_ids():
            if inf_id in InfrastructureList.infrastructure_list:
                inf = InfrastructureList._get_data_from_db(Config.DATA_DB, inf_id)[inf_id]
                InfrastructureList.infrastructure_list[inf_id].update(inf)
            else:
                # Load the data from DB:
                inf = InfrastructureList._get_data_from_db(Config.DATA_DB, inf_id)[inf_id]
                InfrastructureList.infrastructure_list[inf_id] = inf
            return InfrastructureList.infrastructure_list[inf_id]
        else:
            # If Inf is not in the DB but it is in memory
            # the Inf has been deleted in other IM instance
            # so remove from memory
            if inf_id in InfrastructureList.infrastructure_list:
                InfrastructureList.infrastructure_list[inf_id].deleted = True
                InfrastructureList.remove_inf(InfrastructureList.infrastructure_list[inf_id])
            return None

    @staticmethod
    def stop():
        """ Stop securely the IM service """
        # Acquire the lock to avoid writing data to the DATA_FILE
        with InfrastructureList._lock:
            # Stop all the Ctxt threads of the Infrastructures
            for inf in InfrastructureList.infrastructure_list.values():
                inf.stop()

    @staticmethod
    def load_data():
        """ Load Data from DB """
        with InfrastructureList._lock:
            try:
                inf_list = InfrastructureList._get_data_from_db(Config.DATA_DB)
                InfrastructureList.infrastructure_list = inf_list
            except Exception, ex:
                InfrastructureList.logger.exception("ERROR loading data. Correct or delete it!!")
                sys.stderr.write("ERROR loading data: " + str(ex) + ".\nCorrect or delete it!! ")
                sys.exit(-1)

    @staticmethod
    def save_data(inf_id=None):
        """
        Save data to DB

        Args:

        - inf_id(str): ID of the infrastructure to save. If None all will be saved.
        """
        with InfrastructureList._lock:
            try:
                res = InfrastructureList._save_data_to_db(Config.DATA_DB,
                                                          InfrastructureList.infrastructure_list,
                                                          inf_id)
                if not res:
                    InfrastructureList.logger.error("ERROR saving data.\nChanges not stored!!")
                    sys.stderr.write("ERROR saving data.\nChanges not stored!!")
            except Exception, ex:
                InfrastructureList.logger.exception("ERROR saving data. Changes not stored!!")
                sys.stderr.write("ERROR saving data: " + str(ex) + ".\nChanges not stored!!")

    @staticmethod
    def init_table():
        """ Creates de database """
        db = DataBase(Config.DATA_DB)
        if db.connect():
            if not db.table_exists("inf_list"):
                db.execute("CREATE TABLE inf_list(id VARCHAR(255) PRIMARY KEY, deleted INTEGER,"
                           " date TIMESTAMP, data LONGBLOB)")
                db.close()
                return True
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")

        return False

    @staticmethod
    def _get_data_from_db(db_url, inf_id=None):
        if InfrastructureList.init_table():
            return {}
        else:
            db = DataBase(db_url)
            if db.connect():
                inf_list = {}
                if inf_id:
                    res = db.select("select * from inf_list where id = '%s'" % inf_id)
                else:
                    res = db.select("select * from inf_list where deleted = 0 order by id desc")
                if len(res) > 0:
                    for elem in res:
                        # inf_id = elem[0]
                        # date = elem[1]
                        # deleted = elem[2]
                        try:
                            inf = IM.InfrastructureInfo.InfrastructureInfo.deserialize(elem[3])
                            inf_list[inf.id] = inf
                        except:
                            InfrastructureList.logger.exception(
                                "ERROR reading infrastructure from database, ignoring it!.")
                else:
                    InfrastructureList.logger.warn("No data in database!.")

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
                res = db.execute("replace into inf_list (id, deleted, data, date) values (%s, %s, %s, now())",
                                 (inf.id, int(inf.deleted), inf.serialize()))

            db.close()
            return res
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")
            return None

    @staticmethod
    def _get_inf_ids_from_db():
        try:
            db = DataBase(Config.DATA_DB)
            if db.connect():
                inf_list = []
                res = db.select("select id from inf_list where deleted = 0 order by id desc")
                for elem in res:
                    inf_list.append(elem[0])

                db.close()
                return inf_list
            else:
                InfrastructureList.logger.error("ERROR connecting with the database!.")
                return []
        except Exception:
            InfrastructureList.logger.exception("ERROR loading data. Correct or delete it!!")

    @staticmethod
    def _reinit():
        """Restart the class attributes to initial values."""
        InfrastructureList.infrastructure_list = {}
        InfrastructureList._lock = threading.Lock()
        db = DataBase(Config.DATA_DB)
        if db.connect():
            db.execute("delete from inf_list")
            db.close()
