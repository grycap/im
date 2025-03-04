
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
import time
import logging
import threading
import json

from IM.db import DataBase
from IM.config import Config
import IM.InfrastructureInfo


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
            if inf.id in InfrastructureList.infrastructure_list:
                raise Exception("Trying to add an existing infrastructure ID.")
            else:
                InfrastructureList.infrastructure_list[inf.id] = inf

    @staticmethod
    def remove_inf(del_inf):
        """Remove destroyed infrastructure."""

        with InfrastructureList._lock:
            if del_inf.id in InfrastructureList.infrastructure_list:
                del InfrastructureList.infrastructure_list[del_inf.id]

    @staticmethod
    def get_inf_ids(auth=None):
        """ Get the IDs of the Infrastructures """
        if auth:
            # In this case only loads the auth data to improve performance
            inf_ids = []
            for inf_id in InfrastructureList._get_inf_ids_from_db(auth):
                inf = None
                res = InfrastructureList._get_data_from_db(Config.DATA_DB, inf_id, auth)
                if res:
                    inf = res[inf_id]
                if inf and inf.is_authorized(auth):
                    inf_ids.append(inf.id)
            return inf_ids
        else:
            return InfrastructureList._get_inf_ids_from_db()

    @staticmethod
    def get_infrastructure(inf_id):
        """ Get the infrastructure object """
        if inf_id in InfrastructureList.infrastructure_list:
            inf = InfrastructureList.infrastructure_list[inf_id]
            if not inf.has_expired():
                inf.touch()
                return inf

        if inf_id in InfrastructureList.get_inf_ids():
            # Load the data from DB:
            res = InfrastructureList._get_data_from_db(Config.DATA_DB, inf_id)
            if res:
                inf = res[inf_id]
                InfrastructureList.infrastructure_list[inf_id] = inf
                return inf
            else:
                return None
        else:
            InfrastructureList.logger.warning("%s not in list of Inf IDs." % inf_id)
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
            except Exception as ex:
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
            except Exception as ex:
                InfrastructureList.logger.exception("ERROR saving data. Changes not stored!!")
                sys.stderr.write("ERROR saving data: " + str(ex) + ".\nChanges not stored!!")

    @staticmethod
    def init_table():
        """ Creates de database """
        db = DataBase(Config.DATA_DB)
        if db.connect():
            if not db.table_exists("inf_list"):
                InfrastructureList.logger.debug("Creating the IM database!.")
                if db.db_type == DataBase.MYSQL:
                    db.execute("CREATE TABLE inf_list(rowid INTEGER NOT NULL AUTO_INCREMENT UNIQUE,"
                               " id VARCHAR(255) PRIMARY KEY, deleted INTEGER, date TIMESTAMP, data LONGTEXT,"
                               " auth TEXT, FULLTEXT(auth), INDEX(deleted))")
                elif db.db_type == DataBase.SQLITE:
                    db.execute("CREATE TABLE inf_list(id VARCHAR(255) PRIMARY KEY, deleted INTEGER,"
                               " date TIMESTAMP, data TEXT, auth TEXT)")
                elif db.db_type == DataBase.MONGO:
                    db.connection.create_collection("inf_list")
                    db.connection["inf_list"].create_index([("id", 1)], unique=True)
                    db.connection["inf_list"].create_index([("deleted", 1)])
                    db.connection["inf_list"].create_index([("auth", 1)])
                db.close()
            return True
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")

        return False

    @staticmethod
    def _get_data_from_db(db_url, inf_id=None, auth=None):
        """
        Get data from DB.
        If no inf_id specified all Infrastructures are loaded.
        If auth is specified only auth data will be loaded.
        """
        if InfrastructureList.init_table():
            db = DataBase(db_url)
            if db.connect():
                inf_list = {}
                data_field = "data"
                if auth:
                    data_field = "auth"
                if inf_id:
                    if db.db_type == DataBase.MONGO:
                        res = db.find("inf_list", {"id": inf_id}, {data_field: True, "deleted": True})
                    else:
                        res = db.select("select " + data_field + ",deleted from inf_list where id = %s",  # nosec
                                        (inf_id,))
                else:
                    if db.db_type == DataBase.MONGO:
                        res = db.find("inf_list", {"deleted": 0}, {data_field: True, "deleted": True}, [('_id', -1)])
                    else:
                        res = db.select("select " + data_field + ",deleted from inf_list where deleted = 0"  # nosec
                                        " order by rowid desc")
                if len(res) > 0:
                    for elem in res:
                        if db.db_type == DataBase.MONGO:
                            data = elem[data_field]
                            deleted = elem["deleted"]
                        else:
                            data = elem[0]
                            deleted = elem[1]
                        try:
                            if auth:
                                inf = IM.InfrastructureInfo.InfrastructureInfo.deserialize_auth(inf_id, deleted, data)
                            else:
                                inf = IM.InfrastructureInfo.InfrastructureInfo.deserialize(data)
                            inf_list[inf.id] = inf
                        except Exception:
                            InfrastructureList.logger.exception(
                                "ERROR reading infrastructure from database, ignoring it!.")
                else:
                    msg = ""
                    if inf_id:
                        msg = " for inf ID: %s" % inf_id
                    InfrastructureList.logger.warning("No data in database%s!." % msg)

                db.close()
                return inf_list
            else:
                InfrastructureList.logger.error("ERROR connecting with the database!.")
                return {}
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")
            return {}

    @staticmethod
    def _save_data_to_db(db_url, inf_list, inf_id=None):
        if not inf_list:
            InfrastructureList.logger.info("No data to save to the database!.")
            return True
        db = DataBase(db_url)
        if db.connect():
            infs_to_save = inf_list
            if inf_id:
                infs_to_save = {inf_id: inf_list[inf_id]}

            for inf in infs_to_save.values():
                data = inf.serialize()
                if db.db_type == DataBase.MONGO:
                    res = db.replace("inf_list", {"id": inf.id}, {"id": inf.id, "deleted": int(inf.deleted),
                                                                  "data": data, "date": time.time(),
                                                                  "auth": inf.auth.serialize()})
                else:
                    res = db.execute("replace into inf_list (id, deleted, data, date, auth)"
                                     " values (%s, %s, %s, now(), %s)",
                                     (inf.id, int(inf.deleted), json.dumps(data),
                                      json.dumps(inf.auth.serialize())))

            db.close()
            return res
        else:
            InfrastructureList.logger.error("ERROR connecting with the database!.")
            return None

    @staticmethod
    def _gen_where_from_auth(auth):
        like = ""
        if auth:
            for elem in auth.getAuthInfo('InfrastructureManager'):
                if elem.get("admin"):
                    return ""
                if elem.get("username"):
                    if like:
                        like += " or "
                    like += "auth like '%%\"" + elem.get("username") + "\"%%'"

        return like

    @staticmethod
    def _gen_filter_from_auth(auth):
        usernames = []
        if auth:
            for elem in auth.getAuthInfo('InfrastructureManager'):
                if elem.get("admin"):
                    return {}
                if elem.get("username"):
                    usernames.append(elem.get("username"))

        if usernames:
            return {"auth": {"$elemMatch": {"username": {"$in": usernames}}}}
        else:
            return {}

    @staticmethod
    def _get_inf_ids_from_db(auth=None):
        try:
            db = DataBase(Config.DATA_DB)
            if db.connect():
                inf_list = []
                if db.db_type == DataBase.MONGO:
                    filt = InfrastructureList._gen_filter_from_auth(auth)
                    filt["deleted"] = 0
                    res = db.find("inf_list", filt, {"id": True}, [('id', -1)])
                else:
                    like = InfrastructureList._gen_where_from_auth(auth)
                    if like:
                        where = "where deleted = 0 and (%s)" % like
                    else:
                        where = "where deleted = 0"
                    res = db.select("select id from inf_list %s order by rowid desc" % where)  # nosec
                for elem in res:
                    if db.db_type == DataBase.MONGO:
                        inf_list.append(elem['id'])
                    else:
                        inf_list.append(elem[0])

                db.close()
                return inf_list
            else:
                InfrastructureList.logger.error("ERROR connecting with the database!.")
                return []
        except Exception:
            InfrastructureList.logger.exception("ERROR loading data. Correct or delete it!!")
            return []

    @staticmethod
    def _reinit():
        """Restart the class attributes to initial values."""
        InfrastructureList.infrastructure_list = {}
        InfrastructureList._lock = threading.Lock()
        db = DataBase(Config.DATA_DB)
        if db.connect():
            if db.db_type == DataBase.MONGO:
                db.delete("inf_list", {})
            else:
                db.execute("delete from inf_list")
            db.close()
