import logging
import time
import uuid
from flask import Blueprint, request, Response
from IM.awm.models.allocation import AllocationInfo, Allocation, AllocationId
from IM.awm.models.page import PageOfAllocations
from IM.awm.models.error import Error
from IM.awm.models.success import Success
from IM.db import DataBase
from IM.config import Config
from . import require_auth


allocations_bp = Blueprint("allocations", __name__)
logger = logging.getLogger(__name__)


def _init_table(db):
    """ Creates de database """
    if not db.table_exists("allocations"):
        logger.info("Creating allocations table")
        if db.db_type == DataBase.MYSQL:
            db.execute("CREATE TABLE allocations (id VARCHAR(255) PRIMARY KEY, data TEXT, owner VARCHAR(255), created TIMESTAMP)")
        elif db.db_type == DataBase.SQLITE:
            db.execute("CREATE TABLE allocations (id TEXT PRIMARY KEY, data TEXT, owner VARCHAR(255), created TIMESTAMP)")
        elif db.db_type == DataBase.MONGO:
            db.connection.create_collection("allocations")
            db.connection["allocations"].create_index([("id", 1), ("owner", 1)], unique=True)
        return True
    return False


@allocations_bp.route("", methods=["GET"])
@require_auth
def list_allocations(user_info=None):
    # Query params
    try:
        from_ = int(request.args.get("from", 0))
    except (TypeError, ValueError):
        from_ = 0
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100

    # all_nodes_raw = request.args.get("allNodes", "false").lower()
    # all_nodes = all_nodes_raw in ("1", "true", "yes", "on")

    allocations = []
    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            res = db.find("allocations", projection={"data": True}, sort=[('created', -1)])
            for count, elem in enumerate(res):
                if from_ > count:
                    continue
                allocation_data = elem['data']
                allocation_info = AllocationInfo.model_validate_json(allocation_data)
                allocations.append(allocation_info)
                if len(allocations) >= limit:
                    break
            count = len(res)
        else:
            sql = "SELECT data FROM allocations order by created LIMIT %s OFFSET %s"
            res = db.select(sql, (limit, from_))
            for elem in res:
                allocation_data = elem[0]
                allocation_info = AllocationInfo.model_validate_json(allocation_data)
                allocations.append(allocation_info)
            res = db.select("SELECT count(id) from allocations")
            count = res[0][0] if res else 0
        db.close()
    else:
        logger.error("Could not connect to the database")

    page = PageOfAllocations(from_=from_, limit=limit, elements=allocations, count=count)
    return Response(page.model_dump_json(exclude_unset=True), status=200, mimetype="application/json")


def _get_allocation(allocation_id, user_info):
    allocation_info = None
    user_id = user_info['sub']
    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            res = db.find("allocations", {"id": allocation_id, "owner": user_id}, {"id": True, "data": True})
        else:
            res = db.select("SELECT id, data FROM allocations WHERE id = %s and owner = %s", (allocation_id, user_id))
        db.close()
        if res:
            if db.db_type == DataBase.MONGO:
                allocation_data = res[0]["data"]
            else:
                allocation_data = res[0][1]
            allocation_info = AllocationInfo.model_validate_json(allocation_data)
    else:
        logger.error("Could not connect to the database")
    return allocation_info


@allocations_bp.route("/<allocation_id>", methods=["GET"])
@require_auth
def get_allocation(allocation_id, user_info=None):
    allocation_info = _get_allocation(allocation_id, user_info)
    if allocation_info is None:
        err = Error(description="Allocation not found")
        return Response(err.model_dump_json(exclude_unset=True), status=404, mimetype="application/json")
    return Response(allocation_info.model_dump_json(exclude_unset=True), status=200, mimetype="application/json")


@allocations_bp.route("", methods=["POST"])
@require_auth
def create_allocation(user_info=None):
    try:
        payload = request.get_data(as_text=True)
        allocation = Allocation.model_validate_json(payload)
    except Exception as e:
        err = Error(description=f"Invalid allocation body: {e}")
        return Response(err.model_dump_json(exclude_unset=True), status=400, mimetype="application/json")

    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        allocation_id = str(uuid.uuid4())
        if db.db_type == DataBase.MONGO:
            db.replace("allocations", {"id": allocation.id}, {"id": allocation_id, "data": allocation,
                                                              "created": time.time()})
        else:
            db.execute("replace into allocations (id, data, created) values (%s, %s, %s)",
                       (allocation_id, allocation, time.time()))
        db.close()
    else:
        logger.error("Could not connect to the database")

    allocation_id_model = AllocationId(id=allocation_id)
    return Response(allocation_id_model.model_dump_json(exclude_unset=True), status=201, mimetype="application/json")


@allocations_bp.route("/<allocation_id>", methods=["PUT"])
@require_auth
def update_allocation(allocation_id, user_info=None):
    # Not implemented
    err = Error(description="Not implemented")
    return Response(err.model_dump_json(exclude_unset=True), status=503, mimetype="application/json")


@allocations_bp.route("/<allocation_id>", methods=["DELETE"])
@require_auth
def delete_allocation(allocation_id, user_info=None):
    allocation_info = _get_allocation(allocation_id)
    if allocation_info is None:
        err = Error(description="Allocation not found")
        return Response(err.model_dump_json(exclude_unset=True), status=404, mimetype="application/json")

    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            db.delete("allocations", {"id": allocation_id})
        else:
            db.execute("DELETE FROM allocations WHERE id = %s", (allocation_id,))
        db.close()
    else:
        logger.error("Could not connect to the database")

    success = Success(msg="")
    return Response(success.model_dump_json(exclude_unset=True), status=204, mimetype="application/json")
