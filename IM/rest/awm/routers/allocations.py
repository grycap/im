import logging
import time
import uuid
from flask import Blueprint, request, Response
from IM.rest.awm.models.allocation import AllocationInfo, Allocation, AllocationId
from IM.rest.awm.models.page import PageOfAllocations
from IM.rest.awm.models.success import Success
from IM.db import DataBase
from IM.config import Config
import IM.rest.awm
from . import require_auth, return_error, validate_from_limit


allocations_bp = Blueprint("allocations", __name__)
logger = logging.getLogger(__name__)


def _init_table(db: DataBase) -> bool:
    """Creates de database."""
    if not db.table_exists("allocations"):
        logger.info("Creating allocations table")
        if db.db_type == DataBase.MYSQL:
            db.execute("CREATE TABLE allocations (id VARCHAR(255) PRIMARY KEY, data TEXT, "
                       "owner VARCHAR(255), created TIMESTAMP)")
        elif db.db_type == DataBase.SQLITE:
            db.execute("CREATE TABLE allocations (id TEXT PRIMARY KEY, data TEXT, "
                       "owner VARCHAR(255), created TIMESTAMP)")
        elif db.db_type == DataBase.MONGO:
            db.connection.create_collection("allocations")
            db.connection["allocations"].create_index([("id", 1), ("owner", 1)], unique=True)
        return True
    return False


@allocations_bp.route("/allocations", methods=["GET"])
@require_auth
def list_allocations(user_info: dict = None) -> Response:
    # Query params
    from_, limit = validate_from_limit(request)
    if from_ < 0 or limit < 1:
        return return_error("Invalid 'from' or 'limit' parameter", status_code=400)

    # all_nodes = request.args.get("allNodes", "false").lower() in ("1", "true", "yes")

    allocations = []
    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            res = db.find("allocations", filt={"owner": user_info['sub']},
                          projection={"data": True}, sort=[('created', -1)])
            for count, elem in enumerate(res):
                if from_ > count:
                    continue
                allocation_data = elem['data']
                allocation = Allocation.model_validate_json(allocation_data)
                allocation_info = AllocationInfo(
                    id=elem['id'],
                    self_=f"{request.url_root.rstrip('/')}{Config.AWM_PATH}/allocation/{elem['id']}",
                    allocation=allocation
                )
                allocations.append(allocation_info)
                if len(allocations) >= limit:
                    break
            count = len(res)
        else:
            sql = "SELECT id, data FROM allocations WHERE owner = %s order by created LIMIT %s OFFSET %s"
            res = db.select(sql, (user_info['sub'], limit, from_))
            for elem in res:
                allocation_id = elem[0]
                allocation_data = elem[1]
                allocation = Allocation.model_validate_json(allocation_data)
                allocation_info = AllocationInfo(
                    id=allocation_id,
                    self_=f"{request.url_root.rstrip('/')}{Config.AWM_PATH}/allocation/{allocation_id}",
                    allocation=allocation
                )
                allocations.append(allocation_info)
            res = db.select("SELECT count(id) from allocations WHERE owner = %s", (user_info['sub'],))
            count = res[0][0] if res else 0
        db.close()
    else:
        return return_error("Database connection failed", 503)

    page = PageOfAllocations(from_=from_, limit=limit, elements=allocations, count=count)
    return Response(page.model_dump_json(exclude_unset=True, by_alias=True), status=200, mimetype="application/json")


def _get_allocation(allocation_id: str, user_info: dict) -> AllocationInfo:
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
                allocation_id = res[0]["id"]
                allocation_data = res[0]["data"]
            else:
                allocation_id = res[0][0]
                allocation_data = res[0][1]
            allocation = Allocation.model_validate_json(allocation_data)
            allocation_info = AllocationInfo(
                id=allocation_id,
                self_=f"{request.url_root.rstrip('/')}{Config.AWM_PATH}/allocation/{allocation_id}",
                allocation=allocation
            )
    else:
        logger.error("Database connection failed")
        return None

    return allocation_info


@allocations_bp.route("/allocation/<allocation_id>", methods=["GET"])
@require_auth
def get_allocation(allocation_id: str, user_info: dict = None) -> Response:
    allocation_info = _get_allocation(allocation_id, user_info)
    if allocation_info is None:
        return return_error("Allocation not found", status_code=404)
    return Response(allocation_info.model_dump_json(exclude_unset=True, by_alias=True),
                    status=200, mimetype="application/json")


@allocations_bp.route("/allocations", methods=["POST"])
@require_auth
def create_allocation(user_info: dict = None, allocation_id: str = None) -> Response:
    try:
        payload = request.get_data(as_text=True)
        allocation = Allocation.model_validate_json(payload)
    except Exception as e:
        return return_error(f"Invalid allocation body: {e}", status_code=400)

    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        data = allocation.model_dump_json(exclude_unset=True)
        if db.db_type == DataBase.MONGO:
            if allocation_id is None:  # new allocation
                allocation_id = str(uuid.uuid4())
                replace = {"id": allocation_id, "data": data,
                           "owner": user_info['sub'],
                           "created": time.time()}
            else:  # update existing allocation
                replace = {"id": allocation_id, "data": data,
                           "owner": user_info['sub']}
            db.replace("allocations", {"id": allocation_id}, replace)
        else:
            sql = "replace into allocations (id, data, owner"
            if allocation_id is None:  # new allocation
                allocation_id = str(uuid.uuid4())
                sql += ", created) values (%s, %s, %s, %s)"
                values = (allocation_id, data, user_info['sub'], time.time())
            else:  # update existing allocation
                sql += ") values (%s, %s, %s)"
                values = (allocation_id, data, user_info['sub'])
            db.execute(sql, values)
        db.close()
    else:
        return return_error("Database connection failed", 503)

    url = f"{request.url_root.rstrip('/')}{Config.AWM_PATH}/allocation/{allocation_id}"
    allocation_id_model = AllocationId(id=allocation_id, infoLink=url)
    return Response(allocation_id_model.model_dump_json(exclude_unset=True, by_alias=True),
                    status=201, mimetype="application/json")


def _check_allocation_in_use(allocation_id: str) -> Response:
    # check if this allocation is used in any deployment
    response = IM.rest.awm.routers.deployments.list_deployments()
    if response.status_code != 200:
        return response

    for dep_info in response.json.get("elements"):
        if dep_info.get('deployment', {}).get('allocation', {}).get('id') == allocation_id:
            return return_error("Allocation in use", 409)

    return None


@allocations_bp.route("/allocation/<allocation_id>", methods=["PUT"])
@require_auth
def update_allocation(allocation_id: str, user_info: dict = None) -> Response:
    allocation_info = _get_allocation(allocation_id, user_info)
    if allocation_info is None:
        return return_error("Allocation not found", status_code=404)

    # check if this allocation is used in any deployment
    response = _check_allocation_in_use(allocation_id)
    if response:
        return response

    response = create_allocation(allocation_id=allocation_id)
    if response.status_code != 201:
        return response

    allocation_info = _get_allocation(allocation_id, user_info)
    return Response(allocation_info.model_dump_json(exclude_unset=True, by_alias=True),
                    status=200, mimetype="application/json")


@allocations_bp.route("/allocation/<allocation_id>", methods=["DELETE"])
@require_auth
def delete_allocation(allocation_id: str, user_info: dict = None) -> Response:
    allocation_info = _get_allocation(allocation_id, user_info)
    if allocation_info is None:
        return return_error("Allocation not found", status_code=404)

    # check if this allocation is used in any deployment
    response = _check_allocation_in_use(allocation_id)
    if response:
        return response

    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            db.delete("allocations", {"id": allocation_id})
        else:
            db.execute("DELETE FROM allocations WHERE id = %s", (allocation_id,))
        db.close()
    else:
        return return_error("Database connection failed", 503)

    msg = Success(message="Deleted")
    return Response(msg.model_dump_json(exclude_unset=True), status=200, mimetype="application/json")
