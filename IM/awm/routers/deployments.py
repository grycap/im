import logging
import time
from flask import Blueprint, request, Response
from IM.awm.models.deployment import DeploymentInfo, DeploymentId, Deployment
from IM.awm.models.page import PageOfDeployments
from IM.awm.models.error import Error
from IM.db import DataBase
from IM.awm.routers.tools import get_tool_from_repo
from IM.config import Config
from IM.InfrastructureManager import InfrastructureManager
from IM.tosca.Tosca import Tosca
from IM.auth import Authentication
from . import require_auth, return_error, validate_from_limit

deployments_bp = Blueprint("deployments", __name__, url_prefix="/deployments")

logger = logging.getLogger(__name__)


def _init_table(db):
    """ Creates de database """
    if not db.table_exists("deployments"):
        logger.info("Creating deployments table")
        if db.db_type == DataBase.MYSQL:
            db.execute("CREATE TABLE deployments (id VARCHAR(255) PRIMARY KEY, data TEXT, owner VARCHAR(255), created TIMESTAMP)")
        elif db.db_type == DataBase.SQLITE:
            db.execute("CREATE TABLE deployments (id TEXT PRIMARY KEY, data TEXT, owner VARCHAR(255), created TIMESTAMP)")
        elif db.db_type == DataBase.MONGO:
            db.connection.create_collection("deployments")
            db.connection["deployments"].create_index([("id", 1), ("owner", 1)], unique=True)
        return True
    return False


def _get_im_auth_header(token, allocation=None):
    auth_data = [{"type": "InfrastructureManager", "token": token}]
    if allocation:
        if allocation.kind == "EoscNodeAllocation":
            # @TODO: Implement deployment to EOSC
            pass
        elif allocation.kind == "CredentialsOpenStack":
            ost_auth_data = {"id": "ost", "type": "OpenStack", "auth_version": "3.x_oidc_access_token"}
            ost_auth_data["username"] = allocation.userName
            ost_auth_data["password"] = token
            ost_auth_data["tenant"] = allocation.tenant
            ost_auth_data["host"] = str(allocation.host)
            ost_auth_data["domain"] = allocation.domain
            if allocation.region:
                ost_auth_data["region"] = allocation.region
            # @TODO: Add all the other parameters
            auth_data.append(ost_auth_data)
        elif allocation.kind == "CredentialsKubernetes":
            # @TODO: How the TM will get now the token?
            k8s_auth_data = {"type": "kubernetes", "token": token}
            k8s_auth_data["host"] = str(allocation.host)
        else:
            raise ValueError("Allocation kind not supported")
    return Authentication(auth_data)


def _get_deployment(deployment_id, user_info):
    dep_info = None
    user_token = user_info['token']
    user_id = user_info['sub']
    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            res = db.find("deployments", {"id": deployment_id, "owner": user_id}, {"id": True, "data": True})
        else:
            res = db.select("SELECT id, data FROM deployments WHERE id = %s and owner = %s", (deployment_id, user_id))
        db.close()
        if res:
            if db.db_type == DataBase.MONGO:
                deployment_data = res[0]["data"]
            else:
                deployment_data = res[0][1]
            dep_info = DeploymentInfo.model_validate_json(deployment_data)

            try:
                auth_data = _get_im_auth_header(user_token, dep_info.deployment.allocation)
                state_info = InfrastructureManager.GetInfrastructureState(deployment_id, auth_data)
            except Exception as ex:
                msg = Error(id="400", description=str(ex))
                return msg, 400
            dep_info.status = state_info['state']
        else:
            msg = Error(id="404", description=f"Deployment {deployment_id} not found")
            return msg, 404
    else:
        msg = Error(id="503", description="Database connection failed")
        return msg, 503
    return dep_info, 200


@deployments_bp.route("/deployments", methods=["GET"])
@require_auth
def list_deployments(user_info=None):
    # Query params
    from_, limit = validate_from_limit(request)
    if from_ < 0 or limit < 1:
        return return_error("Invalid 'from' or 'limit' parameter", status_code=400)

    # all_nodes = request.args.get("allNodes", "false").lower() in ("1", "true", "yes")

    deployments = []
    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            res = db.find("deployments", filter={"owner": user_info['sub']}, projection={"data": True}, sort=[('created', -1)])
            for count, elem in enumerate(res):
                if from_ > count:
                    continue
                deployment_data = elem['data']
                deployment_info = DeploymentInfo.model_validate_json(deployment_data)
                # @TODO: Should we get the state from the IM?
                deployments.append(deployment_info)
                if len(deployments) >= limit:
                    break
            count = len(res)
        else:
            sql = "SELECT data FROM deployments WHERE owner = %s order by created LIMIT %s OFFSET %s"
            res = db.select(sql, (user_info['sub'], limit, from_))
            for elem in res:
                deployment_data = elem[0]
                deployment_info = DeploymentInfo.model_validate_json(deployment_data)
                # @TODO: Should we get the state from the IM?
                deployments.append(deployment_info)
            res = db.select("SELECT count(id) from deployments WHERE owner = %s", (user_info['sub'],))
            count = res[0][0] if res else 0
        db.close()
    else:
        return return_error("Database connection failed", 503)

    page = PageOfDeployments(from_=from_, limit=limit, elements=deployments, count=count,
                             self_=request.url)
    base_url = request.url_root.rstrip("/") + request.path
    if from_ + limit < count:
        page.nextPage = f"{base_url}?from={from_ + limit}&limit={limit}"
    if from_ > 0 and count > 0:
        page.prevPage = f"{base_url}?from={max(0, from_ - limit)}&limit={limit}"
    return Response(page.model_dump_json(exclude_unset=True), status=200, mimetype="application/json")


@deployments_bp.route("/deployment/<deployment_id>", methods=["GET"])
@require_auth
def get_deployment(deployment_id, user_info=None):
    dep_info, status_code = _get_deployment(deployment_id, user_info)
    return Response(dep_info.model_dump_json(exclude_unset=True), status=status_code,
                    mimetype="application/json")


@deployments_bp.route("/deployment/<deployment_id>", methods=["DELETE"])
@require_auth
def delete_deployment(deployment_id, user_info=None):
    dep_info, status_code = _get_deployment(deployment_id, user_info)
    if status_code != 200:
        return Response(dep_info.model_dump_json(exclude_unset=True), status=status_code,
                        mimetype="application/json")

    auth_data = _get_im_auth_header(user_info['token'], dep_info.deployment.allocation)
    try:
        InfrastructureManager.DestroyInfrastructure(deployment_id, auth_data)
    except Exception as ex:
        return return_error(f"Failed to delete deployment: {str(ex)}", 400)

    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        if db.db_type == DataBase.MONGO:
            db.delete("deployments", {"id": deployment_id})
        else:
            db.select("DELETE FROM deployments WHERE id = %s", (deployment_id,))
        db.close()
    else:
        return return_error("Database connection failed", 503)

    return Response(status=204)


@deployments_bp.route("/deployments", methods=["POST"])
@require_auth
def deploy_workload(user_info=None):
    # Parse incoming JSON into Deployment model
    try:
        payload = request.get_data(as_text=True)
        deployment_req = Deployment.model_validate_json(payload)
    except Exception as e:
        return return_error(f"Invalid deployment body: {e}", status_code=400)

    # Create the infrastructure in the IM
    if deployment_req.tool.kind == "ToolId":
        tool, status_code = get_tool_from_repo(deployment_req.tool.id, user_info['token'])
        if status_code != 200:
            return Response(tool, status=400, mimetype="application/json")
    else:
        tool = deployment_req.tool

    try:
        tosca_data = Tosca(tool.blueprint, tosca_repo=Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
        _, radl_data = tosca_data.to_radl()
    except Exception as ex:
        return return_error(f"Invalid tool blueprint: {str(ex)}", status_code=400)

    auth_data = _get_im_auth_header(user_info['token'], deployment_req.allocation)

    try:
        deployment_id = InfrastructureManager.CreateInfrastructure(radl_data, auth_data, True)
    except Exception as ex:
        return return_error(f"Failed to create deployment: {str(ex)}", status_code=400)

    db = DataBase(Config.DATA_DB)
    if db.connect():
        _init_table(db)
        deployment_info = DeploymentInfo(id=deployment_id,
                                         deployment=deployment_req,
                                         status="pending",
                                         self_=(f"{request.url_root.rstrip('/')}"
                                                "{Config.AWM_PATH}/deployment/{deployment_id}"))
        data = deployment_info.model_dump_json(exclude_unset=True)
        if db.db_type == DataBase.MONGO:
            res = db.replace("deployments", {"id": deployment_id}, {"id": deployment_id, "data": data,
                                                                    "owner": user_info['sub'],
                                                                    "created": time.time()})
        else:
            res = db.execute("replace into deployments (id, data, created, owner) values (%s, %s, %s, %s)",
                             (deployment_id, data, time.time(), user_info['sub']))
        db.close()
        if not res:
            return return_error("Failed to store deployment information in the database", 503)
    else:
        return return_error("Database connection failed", 503)

    dep_id = DeploymentId(id=deployment_id, kind="DeploymentId", self_=deployment_info.self_)
    return Response(dep_id.model_dump_json(exclude_unset=True), status=201, mimetype="application/json")
