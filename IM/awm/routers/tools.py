import base64
import logging
import yaml
from typing import Tuple, List
from pydantic import BaseModel
from flask import Blueprint, request, Response
from IM.awm.models.tool import ToolInfo
from IM.awm.models.page import PageOfTools
from IM.awm.models.error import Error
from IM.awm.node_registry import EOSCNodeRegistry
from IM.oaipmh.utils import Repository
from IM.config import Config
from . import require_auth, return_error, validate_from_limit

tools_bp = Blueprint("tools", __name__)
logger = logging.getLogger(__name__)


def _get_tool_type(tosca: dict) -> str:
    try:
        node_templates = tosca.get('topology_template', {}).get('node_templates', {})
        for _, node in node_templates.items():
            if node.get('type', '') == 'tosca.nodes.Container.Application.Docker':
                return "container"
    except Exception:
        logger.exception("Error getting tool type using default 'vm'")
    return "vm"


def _get_tool_info_from_repo(elem: str, path: str, version: str = None) -> ToolInfo:
    tosca = yaml.safe_load(elem)
    metadata = tosca.get("metadata", {})
    tool_id = path.replace("/", "_")
    url = f"{request.url_root.rstrip('/')}{Config.AWM_PATH}/tool/{tool_id}"
    if version:
        url += "?version=%s" % version
    tool = ToolInfo(
        id=tool_id,
        self_=url,
        version='latest',
        type=_get_tool_type(tosca),
        name=metadata.get("template_name", ""),
        description=tosca.get("description", ""),
        blueprint=elem,
        blueprintType="tosca",
    )
    if metadata.get("template_author"):
        tool.authorName = metadata.get("template_author")
    if version:
        tool.version = version
    return tool


def list_remote_tools(from_: int, limit: int, count: int, user_info: dict = None) -> Tuple[int, List[ToolInfo]]:
    total = 0
    num_tools = 0
    tools = []
    for node in EOSCNodeRegistry.list_nodes():
        node_total, node_tools = node.list_tools(from_, limit, count + num_tools, user_info["token"])
        num_tools += len(node_tools) if node_tools else node_total
        total += node_total
        tools.extend(node_tools)
    return total, tools


@tools_bp.route("/tools", methods=["GET"])
@require_auth
def list_tools(user_info: dict = None) -> Response:
    # query params with simple validation
    from_, limit = validate_from_limit(request)
    if from_ < 0 or limit < 1:
        return return_error("Invalid 'from' or 'limit' parameter", status_code=400)

    tools = []
    try:
        repo = Repository.create(Config.AWM_TOOLS_REPO)
        tools_list = repo.list()
    except Exception as e:
        logger.error("Failed to get list of Tools: %s", e)
        msg = Error(description="Failed to get list of Tools")
        return Response(msg.model_dump_json(exclude_unset=True), 503, mimetype="application/json")

    count = 0
    for _, elem in tools_list.items():
        count += 1
        if from_ > count - 1:
            continue
        try:
            tool = _get_tool_info_from_repo(repo.get(elem), elem['path'], elem['sha'])
            tools.append(tool)
            if len(tools) >= limit:
                break
        except Exception as ex:
            logger.error("Failed to get tool info: %s", ex)

    remote_count = 0
    all_nodes = request.args.get("allNodes", "false").lower() in ("1", "true", "yes")
    if all_nodes:
        remote_count, remote_tools = list_remote_tools(from_, limit, count, user_info)
        tools.extend(remote_tools)

    page = PageOfTools(from_=from_, limit=limit, elements=tools, count=len(tools_list) + remote_count)
    return Response(page.model_dump_json(exclude_unset=True, by_alias=True), status=200,
                    mimetype="application/json")


def get_tool_from_repo(tool_id: str, version: str = None) -> Tuple[BaseModel, int]:
    # tool_id was provided with underscores; convert back path
    repo_tool_id = tool_id.replace("_", "/")
    try:
        repo = Repository.create(Config.AWM_TOOLS_REPO)
        if version:
            response = repo.get_by_sha(version)
        else:
            response = repo.get_by_path(repo_tool_id, True)
    except Exception as e:
        logger.error("Failed to get tool info: %s", e)
        msg = Error(id="503", description="Failed to get tool info")
        return msg, 503

    if response.status_code == 404:
        msg = Error(id="404", description="Tool not found")
        return msg, 404
    if response.status_code != 200:
        logger.error("Failed to fetch tool: %s", response.text)
        msg = Error(id="503", description="Failed to fetch tool")
        return msg, 503

    template = base64.b64decode(response.json().get("content").encode()).decode()
    if not version:
        version = response.json().get("sha")

    tool = _get_tool_info_from_repo(template, repo_tool_id, version)
    return tool, 200


@tools_bp.route("/tool/<tool_id>", methods=["GET"])
@require_auth
def get_tool(tool_id: str, user_info: dict = None) -> Response:
    # build self link from current full URL
    version = request.args.get("version")
    if version == 'latest':
        version = None
    tool_or_msg, status_code = get_tool_from_repo(tool_id, version)

    return Response(tool_or_msg.model_dump_json(exclude_unset=True, by_alias=True),
                    status=status_code, mimetype="application/json")
