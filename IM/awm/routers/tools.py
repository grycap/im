import logging
import yaml
from flask import Blueprint, request, make_response
from IM.awm.models.tool import ToolInfo
from IM.awm.models.page import PageOfTools
from IM.awm.models.error import Error
from IM.oaipmh.utils import Repository
from IM.config import Config
from . import require_auth

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")
logger = logging.getLogger(__name__)


def _build_self_link_for_list(pid: str) -> str:
    base = request.url_root.rstrip("/")
    path = request.path
    if not path.endswith("/"):
        path = path + "/"
    return f"{base}{path}{pid}"


def _get_tool_info_from_repo(elem: str, path: str) -> ToolInfo:
    tosca = yaml.safe_load(elem)
    metadata = tosca.get("metadata", {})
    tool_id = path.replace("/", "_")
    url = _build_self_link_for_list(tool_id)
    tool = ToolInfo(
        id=tool_id,
        self_=url,
        type="vm",  # @TODO: Determine type based on tool_info
        name=metadata.get("template_name"),
        description=tosca.get("description"),
        blueprint=elem,
        blueprint_type="tosca",
    )
    if metadata.get("template_author"):
        tool.author_name = metadata.get("template_author")
    return tool


@tools_bp.route("/", methods=["GET"])
@require_auth
def list_tools(user_info=None):
    # query params with simple validation
    try:
        from_ = int(request.args.get("from", 0))
        limit = int(request.args.get("limit", 100))
    except ValueError:
        msg = Error(description="Invalid 'from' or 'limit' parameter")
        return make_response(msg.model_dump_json(exclude_unset=True), 400, {"Content-Type": "application/json"})

    if from_ < 0 or limit < 1:
        msg = Error(description="Invalid 'from' or 'limit' parameter")
        return make_response(msg.model_dump_json(exclude_unset=True), 400, {"Content-Type": "application/json"})

    # keep support for allNodes param though not used
    # all_nodes = request.args.get("allNodes", "false").lower() in ("1", "true", "yes")

    tools = []
    try:
        repo = Repository.create(Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
        tools_list = repo.list()
    except Exception as e:
        logger.error("Failed to get list of Tools: %s", e)
        msg = Error(description="Failed to get list of Tools")
        return make_response(msg.model_dump_json(exclude_unset=True), 503, {"Content-Type": "application/json"})

    count = 0
    for _, elem in tools_list.items():
        count += 1
        if from_ > count - 1:
            continue
        try:
            tool = _get_tool_info_from_repo(repo.get(elem), elem['path'])
            tools.append(tool)
            if len(tools) >= limit:
                break
        except Exception as ex:
            logger.error("Failed to get tool info: %s", ex)

    page = PageOfTools(from_=from_, limit=limit, elements=tools, count=len(tools_list))
    return make_response(page.model_dump_json(exclude_unset=True), 200, {"Content-Type": "application/json"})


def get_tool_from_repo(tool_id: str, token: str, self_link: str = None):
    # tool_id was provided with underscores; convert back path
    repo_tool_id = tool_id.replace("_", "/")
    try:
        repo = Repository.create(Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
        response = repo.get_by_path(repo_tool_id)
    except Exception as e:
        logger.error("Failed to get tool info: %s", e)
        msg = Error(description="Failed to get tool info")
        return make_response(msg.model_dump_json(exclude_unset=True), 503, {"Content-Type": "application/json"})

    if response.status_code == 404:
        msg = Error(description="Tool not found")
        return msg.model_dump_json(exclude_unset=True), 404
    if response.status_code != 200:
        logger.error("Failed to fetch tool: %s", response.text)
        msg = Error(description="Failed to fetch tool")
        return msg.model_dump_json(exclude_unset=True), 503

    tool = _get_tool_info_from_repo(response.text, repo_tool_id)
    return tool, 200


@tools_bp.route("/<tool_id>", methods=["GET"])
@require_auth
def get_tool(tool_id: str, user_info=None):
    # build self link from current full URL
    self_link = request.url
    tool_or_msg, status_code = get_tool_from_repo(tool_id, user_info["token"], self_link)
    if status_code != 200:
        return make_response(tool_or_msg, status_code, {"Content-Type": "application/json"})
    return make_response(tool_or_msg.model_dump_json(exclude_unset=True), 200, {"Content-Type": "application/json"})
