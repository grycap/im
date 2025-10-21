import logging
from flask import Blueprint, request, Response
from IM.awm.models.allocation import AllocationInfo
from IM.awm.models.page import PageOfAllocations
from IM.awm.models.error import Error
from . import require_auth


allocations_bp = Blueprint("allocations", __name__)
logger = logging.getLogger(__name__)


@allocations_bp.route("/", methods=["GET"])
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

    # @TODO: obtener las allocations reales desde la DB
    page = PageOfAllocations(from_=from_, limit=limit, elements=[], count=0)
    return Response(page.model_dump_json(exclude_unset=True), status=200, mimetype="application/json")


@allocations_bp.route("/<allocation_id>", methods=["GET"])
@require_auth
def get_allocation(allocation_id, user_info=None):
    # Not implemented
    err = Error(description="Not implemented")
    return Response(err.model_dump_json(exclude_unset=True), status=503, mimetype="application/json")
