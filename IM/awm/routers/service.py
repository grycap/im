from flask import Blueprint, Response
from IM.awm.models.success import Success
from IM import __version__

service_bp = Blueprint("service", __name__)


@service_bp.route("", methods=["GET"])
def version():
    return Response(Success(message=__version__).model_dump_json(), status=200, mimetype="application/json")
