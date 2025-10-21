from flask import Blueprint
from IM.awm.routers.allocations import allocations_bp
from IM.awm.routers.deployments import deployments_bp
from IM.awm.routers.service import service_bp
from IM.awm.routers.tools import tools_bp
from IM.awm.routers.users import users_bp


awm_bp = Blueprint("awm", __name__)

# registrar los blueprints hijos dentro del principal
awm_bp.register_blueprint(allocations_bp, url_prefix="/allocations")
awm_bp.register_blueprint(deployments_bp, url_prefix="/deployments")
awm_bp.register_blueprint(tools_bp, url_prefix="/tools")
awm_bp.register_blueprint(service_bp, url_prefix="/version")
awm_bp.register_blueprint(users_bp, url_prefix="/user")
