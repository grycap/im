import os
import yaml
from flask import Blueprint, request
from flask_restx import Api
from IM.awm.routers.allocations import allocations_bp
from IM.awm.routers.deployments import deployments_bp
from IM.awm.routers.service import service_bp
from IM.awm.routers.tools import tools_bp
# from IM.awm.routers.users import users_bp
from IM.config import Config


awm_bp = Blueprint("awm", __name__)
awm_spec = None


@awm_bp.route('/swagger.json')
def awm_swagger():
    awm_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(awm_path, 'awm-api.yaml')
    global awm_spec
    if awm_spec is None:
        with open(abs_file_path, 'r', encoding='utf-8') as f:
            awm_spec = yaml.safe_load(f)
            awm_spec['servers'] = [{
                'url': f'{request.url_root}{Config.AWM_PATH.lstrip("/")}',
                'description': 'Local server'
            }]
    return yaml.safe_dump(awm_spec), 200, {'Content-Type': 'application/x-yaml'}


# registrar los blueprints hijos dentro del principal
awm_bp.register_blueprint(allocations_bp, url_prefix="/")
awm_bp.register_blueprint(deployments_bp, url_prefix="/")
awm_bp.register_blueprint(tools_bp, url_prefix="/")
awm_bp.register_blueprint(service_bp, url_prefix="/version")
# Removed from the spec
# awm_bp.register_blueprint(users_bp, url_prefix="/user")

api = Api(awm_bp, title="AWM API")
