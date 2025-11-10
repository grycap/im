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

import flask
import flask_restx
import logging
import os
import threading
import yaml
import json

from cheroot.wsgi import Server as WSGIServer, PathInfoDispatcher
from cheroot.ssl.builtin import BuiltinSSLAdapter
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from IM.config import Config
from IM import __version__
from IM.rest.utils import return_error
from IM.rest.im.infrastructures import infs_bp
from IM.rest.im.clouds import clouds_bp
from IM.rest.im.oai import oai_bp
from IM.rest.im.service import sys_bp


logger = logging.getLogger('InfrastructureManager')


class RestAPI():

    def __init__(self, host, port):
        self.app = self.init_app()
        self.flask_server = WSGIServer((host, port), PathInfoDispatcher({'/': self.app}))
        if Config.REST_SSL:
            self.flask_server.ssl_adapter = BuiltinSSLAdapter(Config.REST_SSL_CERTFILE,
                                                              Config.REST_SSL_KEYFILE,
                                                              Config.REST_SSL_CA_CERTS)

    def init_app(self):
        app = flask.Flask(__name__)
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
        app.register_blueprint(infs_bp)
        app.register_blueprint(clouds_bp)
        app.register_blueprint(oai_bp)
        app.register_blueprint(sys_bp)

        # Use Flask-RestX to show the Swagger docs
        @app.route('/swagger.json')
        def awm_swagger():
            file_path = os.path.dirname(os.path.abspath(__file__))
            abs_file_path = os.path.join(file_path, 'swagger_api.yaml')
            with open(abs_file_path, 'r', encoding='utf-8') as f:
                im_spec = yaml.safe_load(f)
                im_spec['servers'] = [{
                    'url': f'{flask.request.url_root}',
                    'description': 'Local server'
                }]
            return json.dumps(im_spec), 200, {'Content-Type': 'application/json'}
        flask_restx.Api(app)

        # Activate AWM if configured
        if Config.AWM:
            from IM.rest.awm import awm_bp
            app.register_blueprint(awm_bp, url_prefix=Config.AWM_PATH)

        @app.after_request
        def enable_cors(response):
            """Enable CORS to javascript SDK"""
            if Config.ENABLE_CORS:
                response.headers['Access-Control-Allow-Origin'] = Config.CORS_ORIGIN
                response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, Authorization'
            return response

        @app.route('/<path:url>', methods=['OPTIONS'])
        def ReturnOptions(**kwargs):
            return {}

        @app.errorhandler(HTTPException)
        def handle_http_exception(error):
            return return_error(error.code, error.description)

        return app

    def run(self):
        self.flask_server.start()

    def run_in_thread(self):
        flask_thr = threading.Thread(target=self.run)
        flask_thr.daemon = True
        flask_thr.start()

    def stop(self):
        logger.info('Stopping REST API server...')
        self.flask_server.stop()
