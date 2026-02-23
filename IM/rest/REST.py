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

import logging
import uvicorn

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from IM.config import Config


logger = logging.getLogger('InfrastructureManager')

app = FastAPI(title="Infrastructure Manager API", version="2.0", docs_url="/",
              root_path=Config.REST_ROOT_PATH if Config.REST_ROOT_PATH != "/" else '')

# Configure CORS
if Config.ENABLE_CORS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[Config.CORS_ORIGIN] if Config.CORS_ORIGIN != "*" else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["Origin", "Accept", "Content-Type", "Authorization"],
    )


class RESTServer():

    REST_URL: str = ''

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.uvicorn_server = None

    def run(self):
        """Run the FastAPI server"""
        config = uvicorn.Config(
            app=app,
            host=self.host,
            port=self.port,
            ssl_keyfile=Config.REST_SSL_KEYFILE if Config.REST_SSL else None,
            ssl_certfile=Config.REST_SSL_CERTFILE if Config.REST_SSL else None,
            ssl_ca_certs=Config.REST_SSL_CA_CERTS if Config.REST_SSL else None,
            log_config=None  # Use existing logging configuration
        )
        self.uvicorn_server = uvicorn.Server(config)
        self.uvicorn_server.run()

    def stop(self):
        """Stop the FastAPI server"""
        logger.info('Stopping REST API server...')
        if self.uvicorn_server:
            self.uvicorn_server.should_exit = True


# ============================================================================
# API Endpoints
# ============================================================================

from IM.rest.routers import clouds, infrastructures, oaipmh, stats, sys, return_error

app.include_router(infrastructures.router)
app.include_router(clouds.router, tags=["Clouds"])
app.include_router(stats.router, tags=["Statistics"])
app.include_router(oaipmh.router, tags=["OAI-PMH"])
app.include_router(sys.router, tags=["System"])


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return return_error(request, exc.status_code, exc.detail)


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.exception("Unhandled exception")
    return return_error(request, 500, str(exc))
