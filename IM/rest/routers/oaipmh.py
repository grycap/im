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
import yaml


from fastapi import APIRouter, Request, Response
from IM import get_ex_error
from IM.config import Config
from IM.oaipmh.oai import OAI
from IM.oaipmh.utils import Repository
from IM.rest.routers import return_error

logger = logging.getLogger('InfrastructureManager')


router = APIRouter()


@router.get("/oai", summary="OAI-PMH endpoint")
@router.post("/oai", summary="OAI-PMH endpoint")
async def oaipmh(request: Request):
    """OAI-PMH endpoint"""
    if not (Config.OAIPMH_REPO_BASE_IDENTIFIER_URL and
            Config.OAIPMH_REPO_NAME and Config.OAIPMH_REPO_DESCRIPTION):
        return return_error(request, 400, "OAI-PMH not enabled.")

    oai = OAI(Config.OAIPMH_REPO_NAME, str(request.base_url).rstrip('/') + '/oai', Config.OAIPMH_REPO_DESCRIPTION,
              Config.OAIPMH_REPO_BASE_IDENTIFIER_URL, repo_admin_email=Config.OAIPMH_REPO_ADMIN_EMAIL)

    # Get list of TOSCA templates from Config.OAIPMH_REPO_BASE_IDENTIFIER_URL
    metadata_dict = {}
    try:
        repo = Repository.create(Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
        for name, elem in repo.list().items():
            tosca = yaml.safe_load(repo.get(elem))
            metadata = tosca["metadata"]
            metadata["identifier"] = Config.OAIPMH_REPO_BASE_IDENTIFIER_URL + name
            metadata["resource_type"] = "software"
            metadata["rights"] = "openaccess"
            metadata_dict[name] = metadata
    except Exception as ex:
        logger.exception("Error getting metadata from TOSCA templates")
        return return_error(request, 400, "Error getting metadata from TOSCA templates: %s" % get_ex_error(ex))

    # Convert FastAPI request to a format compatible with OAI-PMH module
    values_dict = dict(request.query_params)
    if request.method == "POST":
        try:
            form_data = await request.form()
            values_dict.update(form_data)
        except Exception as ex:
            logger.warning("Error parsing POST form data: %s" % get_ex_error(ex))

    response_xml = oai.processRequest(values_dict, metadata_dict)
    return Response(content=response_xml, media_type='text/xml')
