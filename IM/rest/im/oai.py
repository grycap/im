#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2025 - GRyCAP - Universitat Politecnica de Valencia
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
import yaml
import logging
from IM.oaipmh.oai import OAI
from IM.oaipmh.utils import Repository
from IM.config import Config
from IM.rest.utils import return_error


oai_bp = flask.Blueprint("oai", __name__, url_prefix='/oai')
logger = logging.getLogger('InfrastructureManager')


@oai_bp.route('', methods=['GET', 'POST'])
def oaipmh():
    if not (Config.OAIPMH_REPO_BASE_IDENTIFIER_URL and
            Config.OAIPMH_REPO_NAME and Config.OAIPMH_REPO_DESCRIPTION):
        return return_error(400, "OAI-PMH not enabled.")

    oai = OAI(Config.OAIPMH_REPO_NAME, flask.request.base_url, Config.OAIPMH_REPO_DESCRIPTION,
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
        return return_error(400, "Error getting metadata from TOSCA templates: %s" % get_ex_error(ex))

    response_xml = oai.processRequest(flask.request, metadata_dict)
    return flask.make_response(response_xml, 200, {'Content-Type': 'text/xml'})
