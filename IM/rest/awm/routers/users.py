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

from flask import Blueprint, Response
from IM.rest.awm.models.user_info import UserInfo
from . import require_auth

# Mantengo el nombre `router` para minimizar cambios al registrar el blueprint
users_bp = Blueprint("users", __name__)


@users_bp.route("/info", methods=["GET"])
@require_auth
def get_user_info(user_info=None):
    """Retrieve information about the user"""
    user = UserInfo(
        base_id=user_info.get("sub"),
        user_dn=user_info.get("name"),
        vos=_get_vos_from_entitlemets(
            user_info.get("entitlements", user_info.get("eduperson_entitlement"))
        ),
    )
    return Response(user.model_dump_json(exclude_unset=True), status=200, mimetype="application/json")


def _get_vos_from_entitlemets(entitlements):
    vos = []
    if not entitlements:
        return vos
    for elem in entitlements:
        # format: urn:mace:egi.eu:group:eosc-synergy.eu:role=vm_operator#aai.egi.eu
        # or      urn:mace:egi.eu:group:demo.fedcloud.egi.eu:vm_operator:role=member#aai.egi.eu
        if elem.startswith('urn:mace:egi.eu:group:'):
            vo = elem[22:22 + elem[22:].find(':')]
            if vo and vo not in vos:
                vos.append(vo)
    vos.sort()
    return vos
