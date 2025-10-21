from flask import Blueprint
from IM.awm.models.user_info import UserInfo
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
    return user.model_dump_json(exclude_unset=True)


def _get_vos_from_entitlemets(entitlements):
    vos = []
    for elem in entitlements:
        # format: urn:mace:egi.eu:group:eosc-synergy.eu:role=vm_operator#aai.egi.eu
        # or      urn:mace:egi.eu:group:demo.fedcloud.egi.eu:vm_operator:role=member#aai.egi.eu
        if elem.startswith('urn:mace:egi.eu:group:'):
            vo = elem[22:22 + elem[22:].find(':')]
            if vo and vo not in vos:
                vos.append(vo)
    vos.sort()
    return vos
