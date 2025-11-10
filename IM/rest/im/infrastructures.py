import logging
import flask
import json
from IM.config import Config
from radl.radl_json import parse_radl as parse_radl_json
from IM.tosca.Tosca import Tosca
from IM import get_ex_error
from IM.auth import Authentication
from IM.rest.utils import get_auth_header, return_error, format_output, get_media_type, require_auth
from IM.InfrastructureInfo import IncorrectVMException, DeletedVMException, IncorrectStateException
from IM.InfrastructureManager import (InfrastructureManager, DeletedInfrastructureException,
                                      IncorrectInfrastructureException, UnauthorizedUserException,
                                      InvaliddUserException, DisabledFunctionException)
from IM.rest.im.virtualmachines import vms_bp


infs_bp = flask.Blueprint('infrastructures', __name__, url_prefix='/infrastructures')
infs_bp.register_blueprint(vms_bp)

logger = logging.getLogger(__name__)


@infs_bp.route('/<infid>', methods=['DELETE'])
@require_auth
def RESTDestroyInfrastructure(infid=None, auth=None):
    try:
        force = False
        if "force" in flask.request.args.keys():
            str_force = flask.request.args.get("force").lower()
            if str_force in ['yes', 'true', '1']:
                force = True
            elif str_force in ['no', 'false', '0']:
                force = False
            else:
                return return_error(400, "Incorrect value in force parameter")

        async_call = False
        if "async" in flask.request.args.keys():
            str_ctxt = flask.request.args.get("async").lower()
            if str_ctxt in ['yes', 'true', '1']:
                async_call = True
            elif str_ctxt in ['no', 'false', '0']:
                async_call = False
            else:
                return return_error(400, "Incorrect value in async parameter")

        InfrastructureManager.DestroyInfrastructure(infid, auth, force, async_call)
        return flask.make_response("", 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectStateException as ex:
        return return_error(409, "Error Destroying Inf: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Destroying Inf")
        return return_error(400, "Error Destroying Inf: %s" % get_ex_error(ex))


@infs_bp.route('/<infid>', methods=['GET'])
@require_auth
def RESTGetInfrastructureInfo(infid=None, auth=None):
    try:
        vm_ids = InfrastructureManager.GetInfrastructureInfo(infid, auth)
        res = []

        for vm_id in vm_ids:
            res.append("%sinfrastructures/%s/vms/%s" % (flask.request.url_root, infid, vm_id))

        return format_output(res, "text/uri-list", "uri-list", "uri")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. info")
        return return_error(400, "Error Getting Inf. info: %s" % get_ex_error(ex))


@infs_bp.route('/<infid>/<prop>')
@require_auth
def RESTGetInfrastructureProperty(infid=None, prop=None, auth=None):
    try:
        if prop == "contmsg":
            headeronly = False
            if "headeronly" in flask.request.args.keys():
                str_headeronly = flask.request.args.get("headeronly").lower()
                if str_headeronly in ['yes', 'true', '1']:
                    headeronly = True
                elif str_headeronly in ['no', 'false', '0']:
                    headeronly = False
                else:
                    return return_error(400, "Incorrect value in headeronly parameter")

            res = InfrastructureManager.GetInfrastructureContMsg(infid, auth, headeronly)
        elif prop == "radl":
            res = InfrastructureManager.GetInfrastructureRADL(infid, auth)
        elif prop == "tosca":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].serialize()
            else:
                flask.abort(403, "'tosca' infrastructure property is not valid in this infrastructure")
        elif prop == "state":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            res = InfrastructureManager.GetInfrastructureState(infid, auth)
            return format_output(res, default_type="application/json", field_name="state")
        elif prop == "outputs":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].get_outputs(sel_inf)
            else:
                flask.abort(403, "'outputs' infrastructure property is not valid in this infrastructure")
            return format_output(res, default_type="application/json", field_name="outputs")
        elif prop == "data":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)

            delete = False
            if "delete" in flask.request.args.keys():
                str_delete = flask.request.args.get("delete").lower()
                if str_delete in ['yes', 'true', '1']:
                    delete = True
                elif str_delete in ['no', 'false', '0']:
                    delete = False
                else:
                    return return_error(400, "Incorrect value in delete parameter")

            data = InfrastructureManager.ExportInfrastructure(infid, delete, auth)
            return format_output(data, default_type="application/json", field_name="data")
        elif prop == "authorization":
            res = InfrastructureManager.GetInfrastructureOwners(infid, auth)
        else:
            return return_error(404, "Incorrect infrastructure property")

        return format_output(res, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. prop")
        return return_error(400, "Error Getting Inf. prop: %s" % get_ex_error(ex))


@infs_bp.route('', methods=['GET'])
@require_auth
def RESTGetInfrastructureList(auth=None):
    try:
        flt = None
        if "filter" in flask.request.args.keys():
            flt = flask.request.args.get("filter")

        inf_ids = InfrastructureManager.GetInfrastructureList(auth, flt)
        res = []

        for inf_id in inf_ids:
            res.append("%sinfrastructures/%s" % (flask.request.url_root, inf_id))

        return format_output(res, "text/uri-list", "uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Getting Inf. List: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. List")
        return return_error(400, "Error Getting Inf. List: %s" % get_ex_error(ex))


@infs_bp.route('', methods=['POST'])
@require_auth
def RESTCreateInfrastructure(auth=None):
    try:
        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")
        tosca_data = None

        async_call = False
        if "async" in flask.request.args.keys():
            str_async = flask.request.args.get("async").lower()
            if str_async in ['yes', 'true', '1']:
                async_call = True
            elif str_async in ['no', 'false', '0']:
                async_call = False
            else:
                return return_error(400, "Incorrect value in async parameter")

        dry_run = False
        if "dry_run" in flask.request.args.keys():
            str_dry_run = flask.request.args.get("dry_run").lower()
            if str_dry_run in ['yes', 'true', '1']:
                dry_run = True
            elif str_dry_run in ['no', 'false', '0']:
                dry_run = False
            else:
                return return_error(400, "Incorrect value in dry_run parameter")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data, tosca_repo=Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                content_type = "text/plain"
            else:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        if dry_run:
            res = InfrastructureManager.EstimateResouces(radl_data, auth)
            return format_output(res, "application/json")
        else:
            inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth, async_call)

            # Store the TOSCA document
            if tosca_data:
                sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
                sel_inf.extra_info['TOSCA'] = tosca_data

            res = "%sinfrastructures/%s" % (flask.request.url_root, inf_id)
            return format_output(res, "text/uri-list", "uri", extra_headers={'InfID': inf_id})
    except InvaliddUserException as ex:
        return return_error(401, "Error Creating Inf. info: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Creating Inf, info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Creating Inf.")
        return return_error(400, "Error Creating Inf.: %s" % get_ex_error(ex))


@infs_bp.route('', methods=['PUT'])
@require_auth
def RESTImportInfrastructure(auth=None):
    try:
        content_type = get_media_type('Content-Type')
        data = flask.request.data.decode("utf-8")

        if content_type:
            if "application/json" not in content_type:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        new_id = InfrastructureManager.ImportInfrastructure(data, auth)

        res = "%sinfrastructures/%s" % (flask.request.url_root, new_id)

        return format_output(res, "text/uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Impporting Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Impporting Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Impporting Inf.")
        return return_error(400, "Error Impporting Inf.: %s" % get_ex_error(ex))


@infs_bp.route('/<infid>', methods=['POST'])
@require_auth
def RESTAddResource(infid=None, auth=None):
    try:
        context = True
        if "context" in flask.request.args.keys():
            str_ctxt = flask.request.args.get("context").lower()
            if str_ctxt in ['yes', 'true', '1']:
                context = True
            elif str_ctxt in ['no', 'false', '0']:
                context = False
            else:
                return return_error(400, "Incorrect value in context parameter")

        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")
        tosca_data = None
        remove_list = []

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                auth = InfrastructureManager.check_auth_data(auth)
                sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
                # merge the current TOSCA with the new one
                if isinstance(sel_inf.extra_info['TOSCA'], Tosca):
                    tosca_data = sel_inf.extra_info['TOSCA'].merge(tosca_data)
                remove_list, radl_data = tosca_data.to_radl(sel_inf)
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                content_type = "text/plain"
            else:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        if remove_list:
            removed_vms = InfrastructureManager.RemoveResource(infid, remove_list, auth, context)
            if len(remove_list) != removed_vms:
                logger.error("Error deleting resources %s (removed %s)" % (remove_list, removed_vms))

        vm_ids = InfrastructureManager.AddResource(infid, radl_data, auth, context)

        # If there are no changes in the infra, launch a reconfigure
        if not remove_list and not vm_ids and context:
            InfrastructureManager.Reconfigure(infid, "", auth)

        # Replace the TOSCA document
        if tosca_data:
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            sel_inf.extra_info['TOSCA'] = tosca_data

        res = []
        for vm_id in vm_ids:
            res.append("%sinfrastructures/%s/vms/%s" % (flask.request.url_root, infid, vm_id))

        if not vm_ids and remove_list and len(remove_list) != removed_vms:
            return return_error(404, "Error deleting resources %s (removed %s)" % (remove_list, removed_vms))
        else:
            extra_headers = {}
            # If we have to reconfigure the infra, return the ID for the HAProxy stickiness
            if context:
                extra_headers = {'InfID': infid}
            return format_output(res, "text/uri-list", "uri-list", "uri", extra_headers)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Adding resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Adding resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Adding resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Adding resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Adding resources")
        return return_error(400, "Error Adding resources: %s" % get_ex_error(ex))


@infs_bp.route('/<infid>/reconfigure', methods=['PUT'])
@require_auth
def RESTReconfigureInfrastructure(infid=None, auth=None):
    try:
        vm_list = None
        if "vm_list" in flask.request.args.keys():
            str_vm_list = flask.request.args.get("vm_list")
            try:
                vm_list = [int(vm_id) for vm_id in str_vm_list.split(",")]
            except Exception:
                return return_error(400, "Incorrect vm_list format.")

        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")

        if radl_data:
            if content_type:
                if "application/json" in content_type:
                    radl_data = parse_radl_json(radl_data)
                elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                    tosca_data = Tosca(radl_data)
                    _, radl_data = tosca_data.to_radl()
                elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                    content_type = "text/plain"
                else:
                    return return_error(415, "Unsupported Media Type %s" % content_type)
        else:
            radl_data = ""

        res = InfrastructureManager.Reconfigure(infid, radl_data, auth, vm_list)
        # As we have to reconfigure the infra, return the ID for the HAProxy stickiness
        return flask.make_response(res, 200, {'Content-Type': 'text/plain', 'InfID': infid})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error reconfiguring infrastructure")
        return return_error(400, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))


@infs_bp.route('/<infid>/<op>', methods=['PUT'])
@require_auth
def RESTOperateInfrastructure(infid=None, op=None, auth=None):
    try:
        if op == "start":
            res = InfrastructureManager.StartInfrastructure(infid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopInfrastructure(infid, auth)
        else:
            flask.abort(404)
        return flask.make_response(res, 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except Exception as ex:
        logger.exception("Error in %s operation" % op)
        return return_error(400, "Error in %s operation: %s" % (op, get_ex_error(ex)))


@infs_bp.route('/<infid>/authorization', methods=['POST'])
@require_auth
def RESTChangeInfrastructureAuth(infid=None, auth=None):
    try:
        overwrite = False
        if "overwrite" in flask.request.args.keys():
            str_overwrite = flask.request.args.get("overwrite").lower()
            if str_overwrite in ['yes', 'true', '1']:
                overwrite = True
            elif str_overwrite in ['no', 'false', '0']:
                overwrite = False
            else:
                return return_error(400, "Incorrect value in overwrite parameter")

        content_type = get_media_type('Content-Type') or ["application/json"]

        if "application/json" in content_type:
            auth_dict = json.loads(flask.request.data.decode("utf-8"))
            if "type" not in auth_dict:
                auth_dict["type"] = "InfrastructureManager"
            new_auth = Authentication([auth_dict])
        else:
            return return_error(415, "Unsupported Media Type %s" % content_type)

        InfrastructureManager.ChangeInfrastructureAuth(infid, new_auth, overwrite, auth)
        return flask.make_response("", 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error modifying infrastructure owners: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error modifying infrastructure owner.")
        return return_error(400, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
