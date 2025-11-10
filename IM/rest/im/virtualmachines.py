import logging
import flask
from radl.radl_json import parse_radl as parse_radl_json
from IM.tosca.Tosca import Tosca
from IM import get_ex_error
from IM.rest.utils import return_error, format_output, get_media_type, require_auth
from IM.InfrastructureInfo import IncorrectVMException, DeletedVMException
from IM.InfrastructureManager import (InfrastructureManager, DeletedInfrastructureException,
                                      IncorrectInfrastructureException, UnauthorizedUserException,
                                      DisabledFunctionException)


vms_bp = flask.Blueprint("vms", __name__, url_prefix='/<infid>/vms')
logger = logging.getLogger(__name__)


@vms_bp.route('/<vmid>', methods=['GET'])
@require_auth
def RESTGetVMInfo(infid=None, vmid=None, auth=None):
    try:
        radl = InfrastructureManager.GetVMInfo(infid, vmid, auth)
        return format_output(radl, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting VM. info: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting VM info")
        return return_error(400, "Error Getting VM info: %s" % get_ex_error(ex))


@vms_bp.route('/<vmid>/<prop>', methods=['GET'])
@require_auth
def RESTGetVMProperty(infid=None, vmid=None, prop=None, auth=None):
    try:
        if prop == 'contmsg':
            info = InfrastructureManager.GetVMContMsg(infid, vmid, auth)
        elif prop == 'command':
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)

            step = 1
            if "step" in flask.request.args.keys():
                step = int(flask.request.args.get("step"))

            if step == 1:
                url = "%sinfrastructures/%s/vms/%s/command?step=2" % (flask.request.url_root, infid, vmid)
                auth = sel_inf.auth.getAuthInfo("InfrastructureManager")[0]
                if 'token' in auth:
                    imauth = "token = %s" % auth['token']
                else:
                    imauth = "username = %s; password = %s" % (auth['username'], auth['password'])
                command = ('curl --insecure -s -H "Authorization: type = InfrastructureManager; %s" '
                           '-H "Accept: text/plain" %s' % (imauth, url))

                ps_command = "ps aux | grep -v grep | grep 'ssh -N -R'"
                info = """
                res="wait"
                while [ "$res" == "wait" ]
                do
                  res=`%s`
                  if [ "$res" != "wait" ]
                  then
                    echo "$res" > /var/tmp/reverse_ssh.sh
                    chmod a+x /var/tmp/reverse_ssh.sh
                    /var/tmp/reverse_ssh.sh
                    if [ "$res" != "true" ]
                    then
                      echo "*/1 * * * * root %s || /var/tmp/reverse_ssh.sh" > /etc/cron.d/reverse_ssh
                    fi
                  else
                    sleep 20
                  fi
                done""" % (command, ps_command)
                logger.debug("Step 1 command: %s" % info)
            elif step == 2:
                sel_vm = None
                for vm in sel_inf.get_vm_list():
                    if vm.creation_im_id == int(vmid):
                        sel_vm = vm
                        break
                if not sel_vm:
                    # it sometimes happen when the VM is in creation state
                    logger.warning("Specified vmid in step2 is incorrect!!")
                    info = "wait"
                else:
                    ssh = sel_vm.get_ssh_ansible_master(retry=False)

                    ssh_ok = False
                    if ssh:
                        ssh_ok = ssh.test_connectivity(time_out=2)

                    if ssh_ok:
                        # if it is the master do not make the ssh command
                        if sel_inf.vm_master and int(vmid) == sel_inf.vm_master.creation_im_id:
                            logger.debug("Step 2: Is the master do no make ssh command.")
                            info = "true"
                        else:
                            # if this vm is connected with the master directly do not make it also
                            if sel_vm.isConnectedWith(sel_inf.vm_master):
                                logger.debug("Step 2: Is connected with the master do no make ssh command.")
                                info = "true"
                            else:
                                info = sel_vm.get_ssh_command()
                    else:
                        info = "wait"
                logger.debug("Step 2 command for vm ID: %s is %s" % (vmid, info))
            else:
                info = None
        else:
            info = InfrastructureManager.GetVMProperty(infid, vmid, prop, auth)

        if info is None:
            return return_error(404, "Incorrect property %s for VM ID %s" % (prop, vmid))
        else:
            return format_output(info, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting VM. property: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting VM property")
        return return_error(400, "Error Getting VM property: %s" % get_ex_error(ex))


@vms_bp.route('/<vmid>', methods=['DELETE'])
@require_auth
def RESTRemoveResource(infid=None, vmid=None, auth=None):
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

        InfrastructureManager.RemoveResource(infid, vmid, auth, context)
        return flask.make_response("", 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Removing resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Removing resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Removing resources")
        return return_error(400, "Error Removing resources: %s" % get_ex_error(ex))


@vms_bp.route('/<vmid>', methods=['PUT'])
@require_auth
def RESTAlterVM(infid=None, vmid=None, auth=None):
    try:
        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")

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

        vm_info = InfrastructureManager.AlterVM(infid, vmid, radl_data, auth)

        return format_output(vm_info, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error modifying resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error modifying resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error modifying resources")
        return return_error(400, "Error modifying resources: %s" % get_ex_error(ex))


@vms_bp.route('/<vmid>/<op>', methods=['PUT'])
@require_auth
def RESTOperateVM(infid=None, vmid=None, op=None, auth=None):
    try:
        if op == "start":
            res = InfrastructureManager.StartVM(infid, vmid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopVM(infid, vmid, auth)
        elif op == "reboot":
            res = InfrastructureManager.RebootVM(infid, vmid, auth)
        else:
            flask.abort(404)
        return flask.make_response(res, 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DeletedVMException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectVMException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except Exception as ex:
        logger.exception("Error in %s op in VM" % op)
        return return_error(400, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))


@vms_bp.route('/<vmid>/disks/<disknum>/snapshot', methods=['PUT'])
@require_auth
def RESTCreateDiskSnapshot(infid=None, vmid=None, disknum=None, auth=None):
    try:
        if "image_name" in flask.request.args.keys():
            image_name = flask.request.args.get("image_name")
        else:
            return return_error(400, "Parameter image_name required.")
        if "auto_delete" in flask.request.args.keys():
            str_auto_delete = flask.request.args.get("auto_delete").lower()
            if str_auto_delete in ['yes', 'true', '1']:
                auto_delete = True
            elif str_auto_delete in ['no', 'false', '0']:
                auto_delete = False
            else:
                return return_error(400, "Incorrect value in auto_delete parameter")
        else:
            auto_delete = False

        res = InfrastructureManager.CreateDiskSnapshot(infid, vmid, int(disknum), image_name, auto_delete, auth)
        return flask.make_response(res, 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error creating snapshot: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error creating snapshot: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error creating snapshot")
        return return_error(400, "Error creating snapshot: %s" % get_ex_error(ex))
