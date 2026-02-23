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
import json

from typing import Literal, Optional

from fastapi import Request, Response, HTTPException, Query, Depends, APIRouter

from IM.InfrastructureInfo import IncorrectVMException, DeletedVMException, IncorrectStateException
from IM.InfrastructureManager import (InfrastructureManager, DeletedInfrastructureException,
                                      IncorrectInfrastructureException, UnauthorizedUserException,
                                      InvaliddUserException, DisabledFunctionException)
from IM.auth import Authentication
from IM.config import Config
from IM import get_ex_error
from radl.radl_json import parse_radl as parse_radl_json
from IM.tosca.Tosca import Tosca
from IM.rest.models import InfrastructureState, UriList, Uri
from IM.rest import STANDARD_RESPONSES, DELETE_RESPONSES
from IM.rest.routers import get_auth_header, get_media_type, format_output, return_error

logger = logging.getLogger('InfrastructureManager')


router = APIRouter()


@router.get("/infrastructures",
            tags=["Infrastructures"],
            summary="Get infrastructure List",
            response_model=UriList,
            responses=STANDARD_RESPONSES)
async def get_infrastructure_list(
    request: Request,
    auth: Authentication = Depends(get_auth_header)
):
    """Get infrastructure list"""
    try:
        inf_ids = InfrastructureManager.GetInfrastructureList(auth)
        res = []
        for inf_id in inf_ids:
            res.append(f"{str(request.base_url).rstrip('/')}/infrastructures/{inf_id}")
        return format_output(request, res, "text/uri-list", "uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error Getting Inf. List: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 400, "Error Getting Inf. List: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. List")
        return return_error(request, 400, "Error Getting Inf. List: %s" % get_ex_error(ex))


@router.post("/infrastructures",
             tags=["Infrastructures"],
             summary="Create new infrastructure",
             response_model=Uri,
             responses=STANDARD_RESPONSES)
async def create_infrastructure(
    request: Request,
    async_call: bool = Query(False, alias="async"),
    dry_run: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Create new infrastructure"""
    # Check content type first, outside of try/except to preserve 415 status code
    content_type = get_media_type(request, 'Content-Type')
    if content_type:
        valid_types = ["application/json", "text/yaml", "text/x-yaml",
                       "application/yaml", "text/plain", "*/*", "text/*"]
        if not any(ct in content_type for ct in valid_types):
            raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

    try:
        body = await request.body()
        radl_data = body.decode("utf-8")
        tosca_data = None

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data, tosca_repo=Config.OAIPMH_REPO_BASE_IDENTIFIER_URL, auth=auth)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass

        if dry_run:
            res = InfrastructureManager.EstimateResouces(radl_data, auth)
            return format_output(request, res, "application/json")
        else:
            inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth, async_call)

            # Store the TOSCA document
            if tosca_data:
                sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
                sel_inf.extra_info['TOSCA'] = tosca_data

            res = f"{str(request.base_url).rstrip('/')}/infrastructures/{inf_id}"
            return format_output(request, res, "text/uri-list", "uri", extra_headers={'InfID': inf_id})
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error Creating Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Creating Inf.: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Creating Inf.")
        return return_error(request, 400, "Error Creating Inf.: %s" % get_ex_error(ex))


@router.put("/infrastructures",
            tags=["Infrastructures"],
            summary="Import infrastructure",
            response_model=Uri,
            responses=STANDARD_RESPONSES)
async def import_infrastructure(
    request: Request,
    auth: Authentication = Depends(get_auth_header)
):
    """Import infrastructure"""
    try:
        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        data = body.decode("utf-8")

        if content_type:
            if "application/json" not in content_type:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        new_id = InfrastructureManager.ImportInfrastructure(data, auth)
        res = f"{str(request.base_url).rstrip('/')}/infrastructures/{new_id}"
        return format_output(request, res, "text/uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error Importing Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Importing Inf.: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Importing Inf.")
        return return_error(request, 400, "Error Importing Inf.: %s" % get_ex_error(ex))


@router.get("/infrastructures/{infid}",
            tags=["Infrastructures"],
            summary="Get infrastructure information",
            response_model=UriList,
            responses=STANDARD_RESPONSES)
async def get_infrastructure_info(
    request: Request,
    infid: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Get infrastructure information"""
    try:
        vm_ids = InfrastructureManager.GetInfrastructureInfo(infid, auth)
        res = []
        for vm_id in vm_ids:
            res.append(f"{str(request.base_url).rstrip('/')}/infrastructures/{infid}/vms/{vm_id}")
        return format_output(request, res, "text/uri-list", "uri-list", "uri")
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. info")
        return return_error(request, 400, "Error Getting Inf. info: %s" % get_ex_error(ex))


@router.delete("/infrastructures/{infid}",
               tags=["Infrastructures"],
               summary="Destroy infrastructure",
               response_model=Uri,
               responses=DELETE_RESPONSES)
async def destroy_infrastructure(
    request: Request,
    infid: str,
    force: bool = Query(False),
    async_call: bool = Query(False, alias="async"),
    auth: Authentication = Depends(get_auth_header)
):
    """Destroy infrastructure"""
    try:
        InfrastructureManager.DestroyInfrastructure(infid, auth, force, async_call)
        return Response(status_code=200, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectStateException as ex:
        return return_error(request, 409, "Error Destroying Inf: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Destroying Inf")
        return return_error(request, 400, "Error Destroying Inf: %s" % get_ex_error(ex))


@router.get("/infrastructures/{infid}/{prop}",
            tags=["Infrastructures"],
            summary="Get infrastructure property",
            response_model=InfrastructureState,
            responses=STANDARD_RESPONSES)
async def get_infrastructure_property(
    request: Request,
    infid: str,
    prop: Literal["contmsg", "radl", "tosca", "state", "outputs", "data", "authorization"],
    headeronly: bool = Query(False),
    delete: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Get infrastructure property"""
    try:
        accept = None
        if prop == "contmsg":
            res = InfrastructureManager.GetInfrastructureContMsg(infid, auth, headeronly)
            return format_output(request, res, field_name=prop)
        elif prop == "radl":
            res = InfrastructureManager.GetInfrastructureRADL(infid, auth)
            return format_output(request, res, field_name=prop)
        elif prop == "tosca":
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].serialize()
            else:
                raise HTTPException(status_code=403,
                                    detail="'tosca' infrastructure property is not valid in this infrastructure")
            return format_output(request, res, field_name=prop)
        else:
            # For other properties, application/json is the only supported media type
            accept = get_media_type(request, 'Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                raise HTTPException(status_code=415, detail="Unsupported Accept Media Types: %s" % accept)

        if prop == "state":
            res = InfrastructureManager.GetInfrastructureState(infid, auth)
        elif prop == "outputs":
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].get_outputs(sel_inf)
            else:
                raise HTTPException(status_code=403,
                                    detail="'outputs' infrastructure property is not valid in this infrastructure")
        elif prop == "data":
            res = InfrastructureManager.ExportInfrastructure(infid, delete, auth)
        elif prop == "authorization":
            res = InfrastructureManager.GetInfrastructureOwners(infid, auth)
        else:
            raise HTTPException(status_code=404, detail="Incorrect infrastructure property")

        return format_output(request, res, default_type="application/json", field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error Getting Inf. prop")
        return return_error(request, 400, "Error Getting Inf. prop: %s" % get_ex_error(ex))


@router.post("/infrastructures/{infid}",
             tags=["Infrastructures"],
             summary="Add resources to infrastructure",
             response_model=UriList,
             responses=STANDARD_RESPONSES)
async def add_resource(
    request: Request,
    infid: str,
    context: bool = Query(True),
    auth: Authentication = Depends(get_auth_header)
):
    """Add resources to infrastructure"""
    try:
        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        radl_data = body.decode("utf-8")
        tosca_data = None
        remove_list = []

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                auth_checked = InfrastructureManager.check_auth_data(auth)
                sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
                # merge the current TOSCA with the new one
                if isinstance(sel_inf.extra_info.get('TOSCA'), Tosca):
                    tosca_data = sel_inf.extra_info['TOSCA'].merge(tosca_data)
                remove_list, radl_data = tosca_data.to_radl(sel_inf)
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass
            else:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

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
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
            sel_inf.extra_info['TOSCA'] = tosca_data

        res = []
        for vm_id in vm_ids:
            res.append(f"{str(request.base_url).rstrip('/')}/infrastructures/{infid}/vms/{vm_id}")

        if not vm_ids and remove_list and len(remove_list) != removed_vms:
            return return_error(request, 404,
                                "Error deleting resources %s (removed %s)" % (remove_list, removed_vms))
        else:
            extra_headers = {}
            # If we have to reconfigure the infra, return the ID for the HAProxy stickiness
            if context:
                extra_headers = {'InfID': infid}
            return format_output(request, res, "text/uri-list", "uri-list", "uri", extra_headers)
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Adding resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Adding resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Adding resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Adding resources: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error Adding resources")
        return return_error(request, 400, "Error Adding resources: %s" % get_ex_error(ex))


@router.put("/infrastructures/{infid}/reconfigure",
            tags=["Infrastructures"],
            summary="Reconfigure infrastructure",
            responses=STANDARD_RESPONSES)
async def reconfigure_infrastructure(
    request: Request,
    infid: str,
    vm_list: Optional[str] = Query(None),
    auth: Authentication = Depends(get_auth_header)
):
    """Reconfigure infrastructure"""
    try:
        vm_list_parsed = None
        if vm_list:
            try:
                vm_list_parsed = [int(vm_id) for vm_id in vm_list.split(",")]
            except Exception as ex:
                raise HTTPException(status_code=400, detail="Incorrect vm_list format.") from ex

        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        radl_data = body.decode("utf-8") if body else ""

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass
            else:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        res = InfrastructureManager.Reconfigure(infid, radl_data, auth, vm_list_parsed)
        # As we have to reconfigure the infra, return the ID for the HAProxy stickiness
        return Response(content=res, media_type='text/plain', headers={'InfID': infid})
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error reconfiguring infrastructure")
        return return_error(request, 400, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))


@router.put("/infrastructures/{infid}/{op}",
            tags=["Infrastructures"],
            summary="Start or stop infrastructure",
            responses=STANDARD_RESPONSES)
async def operate_infrastructure(
    request: Request,
    infid: str,
    op: Literal["start", "stop"],
    auth: Authentication = Depends(get_auth_header)
):
    """Start or stop infrastructure"""
    try:
        if op == "start":
            res = InfrastructureManager.StartInfrastructure(infid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopInfrastructure(infid, auth)
        else:
            raise HTTPException(status_code=404, detail="Operation not found")
        return Response(content=res, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error in %s operation" % op)
        return return_error(request, 400, "Error in %s operation: %s" % (op, get_ex_error(ex)))


@router.post("/infrastructures/{infid}/authorization",
             tags=["Infrastructures"],
             summary="Change infrastructure authorization",
             responses=STANDARD_RESPONSES)
async def change_infrastructure_auth(
    request: Request,
    infid: str,
    overwrite: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Change infrastructure authorization"""
    try:
        content_type = get_media_type(request, 'Content-Type') or ["application/json"]

        body = await request.body()
        if "application/json" in content_type:
            auth_dict = json.loads(body.decode("utf-8"))
            if "type" not in auth_dict:
                auth_dict["type"] = "InfrastructureManager"
            new_auth = Authentication([auth_dict])
        else:
            raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        InfrastructureManager.ChangeInfrastructureAuth(infid, new_auth, overwrite, auth)
        return Response(status_code=200, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error modifying infrastructure owners: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error modifying infrastructure owner.")
        return return_error(request, 400, "Error modifying infrastructure owner: %s" % get_ex_error(ex))


@router.get("/infrastructures/{infid}/vms/{vmid}",
            tags=["VMs"],
            summary="Get VM information",
            responses=STANDARD_RESPONSES)
async def get_vm_info(
    request: Request,
    infid: str,
    vmid: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Get VM information"""
    try:
        radl = InfrastructureManager.GetVMInfo(infid, vmid, auth)
        return format_output(request, radl, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting VM. info: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting VM info")
        return return_error(request, 400, "Error Getting VM info: %s" % get_ex_error(ex))


@router.delete("/infrastructures/{infid}/vms/{vmid}",
               tags=["VMs"],
               summary="Remove VM from infrastructure",
               responses=STANDARD_RESPONSES)
async def remove_resource(
    request: Request,
    infid: str,
    vmid: str,
    context: bool = Query(True),
    auth: Authentication = Depends(get_auth_header)
):
    """Remove VM from infrastructure"""
    try:
        InfrastructureManager.RemoveResource(infid, vmid, auth, context)
        return Response(status_code=200, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Removing resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Removing resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Removing resources")
        return return_error(request, 400, "Error Removing resources: %s" % get_ex_error(ex))


@router.put("/infrastructures/{infid}/vms/{vmid}",
            tags=["VMs"],
            summary="Alter VM information",
            responses=STANDARD_RESPONSES)
async def alter_vm(
    request: Request,
    infid: str,
    vmid: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Alter VM"""
    try:
        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        radl_data = body.decode("utf-8")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass
            else:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        vm_info = InfrastructureManager.AlterVM(infid, vmid, radl_data, auth)
        return format_output(request, vm_info, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error modifying resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error modifying resources: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error modifying resources")
        return return_error(request, 400, "Error modifying resources: %s" % get_ex_error(ex))


def get_command(step, sel_inf, infid, vmid, request):
    """
       Get the command to connect to the VM. Step 1 returns a command to launch a reverse ssh,
       step 2 returns the ssh command to connect to the VM
    """
    if step == 1:
        base_url = str(request.base_url).rstrip('/')
        url = f"{base_url}/infrastructures/{infid}/vms/{vmid}/command?step=2"
        auth_info = sel_inf.auth.getAuthInfo("InfrastructureManager")[0]
        if 'token' in auth_info:
            imauth = "token = %s" % auth_info['token']
        else:
            imauth = "username = %s; password = %s" % (auth_info['username'], auth_info['password'])
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
            logger.warning("Specified vmid in step2 is incorrect!!")
            info = "wait"
        else:
            ssh = sel_vm.get_ssh_ansible_master(retry=False)
            ssh_ok = False
            if ssh:
                ssh_ok = ssh.test_connectivity(time_out=2)

            if ssh_ok:
                if sel_inf.vm_master and int(vmid) == sel_inf.vm_master.creation_im_id:
                    logger.debug("Step 2: Is the master do no make ssh command.")
                    info = "true"
                else:
                    if sel_vm.isConnectedWith(sel_inf.vm_master):
                        logger.debug("Step 2: Is connected with the master do no make ssh command.")
                        info = "true"
                    else:
                        info = sel_vm.get_ssh_command()
            else:
                info = "wait"
    else:
        info = None

    return info


@router.get("/infrastructures/{infid}/vms/{vmid}/{prop}",
            tags=["VMs"],
            summary="Get VM property",
            responses=STANDARD_RESPONSES)
async def get_vm_property(
    request: Request,
    infid: str,
    vmid: str,
    prop: str,
    step: int = Query(1),
    auth: Authentication = Depends(get_auth_header)
):
    """Get VM property"""
    try:
        if prop == 'contmsg':
            info = InfrastructureManager.GetVMContMsg(infid, vmid, auth)
        elif prop == 'command':
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)

            info = get_command(step, sel_inf, infid, vmid, request)
        else:
            info = InfrastructureManager.GetVMProperty(infid, vmid, prop, auth)

        if info is None:
            raise HTTPException(status_code=404, detail="Incorrect property %s for VM ID %s" % (prop, vmid))
        else:
            return format_output(request, info, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting VM. property: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error Getting VM property")
        return return_error(request, 400, "Error Getting VM property: %s" % get_ex_error(ex))


@router.put("/infrastructures/{infid}/vms/{vmid}/{op}",
            tags=["VMs"],
            summary="Start, stop or reboot VM",
            responses=STANDARD_RESPONSES)
async def operate_vm(
    request: Request,
    infid: str,
    vmid: str,
    op: Literal["start", "stop", "reboot"],
    auth: Authentication = Depends(get_auth_header)
):
    """Start, stop or reboot VM"""
    try:
        if op == "start":
            res = InfrastructureManager.StartVM(infid, vmid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopVM(infid, vmid, auth)
        elif op == "reboot":
            res = InfrastructureManager.RebootVM(infid, vmid, auth)
        else:
            raise HTTPException(status_code=404, detail="Operation not found")
        return Response(content=res, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error in %s op in VM" % op)
        return return_error(request, 400, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))


@router.put("/infrastructures/{infid}/vms/{vmid}/disks/{disknum}/snapshot",
            tags=["VMs"],
            summary="Create disk snapshot",
            responses=STANDARD_RESPONSES)
async def create_disk_snapshot(
    request: Request,
    infid: str,
    vmid: str,
    disknum: int,
    image_name: str = Query(...),
    auto_delete: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Create disk snapshot"""
    try:
        res = InfrastructureManager.CreateDiskSnapshot(infid, vmid, disknum, image_name, auto_delete, auth)
        return Response(content=res, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error creating snapshot: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error creating snapshot: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error creating snapshot")
        return return_error(request, 400, "Error creating snapshot: %s" % get_ex_error(ex))
