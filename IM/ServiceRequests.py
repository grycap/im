#
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

from request import Request, AsyncRequest
import InfrastructureManager
from auth import Authentication
from IM import __version__ as version

logger = logging.getLogger('InfrastructureManager')


class IMBaseRequest(AsyncRequest):
    """
    Base class for the IM requests
    """
    ADD_RESOURCE = "AddResource"
    ALTER_VM = "AlterVM"
    CREATE_INFRASTRUCTURE = "CreateInfrastructure"
    DESTROY_INFRASTRUCTURE = "DestroyInfrastructure"
    EXPORT_INFRASTRUCTURE = "ExportInfrastructure"
    GET_INFRASTRUCTURE_CONT_MSG = "GetInfrastructureContMsg"
    GET_INFRASTRUCTURE_INFO = "GetInfrastructureInfo"
    GET_INFRASTRUCTURE_LIST = "GetInfrastructureList"
    GET_INFRASTRUCTURE_RADL = "GetInfrastructureRADL"
    GET_INFRASTRUCTURE_STATE = "GetInfrastructureState"
    GET_VM_CONT_MSG = "GetVMContMsg"
    GET_VM_INFO = "GetVMInfo"
    GET_VM_PROPERTY = "GetVMProperty"
    IMPORT_INFRASTRUCTURE = "ImportInfrastructure"
    RECONFIGURE = "Reconfigure"
    REMOVE_RESOURCE = "RemoveResource"
    START_INFRASTRUCTURE = "StartInfrastructure"
    STOP_INFRASTRUCTURE = "StopInfrastructure"
    SAVE_DATA = "SaveData"
    START_VM = "StartVM"
    STOP_VM = "StopVM"
    GET_VERSION = "GetVersion"

    @staticmethod
    def create_request(function, arguments=(), priority=Request.PRIORITY_NORMAL):
        if function == IMBaseRequest.ADD_RESOURCE:
            return Request_AddResource(arguments)
        elif function == IMBaseRequest.ALTER_VM:
            return Request_AlterVM(arguments)
        elif function == IMBaseRequest.CREATE_INFRASTRUCTURE:
            return Request_CreateInfrastructure(arguments)
        elif function == IMBaseRequest.DESTROY_INFRASTRUCTURE:
            return Request_DestroyInfrastructure(arguments)
        elif function == IMBaseRequest.EXPORT_INFRASTRUCTURE:
            return Request_ExportInfrastructure(arguments)
        elif function == IMBaseRequest.GET_INFRASTRUCTURE_CONT_MSG:
            return Request_GetInfrastructureContMsg(arguments)
        elif function == IMBaseRequest.GET_INFRASTRUCTURE_INFO:
            return Request_GetInfrastructureInfo(arguments)
        elif function == IMBaseRequest.GET_INFRASTRUCTURE_LIST:
            return Request_GetInfrastructureList(arguments)
        elif function == IMBaseRequest.GET_INFRASTRUCTURE_RADL:
            return Request_GetInfrastructureRADL(arguments)
        elif function == IMBaseRequest.GET_VM_CONT_MSG:
            return Request_GetVMContMsg(arguments)
        elif function == IMBaseRequest.GET_VM_INFO:
            return Request_GetVMInfo(arguments)
        elif function == IMBaseRequest.GET_VM_PROPERTY:
            return Request_GetVMProperty(arguments)
        elif function == IMBaseRequest.IMPORT_INFRASTRUCTURE:
            return Request_ImportInfrastructure(arguments)
        elif function == IMBaseRequest.RECONFIGURE:
            return Request_Reconfigure(arguments)
        elif function == IMBaseRequest.REMOVE_RESOURCE:
            return Request_RemoveResource(arguments)
        elif function == IMBaseRequest.START_INFRASTRUCTURE:
            return Request_StartInfrastructure(arguments)
        elif function == IMBaseRequest.STOP_INFRASTRUCTURE:
            return Request_StopInfrastructure(arguments)
        elif function == IMBaseRequest.SAVE_DATA:
            return Request_SaveData(arguments)
        elif function == IMBaseRequest.START_VM:
            return Request_StartVM(arguments)
        elif function == IMBaseRequest.STOP_VM:
            return Request_StopVM(arguments)
        elif function == IMBaseRequest.GET_INFRASTRUCTURE_STATE:
            return Request_GetInfrastructureState(arguments)
        elif function == IMBaseRequest.GET_VERSION:
            return Request_GetVersion(arguments)

        else:
            raise NotImplementedError("Function not Implemented")

    def __init__(self, arguments=(), priority=Request.PRIORITY_NORMAL):
        AsyncRequest.__init__(self, arguments, priority)
        self._error_mesage = "Error."

    def _call_function(self):
        """
        This function call the IM functionality
        """
        raise NotImplementedError("Should have implemented this")

    def _execute(self):
        try:
            res = self._call_function()
            self.set(res)
            return True
        except Exception, ex:
            logger.exception(self._error_mesage)
            self.set(str(ex))
            return False


class Request_AddResource(IMBaseRequest):
    """
    Request class for the AddResource function
    """

    def _call_function(self):
        self._error_mesage = "Error Adding resources."
        (inf_id, radl_data, auth_data, context) = self.arguments
        return InfrastructureManager.InfrastructureManager.AddResource(inf_id, radl_data,
                                                                       Authentication(auth_data),
                                                                       context)


class Request_RemoveResource(IMBaseRequest):
    """
    Request class for the RemoveResource function
    """

    def _call_function(self):
        self._error_mesage = "Error Removing resources."
        (inf_id, vm_list, auth_data, context) = self.arguments
        return InfrastructureManager.InfrastructureManager.RemoveResource(inf_id, vm_list,
                                                                          Authentication(auth_data),
                                                                          context)


class Request_GetInfrastructureInfo(IMBaseRequest):
    """
    Request class for the GetInfrastructureInfo function
    """

    def _call_function(self):
        self._error_mesage = "Error Getting Inf. Info."
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetInfrastructureInfo(inf_id, Authentication(auth_data))


class Request_GetVMInfo(IMBaseRequest):
    """
    Request class for the GetVMInfo function
    """

    def _call_function(self):
        self._error_mesage = "Error Getting VM Info."
        (inf_id, vm_id, auth_data) = self.arguments
        return str(InfrastructureManager.InfrastructureManager.GetVMInfo(inf_id, vm_id, Authentication(auth_data)))


class Request_GetVMProperty(IMBaseRequest):
    """
    Request class for the GetVMProperty function
    """

    def _call_function(self):
        self._error_mesage = "Error Getting VM Property."
        (inf_id, vm_id, property_name, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetVMProperty(inf_id, vm_id, property_name,
                                                                         Authentication(auth_data))


class Request_AlterVM(IMBaseRequest):
    """
    Request class for the AlterVM function
    """

    def _call_function(self):
        self._error_mesage = "Error Changing VM Info."
        (inf_id, vm_id, radl, auth_data) = self.arguments
        return str(InfrastructureManager.InfrastructureManager.AlterVM(inf_id, vm_id, radl, Authentication(auth_data)))


class Request_DestroyInfrastructure(IMBaseRequest):
    """
    Request class for the DestroyInfrastructure function
    """

    def _call_function(self):
        self._error_mesage = "Error Destroying Inf."
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.DestroyInfrastructure(inf_id, Authentication(auth_data))


class Request_StopInfrastructure(IMBaseRequest):
    """
    Request class for the StopInfrastructure function
    """

    def _call_function(self):
        self._error_mesage = "Error Stopping Inf."
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.StopInfrastructure(inf_id, Authentication(auth_data))


class Request_StartInfrastructure(IMBaseRequest):
    """
    Request class for the StartInfrastructure function
    """

    def _call_function(self):
        self._error_mesage = "Error Starting Inf."
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.StartInfrastructure(inf_id, Authentication(auth_data))


class Request_CreateInfrastructure(IMBaseRequest):
    """
    Request class for the CreateInfrastructure function
    """

    def _call_function(self):
        self._error_mesage = "Error Creating Inf."
        (radl_data, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.CreateInfrastructure(radl_data, Authentication(auth_data))


class Request_GetInfrastructureList(IMBaseRequest):
    """
    Request class for the GetInfrastructureList function
    """

    def _call_function(self):
        self._error_mesage = "Error Getting Inf. List."
        (auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetInfrastructureList(Authentication(auth_data))


class Request_Reconfigure(IMBaseRequest):
    """
    Request class for the Reconfigure function
    """

    def _call_function(self):
        self._error_mesage = "Error Reconfiguring Inf."
        (inf_id, radl_data, auth_data, vm_list) = self.arguments
        return InfrastructureManager.InfrastructureManager.Reconfigure(inf_id, radl_data,
                                                                       Authentication(auth_data), vm_list)


class Request_ImportInfrastructure(IMBaseRequest):
    """
    Request class for the ImportInfrastructure function
    """

    def _call_function(self):
        self._error_mesage = "Error Importing Inf."
        (str_inf, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.ImportInfrastructure(str_inf, Authentication(auth_data))


class Request_ExportInfrastructure(IMBaseRequest):
    """
    Request class for the ExportInfrastructure function
    """

    def _call_function(self):
        self._error_mesage = "Error Exporting Inf."
        (inf_id, delete, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.ExportInfrastructure(inf_id, delete,
                                                                                Authentication(auth_data))


class Request_GetInfrastructureRADL(IMBaseRequest):
    """
    Request class for the GetInfrastructureRADL function
    """

    def _call_function(self):
        self._error_mesage = "Error getting RADL of the Inf."
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetInfrastructureRADL(inf_id, Authentication(auth_data))


class Request_GetVMContMsg(IMBaseRequest):
    """
    Request class for the GetVMContMsg function
    """

    def _call_function(self):
        self._error_mesage = "Error Getting VM cont msg."
        (inf_id, vm_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetVMContMsg(inf_id, vm_id, Authentication(auth_data))


class Request_GetInfrastructureContMsg(IMBaseRequest):
    """
    Request class for the GetInfrastructureContMsg function
    """

    def _call_function(self):
        self._error_mesage = "Error gettinf the Inf. cont msg"
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetInfrastructureContMsg(inf_id, Authentication(auth_data))


class Request_SaveData(IMBaseRequest):
    """
    Request class for the save_data function
    """

    def _call_function(self):
        self._error_mesage = "Error saving IM data"
        (inf_id) = self.arguments
        InfrastructureManager.InfrastructureManager.save_data(inf_id)
        return ""


class Request_StartVM(IMBaseRequest):
    """
    Request class for the StartVM function
    """

    def _call_function(self):
        self._error_mesage = "Error starting VM"
        (inf_id, vm_id, auth_data) = self.arguments
        InfrastructureManager.InfrastructureManager.StartVM(
            inf_id, vm_id, Authentication(auth_data))
        return ""


class Request_StopVM(IMBaseRequest):
    """
    Request class for the StopVM function
    """

    def _call_function(self):
        self._error_mesage = "Error stopping VM"
        (inf_id, vm_id, auth_data) = self.arguments
        InfrastructureManager.InfrastructureManager.StopVM(
            inf_id, vm_id, Authentication(auth_data))
        return ""


class Request_GetInfrastructureState(IMBaseRequest):
    """
    Request class for the GetInfrastructureState function
    """

    def _call_function(self):
        self._error_mesage = "Error getting the Inf. state"
        (inf_id, auth_data) = self.arguments
        return InfrastructureManager.InfrastructureManager.GetInfrastructureState(inf_id, Authentication(auth_data))


class Request_GetVersion(IMBaseRequest):
    """
    Request class for the GetVersion function
    """

    def _call_function(self):
        self._error_mesage = "Error getting IM service version"
        return version
