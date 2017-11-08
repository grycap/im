#! /usr/bin/env python
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

import sys
import logging
import logging.handlers
import logging.config
import os
import signal
import subprocess
import time

from IM.request import Request, AsyncXMLRPCServer, get_system_queue
from IM.config import Config
from IM.InfrastructureManager import InfrastructureManager
from IM.InfrastructureList import InfrastructureList
from IM.ServiceRequests import IMBaseRequest
from IM import __version__ as version

if sys.version_info <= (2, 6):
    print("Must use python 2.6 or greater")
    sys.exit(1)

logger = logging.getLogger('InfrastructureManager')


class ExtraInfoFilter(logging.Filter):
    """
    This is a filter which injects extra attributes into the log.
      * hostname
    """
    def filter(self, record):
        import socket
        record.hostname = socket.gethostname()
        return True


def WaitRequest(request):
    """
    Wait for the specified request
    """
    request.wait()
    success = (request.status() == Request.STATUS_PROCESSED)
    return (success, request.get())

# API functions.
# They create the specified request and wait for it.


def AddResource(inf_id, radl_data, auth_data, context=True):
    request = IMBaseRequest.create_request(
        IMBaseRequest.ADD_RESOURCE, (inf_id, radl_data, auth_data, context))
    return WaitRequest(request)


def RemoveResource(inf_id, vm_list, auth_data, context=True):
    request = IMBaseRequest.create_request(
        IMBaseRequest.REMOVE_RESOURCE, (inf_id, vm_list, auth_data, context))
    return WaitRequest(request)


def GetVMInfo(inf_id, vm_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_VM_INFO, (inf_id, vm_id, auth_data))
    return WaitRequest(request)


def GetVMProperty(inf_id, vm_id, property_name, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_VM_PROPERTY, (inf_id, vm_id, property_name, auth_data))
    return WaitRequest(request)


def AlterVM(inf_id, vm_id, radl, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.ALTER_VM, (inf_id, vm_id, radl, auth_data))
    return WaitRequest(request)


def GetInfrastructureInfo(inf_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_INFRASTRUCTURE_INFO, (inf_id, auth_data))
    return WaitRequest(request)


def StopInfrastructure(inf_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.STOP_INFRASTRUCTURE, (inf_id, auth_data))
    return WaitRequest(request)


def StartInfrastructure(inf_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.START_INFRASTRUCTURE, (inf_id, auth_data))
    return WaitRequest(request)


def DestroyInfrastructure(inf_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.DESTROY_INFRASTRUCTURE, (inf_id, auth_data))
    # This function take a lot of time in some connectors. We can make it
    # async: return (True, "")
    return WaitRequest(request)


def CreateInfrastructure(radl_data, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.CREATE_INFRASTRUCTURE, (radl_data, auth_data))
    return WaitRequest(request)


def GetInfrastructureList(auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_INFRASTRUCTURE_LIST, (auth_data))
    return WaitRequest(request)


def Reconfigure(inf_id, radl_data, auth_data, vm_list=None):
    request = IMBaseRequest.create_request(
        IMBaseRequest.RECONFIGURE, (inf_id, radl_data, auth_data, vm_list))
    return WaitRequest(request)


def ImportInfrastructure(str_inf, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.IMPORT_INFRASTRUCTURE, (str_inf, auth_data))
    return WaitRequest(request)


def ExportInfrastructure(inf_id, delete, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.EXPORT_INFRASTRUCTURE, (inf_id, delete, auth_data))
    return WaitRequest(request)


def GetInfrastructureRADL(inf_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_INFRASTRUCTURE_RADL, (inf_id, auth_data))
    return WaitRequest(request)


def GetVMContMsg(inf_id, vm_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_VM_CONT_MSG, (inf_id, vm_id, auth_data))
    return WaitRequest(request)


def GetInfrastructureContMsg(inf_id, auth_data, headeronly=False):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_INFRASTRUCTURE_CONT_MSG, (inf_id, auth_data, headeronly))
    return WaitRequest(request)


def StopVM(inf_id, vm_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.STOP_VM, (inf_id, vm_id, auth_data))
    return WaitRequest(request)


def StartVM(inf_id, vm_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.START_VM, (inf_id, vm_id, auth_data))
    return WaitRequest(request)


def GetInfrastructureState(inf_id, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.GET_INFRASTRUCTURE_STATE, (inf_id, auth_data))
    return WaitRequest(request)


def GetVersion():
    request = IMBaseRequest.create_request(IMBaseRequest.GET_VERSION, None)
    return WaitRequest(request)


def CreateDiskSnapshot(inf_id, vm_id, disk_num, image_name, auto_delete, auth_data):
    request = IMBaseRequest.create_request(
        IMBaseRequest.CREATE_DISK_SNAPSHOT, (inf_id, vm_id, disk_num, image_name, auto_delete, auth_data))
    return WaitRequest(request)


def launch_daemon():
    """
    Launch the IM daemon
    """
    InfrastructureList.init_table()

    if Config.XMLRCP_SSL:
        # if specified launch the secure version
        import ssl
        from IM.request import AsyncSSLXMLRPCServer
        server = AsyncSSLXMLRPCServer((Config.XMLRCP_ADDRESS, Config.XMLRCP_PORT), keyfile=Config.XMLRCP_SSL_KEYFILE,
                                      certfile=Config.XMLRCP_SSL_CERTFILE, ca_certs=Config.XMLRCP_SSL_CA_CERTS,
                                      cert_reqs=ssl.CERT_OPTIONAL)
    else:
        # otherwise the standard XML-RPC service
        server = AsyncXMLRPCServer((Config.XMLRCP_ADDRESS, Config.XMLRCP_PORT))

    # Register the API functions
    server.register_function(CreateInfrastructure)
    server.register_function(DestroyInfrastructure)
    server.register_function(StartInfrastructure)
    server.register_function(StopInfrastructure)
    server.register_function(GetInfrastructureInfo)
    server.register_function(GetVMInfo)
    server.register_function(GetVMProperty)
    server.register_function(AlterVM)
    server.register_function(RemoveResource)
    server.register_function(AddResource)
    server.register_function(GetInfrastructureList)
    server.register_function(Reconfigure)
    server.register_function(ExportInfrastructure)
    server.register_function(ImportInfrastructure)
    server.register_function(GetInfrastructureRADL)
    server.register_function(GetInfrastructureContMsg)
    server.register_function(GetVMContMsg)
    server.register_function(StartVM)
    server.register_function(StopVM)
    server.register_function(GetInfrastructureState)
    server.register_function(GetVersion)
    server.register_function(CreateDiskSnapshot)

    InfrastructureManager.logger.info(
        '************ Start Infrastructure Manager daemon (v.%s) ************' % version)

    # Launch the API XMLRPC thread
    server.serve_forever_in_thread()

    if Config.ACTIVATE_REST:
        # If specified launch the REST server
        import IM.REST
        IM.REST.run_in_thread(host=Config.REST_ADDRESS, port=Config.REST_PORT)

    # Start the messages queue
    get_system_queue().timed_process_loop(None, 1, exit_callback=im_stop)


def config_logging():
    """
    Init the logging info
    """
    try:
        # First look at /etc/im/logging.conf file
        logging.config.fileConfig('/etc/im/logging.conf')
    except Exception as ex:
        print(ex)
        log_dir = os.path.dirname(Config.LOG_FILE)
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir)

        fileh = logging.handlers.RotatingFileHandler(
            filename=Config.LOG_FILE, maxBytes=Config.LOG_FILE_MAX_SIZE, backupCount=3)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fileh.setFormatter(formatter)

        if Config.LOG_LEVEL == "DEBUG":
            log_level = logging.DEBUG
        elif Config.LOG_LEVEL == "INFO":
            log_level = logging.INFO
        elif Config.LOG_LEVEL in ["WARN", "WARNING"]:
            log_level = logging.WARN
        elif Config.LOG_LEVEL == "ERROR":
            log_level = logging.ERROR
        elif Config.LOG_LEVEL in ["FATAL", "CRITICAL"]:
            log_level = logging.FATAL
        else:
            log_level = logging.WARN

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        log = logging.getLogger('ConfManager')
        log.setLevel(log_level)
        log.propagate = 0
        log.addHandler(fileh)

        log = logging.getLogger('CloudConnector')
        log.setLevel(log_level)
        log.propagate = 0
        log.addHandler(fileh)

        log = logging.getLogger('InfrastructureManager')
        log.setLevel(log_level)
        log.propagate = 0
        log.addHandler(fileh)

    # Add the filter to add extra fields
    try:
        filt = ExtraInfoFilter()
        log = logging.getLogger('ConfManager')
        log.addFilter(filt)
        log = logging.getLogger('CloudConnector')
        log.addFilter(filt)
        log = logging.getLogger('InfrastructureManager')
        log.addFilter(filt)
    except Exception as ex:
        print(ex)


def im_stop():
    """
    Function to safely stop the service
    """
    try:
        # Assure that the IM data are correctly saved
        InfrastructureManager.logger.info(
            'Stopping Infrastructure Manager daemon...')
        InfrastructureManager.stop()

        if Config.ACTIVATE_REST:
            # we have to stop the REST server
            import IM.REST
            IM.REST.stop()
    except:
        InfrastructureManager.logger.exception(
            "Error stopping Infrastructure Manager daemon")

    # Assure that there are no Ansible process pending
    kill_childs()

    InfrastructureManager.logger.info(
        '************ Infrastructure Manager daemon stopped ************')
    sys.exit(0)


def get_childs(parent_id=None):
    if parent_id is None:
        parent_id = os.getpid()
    ps_command = subprocess.Popen("ps -o pid --ppid %d --noheaders" % parent_id, shell=True, stdout=subprocess.PIPE)
    ps_command.wait()
    ps_output = str(ps_command.stdout.read())
    childs = ps_output.strip().split("\n")[:-1]
    if childs:
        res = childs
        for child in childs:
            res.extend(get_childs(int(child)))
        return res
    else:
        return childs


def kill_childs():
    for pid_str in get_childs():
        os.kill(int(pid_str), signal.SIGTERM)
    # assure to kill all the processes using KILL signal
    time.sleep(1)
    for pid_str in get_childs():
        os.kill(int(pid_str), signal.SIGKILL)


def signal_int_handler(signal, frame):
    """
    Callback function to catch the system signals
    """
    im_stop()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_int_handler)
    config_logging()
    launch_daemon()
