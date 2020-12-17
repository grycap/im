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
# GNU General Public Licenslast_updatee for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import threading
import time
from uuid import uuid1
import json

import IM.ConfManager
from datetime import datetime, timedelta
from radl.radl import RADL, Feature, deploy, system, contextualize_item
from radl.radl_parse import parse_radl
from radl.radl_json import radlToSimple
from IM.openid.JWT import JWT
from IM.config import Config
try:
    from Queue import PriorityQueue
except ImportError:
    from queue import PriorityQueue
from IM.VirtualMachine import VirtualMachine
from IM.auth import Authentication
from IM.tosca.Tosca import Tosca

if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
    from multiprocessing.pool import ThreadPool


class IncorrectVMException(Exception):
    """ Invalid VM ID. """

    def __init__(self, msg="Invalid VM ID"):
        Exception.__init__(self, msg)
        self.message = msg


class DeletedVMException(Exception):
    """ Deleted VM. """

    def __init__(self, msg="Deleted VM."):
        Exception.__init__(self, msg)
        self.message = msg


class IncorrectStateException(Exception):
    """ Invalid State. """

    def __init__(self, msg="Invalid State to perform this operation."):
        Exception.__init__(self, msg)
        self.message = msg


class InfrastructureInfo:
    """
    Stores all the information about a registered infrastructure.
    """

    logger = logging.getLogger('InfrastructureManager')
    """Logger object."""

    FAKE_SYSTEM = "F0000__FAKE_SYSTEM__"
    OPENID_USER_PREFIX = "__OPENID__"

    def __init__(self):
        self._lock = threading.Lock()
        """Threading Lock to avoid concurrency problems."""
        self.id = str(uuid1())
        """Infrastructure unique ID. """
        self.vm_list = []
        """Map of int to VirtualMachine."""
        self.auth = None
        """Authentication of type ``InfrastructureManager``."""
        self.radl = RADL()
        """RADL associated to the infrastructure."""
        self.private_networks = {}
        """(dict from str to str) Cloud provider ids associated to a private network."""
        self.system_counter = 0
        """(int) Last system generated."""
        self.deleted = False
        """Flag to specify that this infrastructure has been deleted"""
        self.cm = None
        """ConfManager Thread to contextualize"""
        self.vm_master = None
        """VM selected as the master node to the contextualization step"""
        self.vm_id = 0
        """Next vm id available."""
        self.cont_out = ""
        """Contextualization output message"""
        self.ctxt_tasks = PriorityQueue()
        """List of contextualization tasks"""
        self.ansible_configured = None
        """Flag to specify that ansible is configured successfully in the master node of this inf."""
        self.configured = None
        """Flag to specify that the configuration threads of this inf has finished successfully or with errors."""
        self.conf_threads = []
        """ List of configuration threads."""
        self.extra_info = {}
        """ Extra information about the Infrastructure."""
        self.last_access = datetime.now()
        """ Time of the last access to this Inf. """
        self.snapshots = []
        """ List of URLs of snapshots made to this Inf that must be deleted on finalization """
        self.adding = False
        """Flag to specify that this Inf is adding resources """
        self.deleting = False
        """Flag to specify that this Inf is deleting resources """

    def serialize(self):
        with self._lock:
            odict = self.__dict__.copy()
        # Quit the ConfManager object and the lock to the data to be stored
        del odict['cm']
        del odict['_lock']
        del odict['ctxt_tasks']
        del odict['conf_threads']
        del odict['adding']
        del odict['deleting']
        if 'last_access' in odict:
            del odict['last_access']
        if odict['vm_master']:
            odict['vm_master'] = odict['vm_master'].im_id
        vm_list = []
        for vm in odict['vm_list']:
            vm_list.append(vm.serialize())
        odict['vm_list'] = vm_list
        if odict['auth']:
            odict['auth'] = odict['auth'].serialize()
        if odict['radl']:
            odict['radl'] = str(odict['radl'])
        if odict['extra_info'] and "TOSCA" in odict['extra_info']:
            odict['extra_info'] = {'TOSCA': odict['extra_info']['TOSCA'].serialize()}
        return json.dumps(odict)

    @staticmethod
    def deserialize(str_data):
        newinf = InfrastructureInfo()
        dic = json.loads(str_data)
        vm_list = dic['vm_list']
        vm_master_id = dic['vm_master']
        dic['vm_master'] = None
        dic['vm_list'] = []
        if dic['auth']:
            dic['auth'] = Authentication.deserialize(dic['auth'])
        if dic['radl']:
            dic['radl'] = parse_radl(dic['radl'])
        else:
            dic['radl'] = RADL()
        if 'extra_info' in dic and dic['extra_info'] and "TOSCA" in dic['extra_info']:
            try:
                dic['extra_info']['TOSCA'] = Tosca.deserialize(dic['extra_info']['TOSCA'])
            except Exception:
                del dic['extra_info']['TOSCA']
                InfrastructureInfo.logger.exception("Error deserializing TOSCA document")
        newinf.__dict__.update(dic)
        newinf.cloud_connector = None
        # Set the ConfManager object and the lock to the data loaded
        newinf.cm = None
        newinf.ctxt_tasks = PriorityQueue()
        newinf.conf_threads = []
        for vm_data in vm_list:
            vm = VirtualMachine.deserialize(vm_data)
            vm.inf = newinf
            if vm.im_id == vm_master_id:
                newinf.vm_master = vm
            newinf.vm_list.append(vm)
        newinf.adding = False
        newinf.deleting = False
        return newinf

    @staticmethod
    def deserialize_auth(str_data):
        """
        Only Loads auth data
        """
        newinf = InfrastructureInfo()
        dic = json.loads(str_data)
        newinf.deleted = dic['deleted']
        newinf.id = dic['id']
        if dic['auth']:
            newinf.auth = Authentication.deserialize(dic['auth'])
        return newinf

    def destroy_vms(self, auth):
        """
        Destroy all the VMs
        """
        delete_list = list(reversed(self.get_vm_list()))

        exceptions = []
        if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
            pool = ThreadPool(processes=Config.MAX_SIMULTANEOUS_LAUNCHES)
            pool.map(
                lambda vm: vm.delete(delete_list, auth, exceptions),
                delete_list
            )
            pool.close()
        else:
            # If IM server is the first VM, then it will be the last destroyed
            for vm in delete_list:
                vm.delete(delete_list, auth, exceptions)

        if exceptions:
            msg = ""
            for e in exceptions:
                msg += str(e) + "\n"
            raise Exception("Error destroying the infrastructure: \n%s" % msg)

    def delete(self):
        """
        Set this Inf as deleted
        """
        self.stop()
        self.deleted = True

    def stop(self):
        """
        Stop all the Ctxt threads
        """
        # Stop the Ctxt thread if it is alive.
        if self.cm and self.cm.isAlive():
            self.cm.stop()

        # kill all the ctxt processes in the VMs
        for vm in self.get_vm_list():
            vm.kill_check_ctxt_process()

        # Create a new empty queue
        with self._lock:
            self.ctxt_tasks = PriorityQueue()

    def destroy(self, auth, force=False):
        """
        Destroy the infrastructure
        """
        InfrastructureInfo.logger.info("Destroying the Inf ID: %s (force=%s)" % (self.id, force))
        try:
            # First stop ctxt processes
            self.stop()
            # Destroy the Infrastructure
            self.destroy_vms(auth)
        except Exception as ex:
            if not force:
                raise ex
        finally:
            self.set_deleting(False)
        # Set the Infrastructure as deleted
        self.delete()
        InfrastructureInfo.logger.info("Inf ID: %s: Successfully destroyed" % self.id)
        IM.InfrastructureList.InfrastructureList.save_data(self.id)
        IM.InfrastructureList.InfrastructureList.remove_inf(self)

    def get_cont_out(self):
        """
        Returns the contextualization message
        """
        return self.cont_out

    def add_vm(self, vm):
        """
        Add, and assigns a new VM ID to the infrastructure
        """
        with self._lock:
            # Store the creation ID
            vm.creation_im_id = vm.im_id
            # Set the ID of the pos in the list
            vm.im_id = len(self.vm_list)
            # Store the creation ID if not set
            if vm.creation_im_id is None:
                vm.creation_im_id = vm.im_id
            self.vm_list.append(vm)
        IM.InfrastructureList.InfrastructureList.save_data(self.id)

    def add_cont_msg(self, msg):
        """
        Add a line to the contextualization message
        """
        try:
            str_msg = str(msg.decode('utf8', 'ignore'))
        except Exception:
            str_msg = msg
        self.cont_out += str(datetime.now()) + ": " + str_msg + "\n"

    def remove_creating_vms(self):
        """
        Remove the VMs with the creating flag
        """
        with self._lock:
            self.vm_list = [vm for vm in self.vm_list if not vm.creating]

    def get_vm_list(self):
        """
        Get the list of not destroyed VMs.
        """
        with self._lock:
            res = [vm for vm in self.vm_list if not vm.destroy]
        return res

    def get_vm(self, str_vm_id):
        """
        Get the VM with the specified ID (if it is not destroyed)
        """
        try:
            vm_id = int(str_vm_id)
        except Exception:
            raise IncorrectVMException()

        with self._lock:
            for vm in self.vm_list:
                if vm.im_id == vm_id:
                    if not vm.destroy:
                        return vm
                    else:
                        raise DeletedVMException()
        raise IncorrectVMException()

    def get_vm_list_by_system_name(self):
        """
        Get the list of not destroyed VMs grouped by the name of system.
        """
        groups = {}
        for vm in self.get_vm_list():
            if vm.getRequestedSystem().name in groups:
                groups[vm.getRequestedSystem().name].append(vm)
            else:
                groups[vm.getRequestedSystem().name] = [vm]
        return groups

    def update_radl(self, radl, deployed_vms, warn=True):
        """
        Update the stored radl with the passed one.

        Args:

        - radl(RADL) RADL base of the deployment.
        - deployed_vms(list of tuple of deploy, system and list of VirtualMachines): list of
           tuples composed of the deploy, the concrete system deployed and the list of
           virtual machines deployed.
        - warn(bool): Log a Warn message in case of redefinition
        """

        with self._lock:
            original_radl = self.radl.clone()
            # Add new networks ad ansible_hosts only
            for s in radl.networks + radl.ansible_hosts:
                if not self.radl.add(s.clone(), "ignore") and warn:
                    InfrastructureInfo.logger.warn("Ignoring the redefinition of %s %s" % (type(s), s.getId()))

            # Add or update configures and systems
            for s in radl.configures + radl.systems:
                if self.radl.get(s) and warn:
                    InfrastructureInfo.logger.warn("(Re)definition of %s %s" % (type(s), s.getId()))
                self.radl.add(s.clone(), "replace")

            # Append contextualize
            self.radl.add(radl.contextualize)

            if radl.deploys:
                # Overwrite to create only the last deploys
                self.radl.deploys = radl.deploys

            # Associate private networks with cloud providers
            for d, _, _ in deployed_vms:
                for private_net in [net.id for net in radl.networks if not net.isPublic() and
                                    net.id in radl.get_system_by_name(d.id).getNetworkIDs()]:
                    if private_net in self.private_networks:
                        assert self.private_networks[private_net] == d.cloud_id
                    else:
                        self.private_networks[private_net] = d.cloud_id

        # Check the RADL
        try:
            self.radl.check()
        except Exception as ex:
            # If something is not correct restore the original one and raise the error
            self.radl = original_radl
            raise(ex)

    def complete_radl(self, radl):
        """
        Update passed radl with the stored RADL.
        """

        with self._lock:
            # Replace references of systems, networks and configures by its
            # definitions
            for s in radl.networks + radl.systems + radl.configures + radl.ansible_hosts:
                if s.reference:
                    aspect = self.radl.get(s)
                    if aspect is None:
                        raise Exception(
                            "Unknown reference in RADL to %s '%s'" % (type(s), s.getId()))
                    radl.add(aspect.clone(), "replace")

            # Add fake deploys to indicate the cloud provider associated to a
            # private network.
            system_counter = 0
            for n in radl.networks:
                if n.id in self.private_networks:
                    system_id = self.FAKE_SYSTEM + str(system_counter)
                    system_counter += 1
                    radl.add(
                        system(system_id, [Feature("net_interface.0.connection", "=", n.id)]))
                    radl.add(deploy(system_id, 0, self.private_networks[n.id]))

        # Check the RADL
        radl.check()

    def get_json_radl(self):
        """
        Get the RADL of this Infrastructure in JSON format to
        send it to the Ansible inventory
        """
        radl = self.radl.clone()
        res_radl = RADL()
        res_radl.systems = radl.systems
        res_radl.networks = radl.networks
        res_radl.deploys = radl.deploys
        json_data = []
        # remove "." in key names
        for elem in radlToSimple(res_radl):
            new_data = {}
            for key in elem.keys():
                new_data[key.replace(".", "_")] = elem[key]
            json_data.append(new_data)
        return json.dumps(json_data)

    def get_radl(self):
        """
        Get the RADL of this Infrastructure
        """
        # remove the F0000__FAKE_SYSTEM__ deploys
        # TODO: Do in a better way
        radl = self.radl.clone()
        deploys = []
        for deploy in radl.deploys:
            if not deploy.id.startswith(self.FAKE_SYSTEM):
                deploys.append(deploy)
        radl.deploys = deploys

        # remove the F0000__FAKE_SYSTEM__ deploys
        # TODO: Do in a better way
        systems = []
        for system in radl.systems:
            if not system.name.startswith(self.FAKE_SYSTEM):
                systems.append(system)
        radl.systems = systems

        return radl

    def select_vm_master(self):
        """
        Select the VM master of the infrastructure.
        The master VM must be have a Linux OS connected with the maximum number of VMs
        It will select the first created VM that fulfills this requirements
        and store the value in the vm_master field
        """
        # If it was previously selected do no select a new one
        if self.vm_master and not self.vm_master.destroy and not self.vm_master.deleting:
            return self.vm_master

        self.vm_master = None
        max_vms_connected = -1
        for vm in self.get_vm_list():
            vms_connected = -1
            if vm.getOS() and vm.getOS().lower() == 'linux' and (vm.hasPublicNet() or vm.getProxyHost()):
                # check that is connected with other VMs
                vms_connected = 0
                for other_vm in self.get_vm_list():
                    if vm.isConnectedWith(other_vm):
                        vms_connected += 1

                if vms_connected > max_vms_connected:
                    max_vms_connected = vms_connected
                    self.vm_master = vm

    def vm_in_ctxt_tasks(self, vm):
        found = False
        with self._lock:
            for (_, _, v, _) in list(self.ctxt_tasks.queue):
                if v == vm:
                    found = True
                    break
        return found

    def set_configured(self, conf):
        with self._lock:
            if conf:
                if self.configured is None:
                    self.configured = conf
            else:
                self.configured = conf

    def is_configured(self):
        if self.vm_in_ctxt_tasks(self) or self.conf_threads:
            # If there are ctxt tasks pending for this VM, return None
            return None
        else:
            # Otherwise return the value of configured
            return self.configured

    def reset_ctxt_tasks(self):
        with self._lock:
            self.ctxt_tasks = PriorityQueue()

    def add_ctxt_tasks(self, ctxt_tasks):
        # Use the lock to add all the tasks in a atomic way
        with self._lock:
            to_add = []
            for (step, prio, vm, tasks) in ctxt_tasks:
                # Check that the element does not exist in the Queue
                found = False
                for (s, _, v, t) in list(self.ctxt_tasks.queue):
                    if s == step and v == vm and t == tasks:
                        found = True
                if not found:
                    to_add.append((step, prio, vm, tasks))

            for elem in to_add:
                self.ctxt_tasks.put(elem)

    def get_ctxt_process_names(self):
        return [t.name for t in self.conf_threads if t.isAlive()]

    def is_ctxt_process_running(self):
        all_finished = True
        for t in self.conf_threads:
            if t.isAlive():
                all_finished = False
        if all_finished:
            self.conf_threads = []
        return not all_finished

    def Contextualize(self, auth, vm_list=None):
        """
        Launch the contextualization process of this Inf

        Args:

        - auth(Authentication): parsed authentication tokens.
        - vm_list(list of int): List of VM ids to reconfigure. If None all VMs will be reconfigured.
        """
        ctxt = True

        # If the user has specified an empty contextualize it means that he
        # does not want to avoid it
        if self.radl.contextualize.items == {}:
            ctxt = False
        else:
            # check if there are any contextualize_item that needs "Ansible"
            if self.radl.contextualize.items:
                ctxt = False
                for item in self.radl.contextualize.items.values():
                    if item.get_ctxt_tool() == "Ansible":
                        ctxt = True
                        break

        ctxt_task = []
        max_ctxt_time = self.radl.contextualize.max_time
        if not max_ctxt_time:
            max_ctxt_time = Config.MAX_CONTEXTUALIZATION_TIME

        self.configured = None
        for vm in self.get_vm_list():
            # Assure to update the VM status before running the ctxt process
            vm.update_status(auth)
            vm.cont_out = ""
            vm.cloud_connector = None
            vm.configured = None

        if not ctxt:
            InfrastructureInfo.logger.info("Inf ID: " + str(self.id) + ": Contextualization disabled by the RADL. " +
                                           "Only wait for VM IPs.")

            ctxt_task.append((-2, 0, self, ['check_vm_ips']))
            ctxt_task.append((-1, 0, self, ['wait_all_vm_ips']))

            self.cont_out = "Contextualization disabled by the RADL.\n\n"
            for vm in self.get_vm_list():
                vm.configured = True
        else:
            self.cont_out = ""
            self.configured = None
            # get the default ctxts in case of the RADL has not specified them
            ctxts = [contextualize_item(group, group, 1) for group in self.get_vm_list_by_system_name(
            ) if self.radl.get_configure_by_name(group)]
            # get the contextualize steps specified in the RADL, or use the
            # default value
            contextualizes = self.radl.contextualize.get_contextualize_items_by_step({1: ctxts})

            ctxt_task.append((-5, 0, self, ['kill_ctxt_processes']))
            ctxt_task.append((-4, 0, self, ['check_vm_ips']))
            ctxt_task.append((-3, 0, self, ['wait_master']))
            ctxt_task.append((-2, 0, self, ['configure_master', 'wait_all_vm_ips']))
            ctxt_task.append((-1, 0, self, ['generate_playbooks_and_hosts']))

            use_dist = len(self.get_vm_list()) > Config.VM_NUM_USE_CTXT_DIST
            for cont, vm in enumerate(self.get_vm_list()):
                tasks = {}

                # Add basic tasks for all VMs
                if use_dist:
                    init_steps = 5
                    tasks[0] = ['install_ansible']
                    tasks[1] = ['basic']
                    if cont == 0:
                        tasks[2] = ['gen_facts_cache']
                    else:
                        tasks[2] = []
                    if cont == 0:
                        tasks[3] = []
                    else:
                        tasks[3] = ['copy_facts_cache']
                    tasks[4] = ['main_' + vm.info.systems[0].name]
                else:
                    init_steps = 3
                    if cont == 0:
                        # In the first VM put the wait all ssh task
                        tasks[0] = ['wait_all_ssh']
                        tasks[1] = ['basic']
                    else:
                        tasks[0] = []
                        tasks[1] = ['basic']
                    tasks[2] = ['main_' + vm.info.systems[0].name]

                # And the specific tasks only for the specified ones
                if not vm_list or vm.im_id in vm_list:
                    # Then add the configure sections
                    for ctxt_num in contextualizes.keys():
                        for ctxt_elem in contextualizes[ctxt_num]:
                            step = ctxt_num + init_steps
                            if ctxt_elem.system == vm.info.systems[0].name and ctxt_elem.get_ctxt_tool() == "Ansible":
                                if step not in tasks:
                                    tasks[step] = []
                                tasks[step].append(ctxt_elem.configure + "_" + ctxt_elem.system)

                for step in tasks.keys():
                    priority = 0
                    ctxt_task.append((step, priority, vm, tasks[step]))

        self.add_ctxt_tasks(ctxt_task)

        if self.cm is None or not self.cm.isAlive():
            self.cm = IM.ConfManager.ConfManager(self, auth, max_ctxt_time)
            self.cm.start()
        else:
            # update the ConfManager reference to the inf object
            self.cm.inf = self
            # update the ConfManager auth
            self.cm.auth = auth
            self.cm.init_time = time.time()
            # restart the failed step
            self.cm.failed_step = []

    def is_authorized(self, auth):
        """
        Checks if the auth data provided is authorized to access this infrastructure
        """
        if self.auth is not None:
            self_im_auth = self.auth.getAuthInfo("InfrastructureManager")[0]
            other_im_auth = auth.getAuthInfo("InfrastructureManager")[0]

            for elem in ['username', 'password']:
                if elem not in other_im_auth:
                    return False
                if elem not in self_im_auth:
                    InfrastructureInfo.logger.error("Inf ID %s has not elem %s in the auth data" % (self.id, elem))
                    return True
                if self_im_auth[elem] != other_im_auth[elem]:
                    return False

            if 'token' in self_im_auth:
                if 'token' not in other_im_auth:
                    return False
                decoded_token = JWT().get_info(other_im_auth['token'])
                password = str(decoded_token['iss']) + str(decoded_token['sub'])
                # check that the token provided is associated with the current owner of the inf.
                if self_im_auth['password'] != password:
                    return False

                # In case of OIDC token update it in each call to get a fresh version
                self_im_auth['token'] = other_im_auth['token']

            if (self_im_auth['username'].startswith(InfrastructureInfo.OPENID_USER_PREFIX) and
                    'token' not in other_im_auth):
                # This is a OpenID user do not enable to get data using user/pass creds
                InfrastructureInfo.logger.warn("Inf ID %s: A non OpenID user tried to access it." % self.id)
                return False

            return True
        else:
            return False

    def touch(self):
        """
        Set last access of the Inf
        """
        self.last_access = datetime.now()

    def has_expired(self):
        """
        Check if the info of this Inf has expired (for HA mode)
        """
        if Config.INF_CACHE_TIME:
            delay = timedelta(seconds=Config.INF_CACHE_TIME)
            return (datetime.now() - self.last_access > delay)
        else:
            return False

    def set_deleting(self, value=True):
        """
        Set this inf as deleting
        """
        with self._lock:
            if self.adding:
                raise IncorrectStateException()
            self.deleting = value

    def set_adding(self, value=True):
        """
        Set this inf as adding
        """
        with self._lock:
            if self.deleting:
                self.add_cont_msg("Infrastructure deleted. Do not add resources.")
                raise Exception("Infrastructure deleted. Do not add resources.")
            self.adding = value
