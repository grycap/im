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

import json
import os
import string
import random
import logging

import IM.InfrastructureInfo
import IM.InfrastructureList

from IM.VMRC import VMRC
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from IM.recipe import Recipe
from IM.config import Config
from IM.VirtualMachine import VirtualMachine

from radl import radl_parse
from radl.radl import Feature, RADL
from radl.radl_json import dump_radl as dump_radl_json

if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
    from multiprocessing.pool import ThreadPool

try:
    unicode("hola")
except NameError:
    unicode = str


class UnauthorizedUserException(Exception):
    """ Invalid InfrastructureManager credentials to access an infrastructure"""

    def __init__(self, msg="Access to this infrastructure not granted."):
        Exception.__init__(self, msg)


class IncorrectInfrastructureException(Exception):
    """ Invalid infrastructure ID or access not granted. """

    def __init__(self, msg="Invalid infrastructure ID or access not granted."):
        Exception.__init__(self, msg)


class DeletedInfrastructureException(Exception):
    """ Deleted infrastructure. """

    def __init__(self, msg="Deleted infrastructure."):
        Exception.__init__(self, msg)


class InvaliddUserException(Exception):
    """ Invalid InfrastructureManager credentials """

    def __init__(self, msg="Invalid InfrastructureManager credentials"):
        Exception.__init__(self, msg)


class IncorrectVMCrecentialsException(Exception):
    """ Invalid InfrastructureManager credentials """

    def __init__(self, msg="Incorrect VM credentials"):
        Exception.__init__(self, msg)


class InfrastructureManager:
    """
    Front-end to the functionality of the service.
    """

    logger = logging.getLogger('InfrastructureManager')
    """Logger object."""

    @staticmethod
    def _reinit():
        """Restart the class attributes to initial values."""
        IM.InfrastructureList.InfrastructureList._reinit()

    @staticmethod
    def _compute_deploy_groups(radl):
        """
        Group the virtual machines that had to be deployed together.

        Args:

        - radl(RADL): RADL to consider.

        Return(list of list of deploy): list of group of deploys.
        """

        # If some virtual machine is in two private networks, the machines in both
        # networks will be in the same group
        # NOTE: net_groups is a *Disjoint-set data structure*
        net_groups = {}
        for net in radl.networks:
            net_groups[net.id] = net.id

        def root(n):
            while True:
                n0 = net_groups[n]
                if n0 == n:
                    return n
                n = n0

        for d in radl.deploys:
            private_nets = [net.id for net in radl.networks if not net.isPublic() and
                            net.id in radl.get_system_by_name(d.id).getNetworkIDs()]
            if not private_nets:
                continue
            for n in private_nets[1:]:
                net_groups[root(n)] = net_groups[root(private_nets[0])]

        deploy_groups = []
        deploy_groups_net = {}
        for d in radl.deploys:
            private_nets = [net.id for net in radl.networks if not net.isPublic() and
                            net.id in radl.get_system_by_name(d.id).getNetworkIDs()]
            # If no private net is set, every launch can go in a separate group
            if not private_nets:
                for _ in range(d.vm_number):
                    d0 = d.clone()
                    d0.vm_number = 1
                    deploy_groups.append([d0])
                continue
            # Otherwise the deploy goes to some group
            net = net_groups[root(private_nets[0])]
            if net not in deploy_groups_net:
                deploy_groups_net[net] = [d]
            else:
                deploy_groups_net[net].append(d)

        deploy_groups.extend(deploy_groups_net.values())
        return deploy_groups

    @staticmethod
    def _launch_group(sel_inf, deploy_group, deploys_group_cloud_list, cloud_list, concrete_systems,
                      radl, auth, deployed_vm, cancel_deployment):
        """Launch a group of deploys together."""

        if not deploy_group:
            InfrastructureManager.logger.warning("Inf ID: %s: No VMs to deploy!" % sel_inf.id)
            return
        if not deploys_group_cloud_list:
            cancel_deployment.append(Exception("No cloud provider available"))
            return
        all_ok = False
        exceptions = []
        for cloud_id in deploys_group_cloud_list:
            cloud = cloud_list[cloud_id]
            all_ok = True
            for deploy in deploy_group:
                remain_vm, fail_cont = deploy.vm_number, 0
                while remain_vm > 0 and fail_cont < Config.MAX_VM_FAILS and not cancel_deployment:
                    concrete_system = concrete_systems[cloud_id][deploy.id][0]
                    if not concrete_system:
                        InfrastructureManager.logger.error(
                            "Inf ID: " + sel_inf.id + ": " +
                            "Error, no concrete system to deploy: " + deploy.id + " in cloud: " +
                            cloud_id + ". Check if a correct image is being used")
                        exceptions.append("Error, no concrete system to deploy: " + deploy.id +
                                          " in cloud: " + cloud_id + ". Check if a correct image is being used")
                        break

                    (username, _, _, _) = concrete_system.getCredentialValues()
                    if not username:
                        raise IncorrectVMCrecentialsException("No username for deploy: " + deploy.id)

                    launch_radl = radl.clone()
                    launch_radl.systems = [concrete_system.clone()]
                    requested_radl = radl.clone()
                    requested_radl.systems = [radl.get_system_by_name(concrete_system.name)]
                    try:
                        InfrastructureManager.logger.info(
                            "Inf ID: " + sel_inf.id + ": " +
                            "Launching %d VMs of type %s" % (remain_vm, concrete_system.name))
                        launched_vms = cloud.cloud.getCloudConnector(sel_inf).launch(
                            sel_inf, launch_radl, requested_radl, remain_vm, auth)
                    except Exception as e:
                        InfrastructureManager.logger.exception("Inf ID: " + sel_inf.id + ": " +
                                                               "Error launching some of the VMs: %s" % e)
                        exceptions.append("Error launching the VMs of type %s to cloud ID %s"
                                          " of type %s. Cloud Provider Error: %s" % (concrete_system.name,
                                                                                     cloud.cloud.id,
                                                                                     cloud.cloud.type, e))
                        launched_vms = []
                    for success, launched_vm in launched_vms:
                        if success:
                            InfrastructureManager.logger.info("Inf ID: " + sel_inf.id + ": " +
                                                              "VM successfully launched: " + str(launched_vm.id))
                            deployed_vm.setdefault(deploy, []).append(launched_vm)
                            deploy.cloud_id = cloud_id
                            remain_vm -= 1
                        else:
                            InfrastructureManager.logger.warn(
                                "Inf ID: " + sel_inf.id + ": " +
                                "Error launching some of the VMs: " + str(launched_vm))
                            exceptions.append("Error launching the VMs of type %s to cloud ID %s of type %s. %s" % (
                                concrete_system.name, cloud.cloud.id, cloud.cloud.type, str(launched_vm)))
                            if not isinstance(launched_vm, (str, unicode)):
                                cloud.finalize(launched_vm, True, auth)
                    fail_cont += 1
                if remain_vm > 0 or cancel_deployment:
                    all_ok = False
                    break
            if not all_ok:
                for deploy in deploy_group:
                    for vm in deployed_vm.get(deploy, []):
                        vm.finalize(True, auth)
                    deployed_vm[deploy] = []
            if cancel_deployment or all_ok:
                break
        if not all_ok and not cancel_deployment:
            msg = ""
            for i, e in enumerate(exceptions):
                msg += "Attempt " + str(i + 1) + ": " + str(e) + "\n"
            cancel_deployment.append(
                Exception("All machines could not be launched: \n%s" % msg))

    @staticmethod
    def get_infrastructure(inf_id, auth):
        """Return infrastructure info with some id if valid authorization provided."""

        if inf_id not in IM.InfrastructureList.InfrastructureList.get_inf_ids():
            InfrastructureManager.logger.error("Error, incorrect infrastructure ID: %s" % inf_id)
            raise IncorrectInfrastructureException()
        sel_inf = IM.InfrastructureList.InfrastructureList.get_infrastructure(inf_id)
        if not sel_inf.is_authorized(auth):
            InfrastructureManager.logger.error("Access Error to infrastructure ID: %s" % inf_id)
            raise UnauthorizedUserException()
        if sel_inf.deleted:
            InfrastructureManager.logger.error("Infrastructure ID: %s is deleted." % inf_id)
            raise DeletedInfrastructureException()

        return sel_inf

    @staticmethod
    def get_vm_from_inf(inf_id, vm_id, auth):
        """Return VirtualMachie info with some id of an infrastructure if valid authorization provided."""
        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        return sel_inf.get_vm(vm_id)

    @staticmethod
    def Reconfigure(inf_id, radl_data, auth, vm_list=None):
        """
        Add and update RADL definitions and reconfigure the infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - radl_data(str): RADL description, it can be empty.
        - auth(Authentication): parsed authentication tokens.
        - vm_list(list of int): List of VM ids to reconfigure. If None all VMs will be reconfigured.

        Return: "" if success.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Reconfiguring the inf: " + str(inf_id))
        if isinstance(radl_data, RADL):
            radl = radl_data
        else:
            radl = radl_parse.parse_radl(radl_data)
        InfrastructureManager.logger.debug(radl)

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        # Update infrastructure RADL with this new RADL
        # Add or update configures
        for s in radl.configures:
            sel_inf.radl.add(s.clone(), "replace")
            InfrastructureManager.logger.info(
                "Inf ID: " + sel_inf.id + ": " +
                "(Re)definition of %s %s" % (type(s), s.getId()))

        # and update contextualize
        sel_inf.radl.add(radl.contextualize)

        # Check if the user want to set a new password to any system:
        for system in sel_inf.radl.systems:
            new_system = radl.get_system_by_name(system.name)
            if new_system:
                new_creds = new_system.getCredentialValues(new=True)
                # The user has specified a credential:
                if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] is not None:
                    creds = system.getCredentialValues()
                    if new_creds != creds:
                        # The credentials have changed
                        (_, password, public_key, private_key) = new_creds
                        system.setCredentialValues(
                            password=password, public_key=public_key, private_key=private_key, new=True)

        # Stick all virtual machines to be reconfigured
        InfrastructureManager.logger.info("Contextualize the inf: " + sel_inf.id)
        # reset ansible_configured to force the re-installation of galaxy roles
        sel_inf.ansible_configured = None
        sel_inf.Contextualize(auth, vm_list)

        IM.InfrastructureList.InfrastructureList.save_data(inf_id)

        return ""

    @staticmethod
    def _compute_score(system_score, requested_radl):
        """
        Computes the score of a concrete radl comparing with the requested one.

        Args:

        - system_score(tuple(radl.system, int)): System object to deploy and the score
        - requested_radl(radl.system): Original system requested by the user.

        Return(tuple(radl.system, int)): System object to deploy and the new computed score
        """

        concrete_system, score = system_score

        req_apps = requested_radl.getApplications()
        inst_apps = concrete_system.getApplications()

        # Set highest priority to the original score
        score *= 10000

        # For each requested app installed in the VMI score with +100
        if inst_apps:
            for req_app in req_apps:
                for inst_app in inst_apps:
                    if inst_app.isNewerThan(req_app):
                        score += 100

        # For each installed app that is not requested score with -1
        if inst_apps:
            for inst_app in inst_apps:
                if inst_app in req_apps:
                    # Check the version
                    for req_app in req_apps:
                        if req_app.isNewerThan(inst_app):
                            score -= 1
                elif inst_app.getValue("version"):
                    # Only set score to -1 when the user requests a version
                    # to avoid score -1 if the user wants to install some packages
                    # if is not requested -1
                    score -= 1

        return concrete_system, score

    @staticmethod
    def AddResource(inf_id, radl_data, auth, context=True, failed_clouds=None):
        """
        Add the resources in the RADL to the infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - radl(str): RADL description.
        - auth(Authentication): parsed authentication tokens.
        - context(bool): Flag to specify if the ctxt step will be made
        - failed_clouds(list of CloudInfo): A list of failed Cloud providers to avoid launching the VMs in them.

        Return(list of int): ids of the new virtual machine created.
        """
        if failed_clouds is None:
            failed_clouds = []
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Adding resources to inf: " + str(inf_id))

        if isinstance(radl_data, RADL):
            radl = radl_data
        else:
            radl = radl_parse.parse_radl(radl_data)

        InfrastructureManager.logger.debug(radl)
        radl.check()

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        # Update infrastructure RADL with this new RADL
        sel_inf.complete_radl(radl)

        # If any deploy is defined, only update definitions.
        if not radl.deploys:
            sel_inf.update_radl(radl, [])
            InfrastructureManager.logger.warn("Inf ID: " + sel_inf.id + ": without any deploy. Exiting.")
            return []

        for system in radl.systems:
            # Add apps requirements to the RADL
            apps_to_install = system.getApplications()
            for app_to_install in apps_to_install:
                for app_avail, _, _, _, requirements in Recipe.getInstallableApps():
                    if requirements and app_avail.isNewerThan(app_to_install):
                        # This app must be installed and it has special
                        # requirements
                        try:
                            requirements_radl = radl_parse.parse_radl(
                                requirements).systems[0]
                            system.applyFeatures(
                                requirements_radl, conflict="other", missing="other")
                        except Exception:
                            InfrastructureManager.logger.exception(
                                "Inf ID: " + sel_inf.id + ": " +
                                "Error in the requirements of the app: " +
                                app_to_install.getValue("name") +
                                ". Ignore them.")
                            InfrastructureManager.logger.debug(requirements)
                        break

        # Get VMRC credentials
        vmrc_list = []
        for vmrc_elem in auth.getAuthInfo('VMRC'):
            if ('host' in vmrc_elem and 'username' in vmrc_elem and
                    'password' in vmrc_elem):
                vmrc_list.append(VMRC(vmrc_elem['host'], vmrc_elem['username'],
                                      vmrc_elem['password']))

        # Concrete systems using VMRC
        # NOTE: consider not-fake deploys (vm_number > 0)
        systems_with_vmrc = {}
        for system_id in set([d.id for d in radl.deploys if d.vm_number > 0]):
            s = radl.get_system_by_name(system_id)

            if not s.getValue("disk.0.image.url") and len(vmrc_list) == 0:
                raise Exception(
                    "No correct VMRC auth data provided nor image URL")

            # Remove the requested apps from the system
            s_without_apps = radl.get_system_by_name(system_id).clone()
            s_without_apps.delValue("disk.0.applications")

            # Set the default values for cpu, memory
            defaults = (Feature("cpu.count", ">=", Config.DEFAULT_VM_CPUS),
                        Feature("memory.size", ">=", Config.DEFAULT_VM_MEMORY,
                                Config.DEFAULT_VM_MEMORY_UNIT),
                        Feature("cpu.arch", "=", Config.DEFAULT_VM_CPU_ARCH))
            for f in defaults:
                if not s_without_apps.hasFeature(f.prop, check_softs=True):
                    s_without_apps.addFeature(f)

            vmrc_res = [s0 for vmrc in vmrc_list for s0 in vmrc.search_vm(s)]
            # Check that now the image URL is in the RADL
            if not s.getValue("disk.0.image.url") and not vmrc_res:
                raise Exception(
                    "No VMI obtained from VMRC to system: " + system_id)

            n = [s_without_apps.clone().applyFeatures(s0, conflict="other", missing="other")
                 for s0 in vmrc_res]
            systems_with_vmrc[system_id] = n if n else [s_without_apps]

        # Concrete systems with cloud providers and select systems with the greatest score
        # in every cloud
        cloud_list = dict([(c.id, c.getCloudConnector(sel_inf))
                           for c in CloudInfo.get_cloud_list(auth) if c not in failed_clouds])
        concrete_systems = {}
        for cloud_id, cloud in cloud_list.items():
            for system_id, systems in systems_with_vmrc.items():
                s1 = [InfrastructureManager._compute_score(s.clone().applyFeatures(s0,
                                                                                   conflict="other",
                                                                                   missing="other").concrete(),
                                                           radl.get_system_by_name(system_id))
                      for s in systems for s0 in cloud.concreteSystem(s, auth)]
                # Store the concrete system with largest score
                concrete_systems.setdefault(cloud_id, {})[system_id] = (
                    max(s1, key=lambda x: x[1]) if s1 else (None, -1e9))

        # Group virtual machines to deploy by network dependencies
        deploy_groups = InfrastructureManager._compute_deploy_groups(radl)
        InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + ": Groups of VMs with dependencies")
        InfrastructureManager.logger.debug(deploy_groups)

        # Sort by score the cloud providers
        # NOTE: consider fake deploys (vm_number == 0)
        deploys_group_cloud_list = {}
        # reverse the list to use the reverse order in the sort function
        # list of ordered clouds

        ordered_cloud_list = [c.id for c in CloudInfo.get_cloud_list(auth)]
        ordered_cloud_list.reverse()
        for deploy_group in deploy_groups:
            suggested_cloud_ids = list(set([d.cloud_id for d in deploy_group if d.cloud_id]))
            if len(suggested_cloud_ids) > 1:
                raise Exception("Two deployments that have to be launched in the same cloud provider "
                                "are asked to be deployed in different cloud providers: %s" % deploy_group)
            elif len(suggested_cloud_ids) == 1:
                if suggested_cloud_ids[0] not in cloud_list:
                    InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + ": Cloud Provider list:")
                    InfrastructureManager.logger.debug(cloud_list)
                    raise Exception("No auth data for cloud with ID: %s" % suggested_cloud_ids[0])
                else:
                    cloud_list0 = [
                        (suggested_cloud_ids[0], cloud_list[suggested_cloud_ids[0]])]
            else:
                cloud_list0 = cloud_list.items()

            scored_clouds = []
            for cloud_id, _ in cloud_list0:
                total = 0
                for d in deploy_group:
                    if d.vm_number:
                        total += d.vm_number * concrete_systems[cloud_id][d.id][1]
                    else:
                        total += 1
                scored_clouds.append((cloud_id, total))

            # Order the clouds first by the score and then using the cloud
            # order in the auth data
            sorted_scored_clouds = sorted(scored_clouds,
                                          key=lambda x: (x[1], ordered_cloud_list.index(x[0])),
                                          reverse=True)
            deploys_group_cloud_list[id(deploy_group)] = [c[0] for c in sorted_scored_clouds]

        # Launch every group in the same cloud provider
        deployed_vm = {}
        cancel_deployment = []
        try:
            if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
                pool = ThreadPool(processes=Config.MAX_SIMULTANEOUS_LAUNCHES)
                pool.map(
                    lambda ds: InfrastructureManager._launch_group(sel_inf, ds, deploys_group_cloud_list[id(ds)],
                                                                   cloud_list, concrete_systems, radl, auth,
                                                                   deployed_vm, cancel_deployment), deploy_groups)
                pool.close()
            else:
                for ds in deploy_groups:
                    InfrastructureManager._launch_group(sel_inf, ds, deploys_group_cloud_list[id(ds)],
                                                        cloud_list, concrete_systems, radl,
                                                        auth, deployed_vm, cancel_deployment)
        except Exception as e:
            # Please, avoid exception to arrive to this level, because some virtual
            # machine may lost.
            cancel_deployment.append(e)

        # We make this to maintain the order of the VMs in the sel_inf.vm_list
        # according to the deploys shown in the RADL
        new_vms = []
        for orig_dep in radl.deploys:
            for deploy in deployed_vm.keys():
                if orig_dep.id == deploy.id:
                    for vm in deployed_vm.get(deploy, []):
                        if vm not in new_vms:
                            new_vms.append(vm)

        if cancel_deployment:
            # If error, all deployed virtual machine will be undeployed.
            for vm in new_vms:
                vm.finalize(True, auth)
            msg = ""
            for e in cancel_deployment:
                msg += str(e) + "\n"
            raise Exception("Some deploys did not proceed successfully: %s" % msg)

        # Remove the VMs in creating state
        sel_inf.remove_creating_vms()

        for vm in new_vms:
            # Set now the VM as "created"
            vm.creating = False
            # and add it to the Inf
            sel_inf.add_vm(vm)

            (_, passwd, _, _) = vm.info.systems[0].getCredentialValues()
            (_, new_passwd, _, _) = vm.info.systems[0].getCredentialValues(new=True)
            if passwd and not new_passwd:
                # The VM uses the VMI password, set to change it
                random_password = ''.join(random.choice(
                    string.ascii_letters + string.digits) for _ in range(8))
                vm.info.systems[0].setCredentialValues(
                    password=random_password, new=True)

        # Add the new virtual machines to the infrastructure
        sel_inf.update_radl(radl, [(d, deployed_vm[d], concrete_systems[d.cloud_id][d.id][0])
                                   for d in deployed_vm])
        InfrastructureManager.logger.info("VMs %s successfully added to Inf id %s" % (new_vms, sel_inf.id))

        # Let's contextualize!
        if context and new_vms:
            sel_inf.Contextualize(auth)

        IM.InfrastructureList.InfrastructureList.save_data(inf_id)

        return [vm.im_id for vm in new_vms]

    @staticmethod
    def RemoveResource(inf_id, vm_list, auth, context=True):
        """
        Remove a list of resources from the infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - vm_list(str, int or list of str): list of virtual machine ids.
        - auth(Authentication): parsed authentication tokens.
        - context(bool): Flag to specify if the ctxt step will be made

        Return(int): number of undeployed virtual machines.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Removing the VMs: " + str(vm_list) + " from inf ID: '" + str(inf_id) + "'")

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        if isinstance(vm_list, str):
            vm_ids = vm_list.split(",")
        elif isinstance(vm_list, int):
            vm_ids = [str(vm_list)]
        elif isinstance(vm_list, list):
            vm_ids = vm_list
        else:
            raise Exception(
                'Incorrect parameter type to RemoveResource function: expected: str, int or list of str.')

        cont = 0
        exceptions = []
        delete_list = [sel_inf.get_vm(vmid) for vmid in vm_ids]
        for vm in delete_list:
            if InfrastructureManager._delete_vm(vm, delete_list, auth, exceptions):
                cont += 1

        InfrastructureManager.logger.info("Inf ID: " + sel_inf.id + ": %d VMs successfully removed" % cont)

        if context and cont > 0:
            # Now test again if the infrastructure is contextualizing
            sel_inf.Contextualize(auth)

        IM.InfrastructureList.InfrastructureList.save_data(inf_id)

        if exceptions:
            InfrastructureManager.logger.exception("Inf ID: " + sel_inf.id + ": Error removing resources")
            raise Exception("Error removing resources: %s" % exceptions)

        return cont

    @staticmethod
    def GetVMProperty(inf_id, vm_id, property_name, auth):
        """
        Get a particular property about a virtual machine in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - property(str): RADL property to get.
        - auth(Authentication): parsed authentication tokens.

        Return: a str with the property value
        """
        auth = InfrastructureManager.check_auth_data(auth)

        radl = InfrastructureManager.GetVMInfo(inf_id, vm_id, auth)

        res = None
        if radl.systems:
            res = radl.systems[0].getValue(property_name)
        return res

    @staticmethod
    def GetVMInfo(inf_id, vm_id, auth, json_res=False):
        """
        Get information about a virtual machine in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - auth(Authentication): parsed authentication tokens.
        - json_res(bool): Flag to return the info in RADL JSON format

        Return: the RADL with the information about the VM or a str with the JSON data if json_res flag.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Get information about the vm: '" + str(vm_id) + "' from inf: " + str(inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)

        success = vm.update_status(auth)
        if not success:
            InfrastructureManager.logger.debug(
                "Inf ID: " + str(inf_id) + ": " +
                "Information not updated. Using last information retrieved")

        if json_res:
            return dump_radl_json(vm.get_vm_info())
        else:
            return vm.get_vm_info()

    @staticmethod
    def GetVMContMsg(inf_id, vm_id, auth):
        """
        Get the contextualization log of a virtual machine in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - auth(Authentication): parsed authentication tokens.

        Return: a str with the contextualization log of the VM
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Get contextualization log of the vm: '" + str(vm_id) + "' from inf: " + str(inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)

        cont_msg = vm.get_cont_msg()
        InfrastructureManager.logger.debug(cont_msg)

        return cont_msg

    @staticmethod
    def AlterVM(inf_id, vm_id, radl_data, auth):
        """
        Get information about a virtual machine in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - radl(str): RADL description.
        - auth(Authentication): parsed authentication tokens.

        Return: a str with the information about the VM
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Modifying the VM: '" + str(vm_id) + "' from inf: " + str(inf_id))
        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)
        if not vm:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "VM does not exist or Access Error")
            raise Exception("VM does not exist or Access Error")

        if isinstance(radl_data, RADL):
            radl = radl_data
        else:
            radl = radl_parse.parse_radl(radl_data)

        exception = None
        try:
            (success, alter_res) = vm.alter(radl, auth)
        except Exception as e:
            exception = e

        if exception:
            raise exception
        if not success:
            InfrastructureManager.logger.warn(
                "Inf ID: " + str(inf_id) + ": " +
                "Error modifying the information about the VM " + str(vm_id) + ": " + str(alter_res))

        vm.update_status(auth)
        IM.InfrastructureList.InfrastructureList.save_data(inf_id)

        return vm.info

    @staticmethod
    def GetInfrastructureRADL(inf_id, auth):
        """
        Get the original RADL of an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.

        Return: str with the RADL
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Getting RADL of the inf: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        radl = str(sel_inf.get_radl())
        InfrastructureManager.logger.debug(radl)
        return radl

    @staticmethod
    def GetInfrastructureInfo(inf_id, auth):
        """
        Get information about an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.

        Return: a list of str: list of virtual machine ids.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Getting information about the inf: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        res = [str(vm.im_id) for vm in sel_inf.get_vm_list()]

        InfrastructureManager.logger.debug(res)
        return res

    @staticmethod
    def GetInfrastructureContMsg(inf_id, auth, headeronly=False):
        """
        Get cont msg of an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.
        - headeronly(bool): Flag to return only the header part of the infra log.

        Return: a str with the cont msg
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Getting cont msg of the inf: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        res = sel_inf.cont_out

        if not headeronly:
            for vm in sel_inf.get_vm_list():
                if vm.get_cont_msg():
                    res += "VM " + str(vm.id) + ":\n" + vm.get_cont_msg() + "\n"
                    res += "***************************************************************************\n"

        InfrastructureManager.logger.debug(res)
        return res

    @staticmethod
    def GetInfrastructureState(inf_id, auth):
        """
        Get the aggregated state of an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.

        Return: a dict with two elements:
            - 'state': str with the aggregated state of the infrastructure
            - 'vm_states': a dict indexed with the id of the VM and its state as value
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Getting state of the inf: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        vm_states = {}
        for vm in sel_inf.get_vm_list():
            # First try to update the status of the VM
            vm.update_status(auth)
            vm_states[str(vm.im_id)] = vm.state

        state = None
        for vm in sel_inf.get_vm_list():
            # First try to update the status of the VM
            if vm.state == VirtualMachine.FAILED:
                state = VirtualMachine.FAILED
                break
            elif vm.state == VirtualMachine.UNKNOWN:
                state = VirtualMachine.UNKNOWN
                break
            elif vm.state == VirtualMachine.PENDING:
                state = VirtualMachine.PENDING
            elif vm.state == VirtualMachine.RUNNING:
                if state != VirtualMachine.PENDING:
                    state = VirtualMachine.RUNNING
            elif vm.state == VirtualMachine.STOPPED:
                if state is None:
                    state = VirtualMachine.STOPPED
            elif vm.state == VirtualMachine.OFF:
                if state is None:
                    state = VirtualMachine.OFF
            elif vm.state == VirtualMachine.CONFIGURED:
                if state is None:
                    state = VirtualMachine.CONFIGURED
            elif vm.state == VirtualMachine.UNCONFIGURED:
                if state is None or state == VirtualMachine.CONFIGURED:
                    state = VirtualMachine.UNCONFIGURED

        if state is None:
            state = VirtualMachine.UNKNOWN

        InfrastructureManager.logger.info(
            "inf: " + str(inf_id) + " is in state: " + state)
        return {'state': state, 'vm_states': vm_states}

    @staticmethod
    def _stop_vm(vm, auth, exceptions):
        try:
            success = False
            InfrastructureManager.logger.info("Stopping the VM id: " + vm.id)
            (success, msg) = vm.stop(auth)
        except Exception as e:
            msg = str(e)
        if not success:
            InfrastructureManager.logger.info("The VM cannot be stopped")
            exceptions.append(msg)

    @staticmethod
    def StopInfrastructure(inf_id, auth):
        """
        Stop all virtual machines in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.

        Return(str): error messages; empty string means all was ok.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Stopping the infrastructure id: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        exceptions = []
        if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
            pool = ThreadPool(processes=Config.MAX_SIMULTANEOUS_LAUNCHES)
            pool.map(
                lambda vm: InfrastructureManager._stop_vm(
                    vm, auth, exceptions),
                reversed(sel_inf.get_vm_list())
            )
            pool.close()
        else:
            for vm in sel_inf.get_vm_list():
                InfrastructureManager._stop_vm(vm, auth, exceptions)

        if exceptions:
            msg = ""
            for e in exceptions:
                msg += str(e) + "\n"
            raise Exception("Error stopping the infrastructure: %s" % msg)

        InfrastructureManager.logger.info("Inf ID: " + sel_inf.id + ": Successfully stopped")
        return ""

    @staticmethod
    def _start_vm(vm, auth, exceptions):
        try:
            success = False
            InfrastructureManager.logger.info("Starting the VM id: " + vm.id)
            (success, msg) = vm.start(auth)
        except Exception as e:
            msg = str(e)
        if not success:
            InfrastructureManager.logger.info("The VM cannot be restarted")
            exceptions.append(msg)

    @staticmethod
    def StartInfrastructure(inf_id, auth):
        """
        Start all virtual machines in an infrastructure previously stopped.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.

        Return(str): error messages; empty string means all was ok.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Starting the infrastructure id: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        exceptions = []
        if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
            pool = ThreadPool(processes=Config.MAX_SIMULTANEOUS_LAUNCHES)
            pool.map(
                lambda vm: InfrastructureManager._start_vm(
                    vm, auth, exceptions),
                reversed(sel_inf.get_vm_list())
            )
            pool.close()
        else:
            for vm in sel_inf.get_vm_list():
                InfrastructureManager._start_vm(vm, auth, exceptions)

        if exceptions:
            msg = ""
            for e in exceptions:
                msg += str(e) + "\n"
            raise Exception("Error starting the infrastructure: %s" % msg)

        InfrastructureManager.logger.info("Inf ID: " + sel_inf.id + ": Successfully restarted")
        return ""

    @staticmethod
    def StartVM(inf_id, vm_id, auth):
        """
        Start the specified virtual machine in an infrastructure previously stopped.

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - auth(Authentication): parsed authentication tokens.

        Return(str): error messages; empty string means all was ok.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Starting the VM id %s from the infrastructure id: %s" % (vm_id, inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)
        success = False
        try:
            (success, msg) = vm.start(auth)
        except Exception as e:
            msg = str(e)

        if not success:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "The VM %s cannot be restarted: %s" % (vm_id, msg))
            raise Exception("Error starting the VM: %s" % msg)
        else:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "The VM %s successfully restarted" % vm_id)
            return ""

    @staticmethod
    def StopVM(inf_id, vm_id, auth):
        """
        Stop the specified virtual machine in an infrastructure

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - auth(Authentication): parsed authentication tokens.

        Return(str): error messages; empty string means all was ok.
        """
        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Stopping the VM id %s from the infrastructure id: %s" % (vm_id, inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)
        success = False
        try:
            (success, msg) = vm.stop(auth)
        except Exception as e:
            msg = str(e)

        if not success:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "The VM %s cannot be stopped: %s" % (vm_id, msg))
            raise Exception("Error stopping the VM: %s" % msg)
        else:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "The VM %s successfully stopped" % vm_id)
            return ""

    @staticmethod
    def is_last_in_cloud(vm, delete_list, remain_vms):
        """
        Check if this VM is the last in the cloud provider
        to send the correct flag to the finalize function to clean
        resources correctly
        """
        for v in remain_vms:
            if v.cloud.type == vm.cloud.type and v.cloud.server == vm.cloud.server:
                # There are at least one VM in the same cloud
                # that will remain. This is not the last one
                return False

        # Get the list of VMs on the same cloud to be deleted
        delete_list_cloud = [v for v in delete_list if (v.cloud.type == vm.cloud.type and
                                                        v.cloud.server == vm.cloud.server)]

        # And return true in the last of these VMs
        return vm == delete_list_cloud[-1]

    @staticmethod
    def _delete_vm(vm, delete_list, auth, exceptions):
        # Select the last in the list to delete
        remain_vms = [v for v in vm.inf.get_vm_list() if v not in delete_list]
        last = InfrastructureManager.is_last_in_cloud(vm, delete_list, remain_vms)
        success = False
        try:
            InfrastructureManager.logger.info("Finalizing the VM id: " + str(vm.id))
            (success, msg) = vm.finalize(last, auth)
        except Exception as e:
            msg = str(e)
        if not success:
            InfrastructureManager.logger.info("The VM cannot be finalized: %s" % msg)
            exceptions.append(msg)
        return success

    @staticmethod
    def DestroyInfrastructure(inf_id, auth):
        """
        Destroy all virtual machines in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.

        Return: None.
        """
        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Destroying the infrastructure id: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        exceptions = []
        delete_list = list(reversed(sel_inf.get_vm_list()))

        if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
            pool = ThreadPool(processes=Config.MAX_SIMULTANEOUS_LAUNCHES)
            pool.map(
                lambda vm: InfrastructureManager._delete_vm(vm, delete_list, auth, exceptions),
                delete_list
            )
            pool.close()
        else:
            # If IM server is the first VM, then it will be the last destroyed
            for vm in delete_list:
                InfrastructureManager._delete_vm(vm, delete_list, auth, exceptions)

        if exceptions:
            IM.InfrastructureList.InfrastructureList.save_data(inf_id)
            msg = ""
            for e in exceptions:
                msg += str(e) + "\n"
            raise Exception("Error destroying the infrastructure: \n%s" % msg)

        # Set the Infrastructure as deleted
        sel_inf.delete()
        IM.InfrastructureList.InfrastructureList.save_data(inf_id)
        IM.InfrastructureList.InfrastructureList.remove_inf(sel_inf)
        InfrastructureManager.logger.info("Infrastructure %s successfully destroyed" % inf_id)
        return ""

    @staticmethod
    def check_im_user(auth):
        """
        Check if the IM user is valid

        Args:
        - auth(Authentication): IM parsed authentication tokens.

        Return(bool): true if the user is valid or false otherwise.
        """
        if Config.USER_DB:
            if os.path.isfile(Config.USER_DB):
                try:
                    found = False
                    user_db = json.load(open(Config.USER_DB, "r"))
                    for user in user_db['users']:
                        if user['username'] == auth[0]['username'] and user['password'] == auth[0]['password']:
                            found = True
                            break
                    return found
                except Exception:
                    InfrastructureManager.logger.exception(
                        "Incorrect format in the User DB file %s" % Config.USER_DB)
                    return False
            else:
                InfrastructureManager.logger.error(
                    "User DB file %s not found" % Config.USER_DB)
                return False
        else:
            return True

    @staticmethod
    def check_auth_data(auth):
        # First check if it is configured to check the users from a list
        im_auth = auth.getAuthInfo("InfrastructureManager")

        if not im_auth:
            raise IncorrectVMCrecentialsException("No credentials provided for the InfrastructureManager.")

        # if not assume the basic user/password auth data
        if not InfrastructureManager.check_im_user(im_auth):
            raise InvaliddUserException()

        # We have to check if TTS is needed for other auth item
        return auth

    @staticmethod
    def CreateInfrastructure(radl, auth):
        """
        Create a new infrastructure.

        IM creates an infrastructure based on the RADL description and associated it to
        the first valid IM user in the authentication tokens.

        Args:

        - radl(RADL): RADL description.
        - auth(Authentication): parsed authentication tokens.

        Return(int): the new infrastructure ID if successful.
        """

        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        # Create a new infrastructure
        inf = IM.InfrastructureInfo.InfrastructureInfo()
        inf.auth = Authentication(auth.getAuthInfo("InfrastructureManager"))
        IM.InfrastructureList.InfrastructureList.add_infrastructure(inf)
        IM.InfrastructureList.InfrastructureList.save_data(inf.id)
        InfrastructureManager.logger.info(
            "Creating new infrastructure with id: " + str(inf.id))

        # Add the resources in radl_data
        try:
            InfrastructureManager.AddResource(inf.id, radl, auth)
        except Exception as e:
            InfrastructureManager.logger.exception(
                "Error Creating Inf id " + str(inf.id))
            inf.delete()
            IM.InfrastructureList.InfrastructureList.save_data(inf.id)
            IM.InfrastructureList.InfrastructureList.remove_inf(inf)
            raise e
        InfrastructureManager.logger.info(
            "Infrastructure id " + str(inf.id) + " successfully created")

        return inf.id

    @staticmethod
    def GetInfrastructureList(auth):
        """
        Return the infrastructure ids associated to IM tokens.

        Args:

        - auth(Authentication): parsed authentication tokens.

        Return(list of int): list of infrastructure ids.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Listing the user infrastructures")

        auths = auth.getAuthInfo('InfrastructureManager')
        if not auths:
            InfrastructureManager.logger.error(
                "No correct auth data has been specified.")
            raise InvaliddUserException()

        return IM.InfrastructureList.InfrastructureList.get_inf_ids(auth)

    @staticmethod
    def ExportInfrastructure(inf_id, delete, auth_data):
        auth = Authentication(auth_data)
        auth = InfrastructureManager.check_auth_data(auth)

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        str_inf = sel_inf.serialize()
        InfrastructureManager.logger.info("Exporting infrastructure id: " + str(sel_inf.id))
        if delete:
            sel_inf.delete()
            IM.InfrastructureList.InfrastructureList.save_data(sel_inf.id)
            IM.InfrastructureList.InfrastructureList.remove_inf(sel_inf)
        return str_inf

    @staticmethod
    def ImportInfrastructure(str_inf, auth_data):
        auth = Authentication(auth_data)
        auth = InfrastructureManager.check_auth_data(auth)

        try:
            new_inf = IM.InfrastructureInfo.InfrastructureInfo.deserialize(str_inf)
        except Exception as ex:
            InfrastructureManager.logger.exception("Error importing the infrastructure, incorrect data")
            raise Exception("Error importing the infrastructure, incorrect data: " + str(ex))

        new_inf.auth = Authentication(auth.getAuthInfo("InfrastructureManager"))

        IM.InfrastructureList.InfrastructureList.add_infrastructure(new_inf)
        InfrastructureManager.logger.info(
            "Importing new infrastructure with id: " + str(new_inf.id))
        # Save the state
        IM.InfrastructureList.InfrastructureList.save_data(new_inf.id)
        return new_inf.id

    @staticmethod
    def CreateDiskSnapshot(inf_id, vm_id, disk_num, image_name, auto_delete, auth):
        """
        Create a snapshot of the specified num disk in a
        virtual machine in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - image_name(str): A name to set to the image
        - disk_num(int): Number of the disk.
        - auto_delete(bool): A flag to specify that the snapshot will be deleted when the
          infrastructure is destroyed.
        - auth(Authentication): parsed authentication tokens.

        Return: a str with url of the saved snapshot.
        """
        auth = InfrastructureManager.check_auth_data(auth)
        InfrastructureManager.logger.info("Creating a snapshot of VM id: %s Inf id: %s" % (vm_id, inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)

        success, image_url = vm.create_snapshot(disk_num, image_name, auto_delete, auth)
        if not success:
            InfrastructureManager.logger.error("Error creating snapshot: %s" % image_url)
            raise Exception("Error creating snapshot: %s" % image_url)
        else:
            return image_url

    @staticmethod
    def stop():
        IM.InfrastructureList.InfrastructureList.stop()
