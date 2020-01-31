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

import re
import yaml
import json
import os
import string
import random
import logging
import threading

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

from IM.openid.JWT import JWT
from IM.openid.OpenIDClient import OpenIDClient


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
        self.message = msg


class IncorrectInfrastructureException(Exception):
    """ Invalid infrastructure ID or access not granted. """

    def __init__(self, msg="Invalid infrastructure ID or access not granted."):
        Exception.__init__(self, msg)
        self.message = msg


class DeletedInfrastructureException(Exception):
    """ Deleted infrastructure. """

    def __init__(self, msg="Deleted infrastructure."):
        Exception.__init__(self, msg)
        self.message = msg


class InvaliddUserException(Exception):
    """ Invalid InfrastructureManager credentials """

    def __init__(self, msg="Invalid InfrastructureManager credentials"):
        Exception.__init__(self, msg)
        self.message = msg


class IncorrectVMCrecentialsException(Exception):
    """ Invalid InfrastructureManager credentials """

    def __init__(self, msg="Incorrect VM credentials"):
        Exception.__init__(self, msg)
        self.message = msg


class DisabledFunctionException(Exception):
    """ Disabled function called"""

    def __init__(self, msg="Function currently disabled."):
        Exception.__init__(self, msg)
        self.message = msg


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
    def _launch_deploy(sel_inf, deploy, cloud_id, cloud, concrete_systems, radl, auth, deployed_vm):
        """Launch a deploy."""

        if deploy.vm_number <= 0:
            InfrastructureManager.logger.warning(
                "Inf ID: %s: deploy %s with 0 num: Ignoring." % (sel_inf.id, deploy.id))
            return

        if not deploy.id.startswith(IM.InfrastructureInfo.InfrastructureInfo.FAKE_SYSTEM):
            concrete_system = concrete_systems[cloud_id][deploy.id][0]
            launched_vms = []
            launch_radl = radl.clone()
            requested_radl = radl.clone()
            requested_radl.systems = [radl.get_system_by_name(deploy.id)]
            if not concrete_system:
                InfrastructureManager.logger.error("Inf ID: " + str(sel_inf.id) +
                                                   ". Error, no concrete system to deploy: " +
                                                   deploy.id + " in cloud: " + cloud_id +
                                                   ". Check if a correct image is being used")
                for _ in range(deploy.vm_number):
                    launched_vms.append((False, "Error, no concrete system to deploy: " + deploy.id +
                                         " in cloud: " + cloud_id + ". Check if a correct image is being used"))
            else:
                launch_radl = radl.clone()
                launch_radl.systems = [concrete_system.clone()]
                requested_radl = radl.clone()
                requested_radl.systems = [radl.get_system_by_name(concrete_system.name)]

                (username, _, _, _) = concrete_system.getCredentialValues()
                if not username:
                    for _ in range(deploy.vm_number):
                        launched_vms.append((False, "No username for deploy: " + deploy.id))
                else:
                    InfrastructureManager.logger.debug("Inf ID: %s. Launching %d VMs of type %s" %
                                                       (sel_inf.id, deploy.vm_number, concrete_system.name))
                    launched_vms = cloud.cloud.getCloudConnector(sel_inf).launch_with_retry(
                        sel_inf, launch_radl, requested_radl, deploy.vm_number, auth, Config.MAX_VM_FAILS,
                        Config.DELAY_BETWEEN_VM_RETRIES)

            # this must never happen ...
            if len(launched_vms) < deploy.vm_number:
                for _ in range(deploy.vm_number - len(launched_vms)):
                    launched_vms.append((False, "Error in deploy: " + deploy.id))

            for success, launched_vm in launched_vms:
                if success:
                    InfrastructureManager.logger.debug("Inf ID: %s. VM successfully launched: %s" % (sel_inf.id,
                                                                                                     launched_vm.id))
                    deployed_vm.setdefault(deploy, []).append(launched_vm)
                    deploy.cloud_id = cloud_id
                else:
                    InfrastructureManager.logger.error("Inf ID: %s. Error launching some of the "
                                                       "VMs: %s" % (sel_inf.id, launched_vm))
                    vm = VirtualMachine(sel_inf, None, cloud.cloud, launch_radl, requested_radl)
                    vm.state = VirtualMachine.FAILED
                    vm.info.systems[0].setValue('state', VirtualMachine.FAILED)
                    vm.error_msg = "Error launching the VMs of type %s to cloud ID %s of type %s. %s" % (
                        deploy.id, cloud.cloud.id, cloud.cloud.type, launched_vm)
                    sel_inf.add_vm(vm)
                    deployed_vm.setdefault(deploy, []).append(vm)
                    deploy.cloud_id = cloud_id

    @staticmethod
    def get_infrastructure(inf_id, auth):
        """Return infrastructure info with some id if valid authorization provided."""

        if inf_id not in IM.InfrastructureList.InfrastructureList.get_inf_ids():
            InfrastructureManager.logger.error("Error, incorrect Inf ID: %s" % inf_id)
            raise IncorrectInfrastructureException()
        sel_inf = IM.InfrastructureList.InfrastructureList.get_infrastructure(inf_id)
        if not sel_inf:
            InfrastructureManager.logger.error("Error loading Inf ID: %s" % inf_id)
            raise IncorrectInfrastructureException("Error loading Inf ID data.")
        if not sel_inf.is_authorized(auth):
            InfrastructureManager.logger.error("Access Error to Inf ID: %s" % inf_id)
            raise UnauthorizedUserException()
        if sel_inf.deleted:
            InfrastructureManager.logger.error("Inf ID: %s is deleted." % inf_id)
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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Reconfiguring the Inf ID: " + str(inf_id))
        if isinstance(radl_data, RADL):
            radl = radl_data
        else:
            radl = radl_parse.parse_radl(radl_data)
        InfrastructureManager.logger.debug("Inf ID: " + str(inf_id) + ": \n" + str(radl))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        # Update infrastructure RADL with this new RADL
        # Add or update configures
        for s in radl.configures:
            # first check that the YAML is correct
            try:
                yaml.safe_load(s.recipes)
            except Exception as ex:
                raise Exception("Error parsing YAML: %s" % str(ex))
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

                # The user has new applications
                curr_apps = system.getValue("disk.0.applications")
                curr_apps_names = {}
                if curr_apps:
                    for app_name in curr_apps.keys():
                        orig_app_name = app_name
                        if "," in app_name:
                            # remove version substring
                            pos = app_name.find(",")
                            app_name = app_name[:pos]
                        curr_apps_names[app_name] = orig_app_name

                new_apps = new_system.getValue("disk.0.applications")
                if new_apps:
                    for app_name, app in new_apps.items():
                        orig_app_name = app_name
                        if "," in app_name:
                            # remove version substring
                            pos = app_name.find(",")
                            app_name = app_name[:pos]
                        if app_name in list(curr_apps_names.keys()):
                            del curr_apps[curr_apps_names[app_name]]
                        curr_apps[orig_app_name] = app

        # Stick all virtual machines to be reconfigured
        InfrastructureManager.logger.info("Contextualize the Inf ID: " + sel_inf.id)
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
    def systems_with_vmrc(sel_inf, radl, auth):
        """
        Concrete systems using VMRC
        NOTE: consider not-fake deploys (vm_number > 0)
        """
        # Get VMRC credentials
        vmrc_list = []
        for vmrc_elem in auth.getAuthInfo('VMRC'):
            if 'host' in vmrc_elem and 'username' in vmrc_elem and 'password' in vmrc_elem:
                vmrc_list.append(VMRC(vmrc_elem['host'], vmrc_elem['username'], vmrc_elem['password']))

        systems_with_vmrc = {}
        for system_id in set([d.id for d in radl.deploys if d.vm_number > 0]):
            s = radl.get_system_by_name(system_id)

            if not s.getValue("disk.0.image.url") and len(vmrc_list) == 0:
                raise Exception("No correct VMRC auth data provided nor image URL")

            if Config.SINGLE_SITE:
                image_id = os.path.basename(s.getValue("disk.0.image.url"))
                url_prefix = Config.SINGLE_SITE_IMAGE_URL_PREFIX
                if not url_prefix.endswith("/"):
                    url_prefix = url_prefix + "/"
                s.setValue("disk.0.image.url", url_prefix + image_id)

            # Remove the requested apps from the system
            s_without_apps = radl.get_system_by_name(system_id).clone()
            s_without_apps.delValue("disk.0.applications")

            # Set the default values for cpu, memory
            defaults = (Feature("cpu.count", ">=", Config.DEFAULT_VM_CPUS),
                        Feature("memory.size", ">=", Config.DEFAULT_VM_MEMORY, Config.DEFAULT_VM_MEMORY_UNIT),
                        Feature("cpu.arch", "=", Config.DEFAULT_VM_CPU_ARCH))
            for f in defaults:
                if not s_without_apps.hasFeature(f.prop, check_softs=True):
                    s_without_apps.addFeature(f)

            vmrc_res = [s0 for vmrc in vmrc_list for s0 in vmrc.search_vm(s)]
            # Check that now the image URL is in the RADL
            if not s.getValue("disk.0.image.url") and not vmrc_res:
                sel_inf.add_cont_msg("No VMI obtained from VMRC to system: " + system_id)
                raise Exception("No VMI obtained from VMRC to system: " + system_id)

            n = [s_without_apps.clone().applyFeatures(s0, conflict="other", missing="other")
                 for s0 in vmrc_res]
            systems_with_vmrc[system_id] = n if n else [s_without_apps]

        return systems_with_vmrc

    @staticmethod
    def sort_by_score(sel_inf, concrete_systems, cloud_list, deploy_groups, auth):
        """
        Sort by score the cloud providers
        NOTE: consider fake deploys (vm_number == 0)
        """
        deploys_group_cloud = {}

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
                    InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + " - " + str(cloud_list))
                    raise Exception("No auth data for cloud with ID: %s" % suggested_cloud_ids[0])
                else:
                    cloud_list0 = [(suggested_cloud_ids[0], cloud_list[suggested_cloud_ids[0]])]
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
            if sorted_scored_clouds and sorted_scored_clouds[0]:
                deploys_group_cloud[id(deploy_group)] = sorted_scored_clouds[0][0]
            else:
                sel_inf.configured = False
                sel_inf.add_cont_msg("No cloud provider available")
                raise Exception("No cloud provider available")

        return deploys_group_cloud

    @staticmethod
    def AddResource(inf_id, radl_data, auth, context=True):
        """
        Add the resources in the RADL to the infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - radl(str): RADL description.
        - auth(Authentication): parsed authentication tokens.
        - context(bool): Flag to specify if the ctxt step will be made

        Return(list of int): ids of the new virtual machine created.
        """
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Adding resources to Inf ID: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        try:
            if isinstance(radl_data, RADL):
                radl = radl_data
            else:
                radl = radl_parse.parse_radl(radl_data)

            InfrastructureManager.logger.debug("Inf ID: " + str(inf_id) + ": \n" + str(radl))
            radl.check()

            # Update infrastructure RADL with this new RADL
            sel_inf.complete_radl(radl)
            sel_inf.update_radl(radl, [])

            # If any deploy is defined, only update definitions.
            if not radl.deploys:
                InfrastructureManager.logger.warn("Inf ID: " + sel_inf.id + ": without any deploy. Exiting.")
                sel_inf.add_cont_msg("Infrastructure without any deploy. Exiting.")
                if sel_inf.configured is None:
                    sel_inf.configured = False
                return []
        except Exception as ex:
            sel_inf.configured = False
            sel_inf.add_cont_msg("Error parsing RADL: %s" % str(ex))
            InfrastructureManager.logger.exception("Inf ID: " + sel_inf.id + " error parsing RADL")
            raise ex

        for system in radl.systems:
            # Add apps requirements to the RADL
            apps_to_install = system.getApplications()
            for app_to_install in apps_to_install:
                for app_avail, _, _, _, requirements in Recipe.getInstallableApps():
                    if requirements and app_avail.isNewerThan(app_to_install):
                        # This app must be installed and it has special
                        # requirements
                        try:
                            requirements_radl = radl_parse.parse_radl(requirements).systems[0]
                            system.applyFeatures(requirements_radl, conflict="other", missing="other")
                        except Exception:
                            InfrastructureManager.logger.exception(
                                "Inf ID: " + sel_inf.id + ": Error in the requirements of the app: " +
                                app_to_install.getValue("name") + ". Ignore them.")
                            InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + ": " + str(requirements))
                        break

        # Concrete systems using VMRC
        try:
            systems_with_vmrc = InfrastructureManager.systems_with_vmrc(sel_inf, radl, auth)
        except Exception as ex:
            sel_inf.configured = False
            sel_inf.add_cont_msg("Error getting VM images: %s" % str(ex))
            InfrastructureManager.logger.exception("Inf ID: " + sel_inf.id + " error getting VM images")
            raise ex

        # Concrete systems with cloud providers and select systems with the greatest score
        # in every cloud
        cloud_list = dict([(c.id, c.getCloudConnector(sel_inf)) for c in CloudInfo.get_cloud_list(auth)])
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
        InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + "\n" + str(deploy_groups))

        # Sort by score the cloud providers
        deploys_group_cloud = InfrastructureManager.sort_by_score(sel_inf, concrete_systems, cloud_list,
                                                                  deploy_groups, auth)

        # We are going to start adding resources
        sel_inf.set_adding()

        # Launch every group in the same cloud provider
        deployed_vm = {}
        for deploy_group in deploy_groups:
            if not deploy_group:
                InfrastructureManager.logger.warning("Inf ID: %s: No VMs to deploy!" % sel_inf.id)
                sel_inf.add_cont_msg("No VMs to deploy. Exiting.")
                if sel_inf.configured is None:
                    sel_inf.configured = False
                return []

            cloud_id = deploys_group_cloud[id(deploy_group)]
            cloud = cloud_list[cloud_id]
            if Config.MAX_SIMULTANEOUS_LAUNCHES > 1:
                pool = ThreadPool(processes=Config.MAX_SIMULTANEOUS_LAUNCHES)
                pool.map(
                    lambda deploy: InfrastructureManager._launch_deploy(sel_inf, deploy, cloud_id,
                                                                        cloud, concrete_systems, radl, auth,
                                                                        deployed_vm),
                    deploy_group)
                pool.close()
            else:
                for deploy in deploy_group:
                    InfrastructureManager._launch_deploy(sel_inf, deploy, cloud_id,
                                                         cloud, concrete_systems, radl,
                                                         auth, deployed_vm)

        # We make this to maintain the order of the VMs in the sel_inf.vm_list
        # according to the deploys shown in the RADL
        new_vms = []
        for orig_dep in radl.deploys:
            for deploy in deployed_vm.keys():
                if orig_dep.id == deploy.id:
                    for vm in deployed_vm.get(deploy, []):
                        if vm not in new_vms:
                            new_vms.append(vm)

        # Remove the VMs in creating state
        sel_inf.remove_creating_vms()

        all_failed = True
        for vm in new_vms:
            # Set now the VM as "created"
            vm.creating = False
            # and add it to the Inf
            sel_inf.add_vm(vm)

            if vm.state != VirtualMachine.FAILED:
                all_failed = False

                (_, passwd, _, _) = vm.info.systems[0].getCredentialValues()
                (_, new_passwd, _, _) = vm.info.systems[0].getCredentialValues(new=True)
                if passwd and not new_passwd:
                    # The VM uses the VMI password, set to change it
                    random_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                    vm.info.systems[0].setCredentialValues(password=random_password, new=True)

        error_msg = ""
        # Add the new virtual machines to the infrastructure
        sel_inf.update_radl(radl,
                            [(d, deployed_vm[d], concrete_systems[d.cloud_id][d.id][0]) for d in deployed_vm],
                            False)
        if all_failed:
            InfrastructureManager.logger.error("VMs failed when adding to Inf ID: %s" % sel_inf.id)
            sel_inf.add_cont_msg("All VMs failed. No contextualize.")

            # in case of all VMs are failed delete it
            delete_list = list(reversed(sel_inf.get_vm_list()))
            for vm in new_vms:
                if vm.error_msg:
                    error_msg += "%s\n" % vm.error_msg
                vm.delete(delete_list, auth, [])
            sel_inf.add_cont_msg(error_msg)
        else:
            InfrastructureManager.logger.info("VMs %s successfully added to Inf ID: %s" % (new_vms, sel_inf.id))

        # The resources has been added
        sel_inf.set_adding(False)

        # Let's contextualize!
        if context and new_vms and not all_failed:
            sel_inf.Contextualize(auth)

        IM.InfrastructureList.InfrastructureList.save_data(inf_id)

        if all_failed and new_vms:
            # if there are no VMs, set it as unconfigured
            if not sel_inf.get_vm_list():
                sel_inf.configured = False
            raise Exception("Error adding VMs: %s" % error_msg)

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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Removing the VMs: " + str(vm_list) + " from Inf ID: '" + str(inf_id) + "'")

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
            if vm.delete(delete_list, auth, exceptions):
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
            "Get information about the vm: '" + str(vm_id) + "' from Inf ID: " + str(inf_id))

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
            "Get contextualization log of the vm: '" + str(vm_id) + "' from Inf ID: " + str(inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)

        cont_msg = vm.get_cont_msg()
        InfrastructureManager.logger.debug("Inf ID: " + str(inf_id) + ": " + cont_msg)

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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Modifying the VM: '" + str(vm_id) + "' from Inf ID: " + str(inf_id))
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

        (success, alter_res) = vm.alter(radl, auth)

        if not success:
            raise Exception("Error modifying the information about the VM %s: %s" % (vm_id, alter_res))

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

        InfrastructureManager.logger.info("Getting RADL of the Inf ID: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        radl = str(sel_inf.get_radl())
        InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + ": " + radl)
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

        InfrastructureManager.logger.info("Getting information about the Inf ID: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        res = [str(vm.im_id) for vm in sel_inf.get_vm_list()]

        InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + ": " + str(res))
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
            "Getting cont msg of the Inf ID: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        res = sel_inf.cont_out

        if not headeronly:
            for vm in sel_inf.get_vm_list():
                if vm.get_cont_msg():
                    res += "VM " + str(vm.im_id) + ":\n" + vm.get_cont_msg() + "\n"
                    res += "***************************************************************************\n"

        InfrastructureManager.logger.debug("Inf ID: " + sel_inf.id + ": " + res)
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

        InfrastructureManager.logger.info("Getting state of the Inf ID: " + str(inf_id))

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)

        vm_list = sel_inf.get_vm_list()
        vm_states = {}
        for vm in vm_list:
            # First try to update the status of the VM
            vm.update_status(auth)
            vm_states[str(vm.im_id)] = vm.state

        state = None
        for vm in vm_list:
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
            if sel_inf.configured is False:
                state = VirtualMachine.FAILED
            elif not vm_list and sel_inf.configured is None:
                # if there are no vms we probably are in the vm creation process
                state = VirtualMachine.PENDING
            else:
                state = VirtualMachine.UNKNOWN

        if sel_inf.deleting:
            state = VirtualMachine.DELETING

        InfrastructureManager.logger.info("Inf ID: " + str(inf_id) + " is in state: " + state)
        return {'state': state, 'vm_states': vm_states}

    @staticmethod
    def _stop_vm(vm, auth, exceptions):
        try:
            success = False
            InfrastructureManager.logger.info("Inf ID: " + vm.inf.id + ": Stopping the VM id: " + vm.id)
            (success, msg) = vm.stop(auth)
        except Exception as e:
            msg = str(e)
        if not success:
            InfrastructureManager.logger.info("Inf ID: " + vm.inf.id + ": The VM cannot be stopped")
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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Stopping the Inf ID: " + str(inf_id))

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
            InfrastructureManager.logger.info("Inf ID: " + vm.inf.id + ": Starting the VM id: " + vm.id)
            (success, msg) = vm.start(auth)
        except Exception as e:
            msg = str(e)
        if not success:
            InfrastructureManager.logger.info("Inf ID: " + vm.inf.id + ": The VM cannot be restarted")
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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Starting the Inf ID: " + str(inf_id))

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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Starting the VM id %s from the Inf ID: %s" % (vm_id, inf_id))

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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Stopping the VM id %s from the Inf ID: %s" % (vm_id, inf_id))

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
    def RebootVM(inf_id, vm_id, auth):
        """
        Reboot the specified virtual machine in an infrastructure

        Args:

        - inf_id(str): infrastructure id.
        - vm_id(str): virtual machine id.
        - auth(Authentication): parsed authentication tokens.

        Return(str): error messages; empty string means all was ok.
        """
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info(
            "Rebooting the VM id %s from the Inf ID: %s" % (vm_id, inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)
        success = False
        try:
            (success, msg) = vm.reboot(auth)
        except Exception as e:
            msg = str(e)

        if not success:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "The VM %s cannot be rebooted: %s" % (vm_id, msg))
            raise Exception("Error rebooting the VM: %s" % msg)
        else:
            InfrastructureManager.logger.info(
                "Inf ID: " + str(inf_id) + ": " +
                "The VM %s successfully rebooted" % vm_id)
            return ""

    @staticmethod
    def DestroyInfrastructure(inf_id, auth, force=False, async_call=False):
        """
        Destroy all virtual machines in an infrastructure.

        Args:

        - inf_id(str): infrastructure id.
        - auth(Authentication): parsed authentication tokens.
        - force(bool): delete the infra from the IM although not all resources are deleted.
        - async_call(bool): Destroy the inf in an async way.

        Return: None.
        """
        if Config.BOOT_MODE == 1:
            raise DisabledFunctionException()

        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        # First set this infra as "deleting"
        sel_inf.set_deleting()

        if async_call:
            t = threading.Thread(name="DestroyResource-%s" % sel_inf.id,
                                 target=sel_inf.destroy,
                                 args=(auth, force))
            t.daemon = True
            t.start()
        else:
            sel_inf.destroy(auth, force)
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
                    InfrastructureManager.logger.exception("Incorrect format in the User DB file %s" % Config.USER_DB)
                    return False
            else:
                InfrastructureManager.logger.error("User DB file %s not found" % Config.USER_DB)
                return False
        else:
            return True

    @staticmethod
    def check_oidc_token(im_auth):
        token = im_auth["token"]
        success = False
        try:
            # decode the token to get the info
            decoded_token = JWT().get_info(token)
        except Exception as ex:
            InfrastructureManager.logger.exception("Error trying decode OIDC auth token: %s" % str(ex))
            raise Exception("Error trying to decode OIDC auth token: %s" % str(ex))

        # First check if the issuer is in valid
        if decoded_token['iss'] not in Config.OIDC_ISSUERS:
            InfrastructureManager.logger.error("Incorrect OIDC issuer: %s" % decoded_token['iss'])
            raise InvaliddUserException("Invalid InfrastructureManager credentials. Issuer not accepted.")

        # Now check the audience
        if Config.OIDC_AUDIENCE:
            if 'aud' in decoded_token and decoded_token['aud']:
                found = False
                for aud in decoded_token['aud'].split(","):
                    if aud == Config.OIDC_AUDIENCE:
                        found = True
                        break
                if found:
                    InfrastructureManager.logger.debug("Audience %s successfully checked." % Config.OIDC_AUDIENCE)
                else:
                    InfrastructureManager.logger.error("Audience %s not found in access token." % Config.OIDC_AUDIENCE)
                    raise InvaliddUserException("Invalid InfrastructureManager credentials. Audience not accepted.")
            else:
                InfrastructureManager.logger.error("Audience %s not found in access token." % Config.OIDC_AUDIENCE)
                raise InvaliddUserException("Invalid InfrastructureManager credentials. Audience not accepted.")

        if Config.OIDC_SCOPES and Config.OIDC_CLIENT_ID and Config.OIDC_CLIENT_SECRET:
            success, res = OpenIDClient.get_token_introspection(token,
                                                                Config.OIDC_CLIENT_ID,
                                                                Config.OIDC_CLIENT_SECRET)
            if not success:
                raise InvaliddUserException("Invalid InfrastructureManager credentials. "
                                            "Invalid token or Client credentials.")
            else:
                if not res["scope"]:
                    raise InvaliddUserException("Invalid InfrastructureManager credentials. "
                                                "No scope obtained from introspection.")
                else:
                    scopes = res["scope"].split(" ")
                    if not all([elem in scopes for elem in Config.OIDC_SCOPES]):
                        raise InvaliddUserException("Invalid InfrastructureManager credentials. Scopes %s "
                                                    "not in introspection scopes: %s" % (" ".join(Config.OIDC_SCOPES),
                                                                                         res["scope"]))

        # Now check if the token is not expired
        expired, msg = OpenIDClient.is_access_token_expired(token)
        if expired:
            InfrastructureManager.logger.error("OIDC auth %s." % msg)
            raise InvaliddUserException("Invalid InfrastructureManager credentials. OIDC auth %s." % msg)

        try:
            # Now try to get user info
            success, userinfo = OpenIDClient.get_user_info_request(token)
            if success:
                # convert to username to use it in the rest of the IM
                im_auth['username'] = IM.InfrastructureInfo.InfrastructureInfo.OPENID_USER_PREFIX
                if userinfo.get("preferred_username"):
                    im_auth['username'] += str(userinfo.get("preferred_username"))
                elif userinfo.get("name"):
                    im_auth['username'] += str(userinfo.get("name"))
                else:
                    im_auth['username'] += str(userinfo.get("sub"))
                im_auth['password'] = str(decoded_token['iss']) + str(userinfo.get("sub"))
        except Exception as ex:
            InfrastructureManager.logger.exception("Error trying to validate OIDC auth token: %s" % str(ex))
            raise Exception("Error trying to validate OIDC auth token: %s" % str(ex))

        if not success:
            InfrastructureManager.logger.error("Incorrect OIDC auth token: %s" % userinfo)
            raise InvaliddUserException("Invalid InfrastructureManager credentials. %s." % userinfo)

    @staticmethod
    def check_auth_data(auth):
        # First check if it is configured to check the users from a list
        im_auth = auth.getAuthInfo("InfrastructureManager")

        if not im_auth:
            raise IncorrectVMCrecentialsException("No credentials provided for the InfrastructureManager.")

        if Config.FORCE_OIDC_AUTH and "token" not in im_auth[0]:
            raise IncorrectVMCrecentialsException("No token provided for the InfrastructureManager.")

        # First check if an OIDC token is included
        if "token" in im_auth[0]:
            InfrastructureManager.check_oidc_token(im_auth[0])
        elif "username" in im_auth[0]:
            if im_auth[0]['username'].startswith(IM.InfrastructureInfo.InfrastructureInfo.OPENID_USER_PREFIX):
                # This is a OpenID user do not enable to get data using user/pass creds
                raise IncorrectVMCrecentialsException("Invalid username used for the InfrastructureManager.")
        else:
            raise IncorrectVMCrecentialsException("No username nor token for the InfrastructureManager.")

        # Now check if the user is in authorized
        if not InfrastructureManager.check_im_user(im_auth):
            raise InvaliddUserException()

        if Config.SINGLE_SITE:
            vmrc_auth = auth.getAuthInfo("VMRC")
            single_site_auth = auth.getAuthInfo(Config.SINGLE_SITE_TYPE)

            single_site_auth[0]["host"] = Config.SINGLE_SITE_AUTH_HOST

            auth_list = []
            auth_list.extend(im_auth)
            auth_list.extend(vmrc_auth)
            auth_list.extend(single_site_auth)
            auth = Authentication(auth_list)

        # We have to check if TTS is needed for other auth item
        return auth

    @staticmethod
    def CreateInfrastructure(radl_data, auth, async_call=False):
        """
        Create a new infrastructure.

        IM creates an infrastructure based on the RADL description and associated it to
        the first valid IM user in the authentication tokens.

        Args:

        - radl_data(RADL): RADL description.
        - auth(Authentication): parsed authentication tokens.
        - async_call(bool): Create the inf in an async way.

        Return(int): the new infrastructure ID if successful.
        """
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        # First check the auth data
        auth = InfrastructureManager.check_auth_data(auth)

        # Then parse the RADL
        if isinstance(radl_data, RADL):
            radl = radl_data
        else:
            radl = radl_parse.parse_radl(radl_data)

        radl.check()

        # Create a new infrastructure
        inf = IM.InfrastructureInfo.InfrastructureInfo()
        inf.auth = Authentication(auth.getAuthInfo("InfrastructureManager"))
        IM.InfrastructureList.InfrastructureList.add_infrastructure(inf)
        IM.InfrastructureList.InfrastructureList.save_data(inf.id)
        InfrastructureManager.logger.info("Creating new Inf ID: " + str(inf.id))

        # Add the resources in radl_data
        try:
            if async_call:
                InfrastructureManager.logger.debug("Inf ID: " + str(inf.id) + " created Async.")
                t = threading.Thread(name="AddResource-%s" % inf.id,
                                     target=InfrastructureManager.AddResource,
                                     args=(inf.id, radl, auth))
                t.daemon = True
                t.start()
            else:
                # In case of sync call
                vms = InfrastructureManager.AddResource(inf.id, radl, auth)

                all_failed = False
                error_msg = ""
                for vmid in vms:
                    vm = inf.get_vm(vmid)
                    if vm.state == VirtualMachine.FAILED:
                        all_failed = True
                        if vm.error_msg:
                            error_msg += "%s\n" % vm.error_msg
                    else:
                        all_failed = False
                        break
                if all_failed:
                    # If all VMs has failed, destroy then inf and return the error
                    try:
                        inf.destroy(auth)
                    except Exception as de:
                        error_msg += "%s" % de
                    raise Exception(error_msg)
        except Exception as e:
            InfrastructureManager.logger.exception("Error Creating Inf ID " + str(inf.id))
            inf.delete()
            IM.InfrastructureList.InfrastructureList.save_data(inf.id)
            IM.InfrastructureList.InfrastructureList.remove_inf(inf)
            raise e

        InfrastructureManager.logger.info("Inf ID:" + str(inf.id) + ": Successfully created")

        return inf.id

    @staticmethod
    def GetInfrastructureList(auth, flt=None):
        """
        Return the infrastructure ids associated to IM tokens.

        Args:

        - auth(Authentication): parsed authentication tokens.
        - flt(string): string to filter the list of returned infrastructures.
                          A regex to be applied in the RADL or TOSCA of the infra.

        Return(list of int): list of infrastructure ids.
        """
        auth = InfrastructureManager.check_auth_data(auth)

        InfrastructureManager.logger.info("Listing the user infrastructures")

        auths = auth.getAuthInfo('InfrastructureManager')
        if not auths:
            InfrastructureManager.logger.error("No correct auth data has been specified.")
            raise InvaliddUserException()

        inf_ids = IM.InfrastructureList.InfrastructureList.get_inf_ids(auth)
        if flt:
            res = []
            for infid in inf_ids:
                inf = InfrastructureManager.get_infrastructure(infid, auth)
                radl = str(inf.get_radl())
                tosca = ""
                if "TOSCA" in inf.extra_info:
                    tosca = inf.extra_info["TOSCA"].serialize()

                if re.search(flt, radl) or re.search(flt, tosca):
                    res.append(infid)
        else:
            res = inf_ids
        return res

    @staticmethod
    def ExportInfrastructure(inf_id, delete, auth_data):
        if delete and Config.BOOT_MODE == 1:
            raise DisabledFunctionException()

        auth = Authentication(auth_data)
        auth = InfrastructureManager.check_auth_data(auth)

        sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
        str_inf = sel_inf.serialize()
        InfrastructureManager.logger.info("Exporting Inf ID: " + str(sel_inf.id))
        if delete:
            sel_inf.delete()
            IM.InfrastructureList.InfrastructureList.save_data(sel_inf.id)
            IM.InfrastructureList.InfrastructureList.remove_inf(sel_inf)
        return str_inf

    @staticmethod
    def ImportInfrastructure(str_inf, auth_data):
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = Authentication(auth_data)
        auth = InfrastructureManager.check_auth_data(auth)

        try:
            new_inf = IM.InfrastructureInfo.InfrastructureInfo.deserialize(str_inf)
        except Exception as ex:
            InfrastructureManager.logger.exception("Error importing the infrastructure, incorrect data")
            raise Exception("Error importing the infrastructure, incorrect data: " + str(ex))

        new_inf.auth = Authentication(auth.getAuthInfo("InfrastructureManager"))

        IM.InfrastructureList.InfrastructureList.add_infrastructure(new_inf)
        InfrastructureManager.logger.info("Importing new infrastructure with Inf ID: " + str(new_inf.id))
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
        if Config.BOOT_MODE in [1, 2]:
            raise DisabledFunctionException()

        auth = InfrastructureManager.check_auth_data(auth)
        InfrastructureManager.logger.info("Creating a snapshot of VM id: %s Inf ID: %s" % (vm_id, inf_id))

        vm = InfrastructureManager.get_vm_from_inf(inf_id, vm_id, auth)

        success, image_url = vm.create_snapshot(disk_num, image_name, auto_delete, auth)
        if not success:
            InfrastructureManager.logger.error("Error creating a snapshot: %s of VM id: %s "
                                               "Inf ID: %s" % (image_url, vm_id, inf_id))
            raise Exception("Error creating snapshot: %s" % image_url)
        else:
            return image_url

    @staticmethod
    def stop():
        IM.InfrastructureList.InfrastructureList.stop()
