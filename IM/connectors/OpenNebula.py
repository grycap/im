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

import defusedxml.xmlrpc
defusedxml.xmlrpc.monkey_patch()

try:
    from xmlrpclib import ServerProxy
except ImportError:
    from xmlrpc.client import ServerProxy

import os.path
import time
from distutils.version import LooseVersion
from IM.xmlobject import XMLObject
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.config import ConfigOpenNebula
from netaddr import IPNetwork, IPAddress
from IM.config import Config
from IM.tts.onetts import ONETTSClient

# Set of classes to parse the XML results of the ONE API


class NIC(XMLObject):
    values = ['BRIDGE', 'IP', 'MAC', 'NETWORK', 'VNID']


class OS(XMLObject):
    values = ['BOOT', 'ROOT']


class GRAPHICS(XMLObject):
    values = ['LISTEN', 'TYPE']


class DISK(XMLObject):
    values = ['CLONE', 'READONLY', 'SAVE', 'SOURCE', 'TARGET',
              'SIZE', 'DISK_ID', 'IMAGE_ID', 'IMAGE', 'FORMAT']
    numeric = ['SIZE', 'DISK_ID']


class TEMPLATE(XMLObject):
    values = ['CPU', 'MEMORY', 'NAME', 'RANK', 'REQUIREMENTS', 'VMID', 'VCPU']
    tuples = {'GRAPHICS': GRAPHICS, 'OS': OS}
    tuples_lists = {'DISK': DISK, 'NIC': NIC}
    numeric = ['CPU', 'MEMORY', 'VCPU']
    noneval = 0


class USER_TEMPLATE(XMLObject):
    values = ['ERROR']


class HISTORY(XMLObject):
    values = ['SEQ', 'HOSTNAME', 'HID', 'STIME', 'ETIME', 'PSTIME',
              'PETIME', 'RSTIME', 'RETIME', 'ESTIME', 'EETIME', 'REASON']


class VM(XMLObject):
    STATE_INIT = 0
    STATE_PENDING = 1
    STATE_HOLD = 2
    STATE_ACTIVE = 3
    STATE_STOPPED = 4
    STATE_SUSPENDED = 5
    STATE_DONE = 6
    STATE_FAILED = 7
    STATE_POWEROFF = 8
    values = ['ID', 'UID', 'NAME', 'LAST_POLL', 'STATE', 'LCM_STATE',
              'DEPLOY_ID', 'MEMORY', 'CPU', 'NET_TX', 'NET_RX', 'STIME', 'ETIME']
    tuples = {'TEMPLATE': TEMPLATE, 'USER_TEMPLATE': USER_TEMPLATE}
    numeric = ['ID', 'UID', 'STATE', 'LCM_STATE', 'STIME', 'ETIME']


class LEASE(XMLObject):
    values = ['IP', 'MAC', 'USED']


class TEMPLATE_VNET(XMLObject):
    values = ['BRIDGE', 'NAME', 'TYPE', 'NETWORK_ADDRESS']
    tuples_lists = {'LEASES': LEASE}


class LEASES(XMLObject):
    tuples_lists = {'LEASE': LEASE}


class RANGE(XMLObject):
    values = ['IP_START', 'IP_END']


class AR(XMLObject):
    values = ['IP', 'MAC', 'TYPE', 'ALLOCATED',
              'GLOBAL_PREFIX', 'AR_ID', 'SIZE', 'USED_LEASES']


class AR_POOL(XMLObject):
    tuples_lists = {'AR': AR}


class VNET(XMLObject):
    values = ['ID', 'UID', 'GID', 'UNAME', 'GNAME', 'NAME',
              'TYPE', 'BRIDGE', 'PUBLIC', 'USED_LEASES', 'TOTAL_LEASES']
    tuples = {'TEMPLATE': TEMPLATE_VNET, 'LEASES': LEASES,
              'RANGE': RANGE, 'AR_POOL': AR_POOL}


class VNET_POOL(XMLObject):
    tuples_lists = {'VNET': VNET}


class IMAGE(XMLObject):
    STATE_READY = 1
    STATE_ERROR = 5
    values = ['ID', 'UID', 'GID', 'UNAME', 'GNAME', 'NAME', 'SOURCE', 'PATH'
              'FSTYPE', 'TYPE', 'DISK_TYPE', 'PERSISTENT', 'SIZE', 'STATE']
    numeric = ['ID', 'UID', 'GID', 'SIZE', 'STATE']


class IMAGE_POOL(XMLObject):
    tuples_lists = {'IMAGE': IMAGE}


class RULE(XMLObject):
    values = ['PROTOCOL', 'RULE_TYPE', 'RANGE', 'NETWORK_ID']


class TEMPLATE_SG(XMLObject):
    values = ['DESCRIPTION']
    tuples_lists = {'RULE': RULE}


class SECURITY_GROUP(XMLObject):
    values = ['ID', 'UID', 'GID', 'UNAME', 'GNAME', 'NAME']
    numeric = ['ID', 'UID', 'GID']
    tuples = {'TEMPLATE': TEMPLATE_SG}


class SECURITY_GROUP_POOL(XMLObject):
    tuples_lists = {'SECURITY_GROUP': SECURITY_GROUP}


class OpenNebulaCloudConnector(CloudConnector):
    """
    Cloud Launcher to the OpenNebula platform
    """

    type = "OpenNebula"
    """str with the name of the provider."""
    DEFAULT_USER = 'root'
    """ default user to SSH access the VM """

    def __init__(self, cloud_info, inf):
        CloudConnector.__init__(self, cloud_info, inf)
        if self.cloud.path:
            if self.cloud.port == -1:
                if self.cloud.protocol == 'https':
                    self.cloud.port = 443
                elif self.cloud.protocol == 'http':
                    self.cloud.port = 80
                else:
                    raise Exception("Invalid port/protocol specified for OpenNebula site: %s" % self.cloud.server)
            self.server_url = "%s://%s:%d%s" % (self.cloud.protocol, self.cloud.server,
                                                self.cloud.port, self.cloud.path)
        else:
            self.server_url = "http://%s:%d/RPC2" % (self.cloud.server, self.cloud.port)

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if (protocol == "one") and self.cloud.server == src_host:
            # Check the space in image and compare with disks.free_size
            if radl_system.getValue('disks.free_size'):
                disk_free = int(radl_system.getFeature('disks.free_size').getValue('M'))
                # The VMRC specified the value in MB
                if radl_system.getValue("disk.0.size"):
                    disk_size = int(radl_system.getValue("disk.0.size"))
                else:
                    disk_size = 0

                if disk_size < disk_free:
                    # if the image do not have enough space, discard it
                    return []

            res_system = radl_system.clone()

            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    def getSessionID(self, auth_data):
        """
        Get the ONE Session ID from the auth data

        Arguments:
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

         Returns: str with the Session ID
        """
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise Exception("No auth data has been specified to OpenNebula.")
        else:
            auth = auths[0]

        if 'username' in auth and 'password' in auth:
            passwd = auth['password']
            return auth['username'] + ":" + passwd
        elif 'token' in auth:
            username, passwd = ONETTSClient.get_auth_from_tts(ConfigOpenNebula.TTS_URL,
                                                              self.cloud.server, auth['token'])
            if not username or not passwd:
                raise Exception("Error getting ONE credentials using TTS.")
            auth["username"] = username
            auth["password"] = passwd
            return username + ":" + passwd
        else:
            raise Exception("No correct auth data has been specified to OpenNebula: username and password")

    @staticmethod
    def setDisksFromTemplate(vm, template):
        """
        Set the Disks of the VM from the info obtained in the ONE template object

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - template(:py:class:`TEMPLATE`): ONE Template information.
        """
        for disk in template.DISK:
            vm.info.systems[0].setValue(
                "disk." + str(disk.DISK_ID) + ".size", disk.SIZE, "M")
            if disk.TARGET and not vm.info.systems[0].getValue("disk." + str(disk.DISK_ID) + ".device"):
                vm.info.systems[0].setValue(
                    "disk." + str(disk.DISK_ID) + ".device", disk.TARGET)
            if disk.FORMAT and not vm.info.systems[0].getValue("disk." + str(disk.DISK_ID) + ".fstype"):
                vm.info.systems[0].setValue(
                    "disk." + str(disk.DISK_ID) + ".fstype", disk.FORMAT)

    @staticmethod
    def setIPsFromTemplate(vm, template):
        """
        Set the IPs of the VM from the info obtained in the ONE template object

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - template(:py:class:`TEMPLATE`): ONE Template information.
        """
        system = vm.info.systems[0]
        for nic in template.NIC:
            i = 0
            while system.getValue("net_interface." + str(i) + ".connection"):
                net_name = system.getValue("net_interface." + str(i) + ".connection")
                net = vm.info.get_network_by_id(net_name)
                provider_id = net.getValue("provider_id")
                if provider_id == nic.NETWORK:
                    ip = str(nic.IP)
                    if IPAddress(ip).version == 6:
                        system.setValue("net_interface." + str(i) + ".ipv6", ip)
                    else:
                        system.setValue("net_interface." + str(i) + ".ip", ip)
                    break
                i += 1

    def updateVMInfo(self, vm, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)

        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")

        success, res_info = server.one.vm.info(session_id, int(vm.id))[0:2]
        if success:
            res_vm = VM(res_info)

            vm.info.systems[0].setValue('instance_name', res_vm.NAME)

            # update the state of the VM
            if res_vm.STATE < 3:
                res_state = VirtualMachine.PENDING
            elif res_vm.STATE == 3:
                if res_vm.LCM_STATE < 3:
                    res_state = VirtualMachine.PENDING
                elif res_vm.LCM_STATE == 5 or res_vm.LCM_STATE == 6:
                    res_state = VirtualMachine.STOPPED
                elif res_vm.LCM_STATE == [14, 44, 61]:
                    res_state = VirtualMachine.FAILED
                elif res_vm.LCM_STATE == 16:
                    res_state = VirtualMachine.UNKNOWN
                elif res_vm.LCM_STATE == 12 or res_vm.LCM_STATE == 13 or res_vm.LCM_STATE == 18:
                    res_state = VirtualMachine.OFF
                elif res_vm.LCM_STATE >= 36 and res_vm.LCM_STATE <= 42:
                    res_state = VirtualMachine.FAILED
                elif res_vm.LCM_STATE >= 46 and res_vm.LCM_STATE <= 50:
                    res_state = VirtualMachine.FAILED
                else:
                    res_state = VirtualMachine.RUNNING
            elif res_vm.STATE == 4 or res_vm.STATE == 5:
                res_state = VirtualMachine.STOPPED
            elif res_vm.STATE == 7:
                res_state = VirtualMachine.FAILED
            elif res_vm.STATE == 6 or res_vm.STATE == 8 or res_vm.STATE == 9:
                res_state = VirtualMachine.OFF
            else:
                res_state = VirtualMachine.UNKNOWN
            vm.state = res_state

            if vm.state == VirtualMachine.FAILED:
                # in case of error try to get the error message
                if res_vm.USER_TEMPLATE and res_vm.USER_TEMPLATE.ERROR:
                    error_msg = res_vm.USER_TEMPLATE.ERROR
                    if error_msg not in self.error_messages:
                        self.error_messages += error_msg

            # Update network data
            self.setIPsFromTemplate(vm, res_vm.TEMPLATE)

            # Update disks data
            self.setDisksFromTemplate(vm, res_vm.TEMPLATE)

            vm.info.systems[0].addFeature(Feature(
                "cpu.count", "=", res_vm.TEMPLATE.CPU), conflict="other", missing="other")
            vm.info.systems[0].addFeature(Feature(
                "memory.size", "=", res_vm.TEMPLATE.MEMORY, 'M'), conflict="other", missing="other")

            if res_vm.STIME > 0:
                vm.info.systems[0].setValue('launch_time', res_vm.STIME)

            return (success, vm)
        else:
            return (success, res_info)

    def _get_security_group(self, sg_name, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)

        success, res_info = server.one.secgrouppool.info(session_id, -1, -1, -1)[0:2]
        if success:
            sg_pool = SECURITY_GROUP_POOL(res_info)
            for sg in sg_pool.SECURITY_GROUP:
                if sg.NAME == sg_name:
                    return sg.ID
        else:
            self.logger.error("Error getting security group: %s" % res_info)

        return None

    def create_security_groups(self, inf, radl, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)

        sgs = {}
        one_ver = LooseVersion(self.getONEVersion(auth_data))
        # Security Groups appears in version 4.12.0
        if one_ver >= LooseVersion("4.12.0"):
            sgs = {}
            i = 0
            system = radl.systems[0]
            while system.getValue("net_interface." + str(i) + ".connection"):
                network_name = system.getValue("net_interface." + str(i) + ".connection")
                network = radl.get_network_by_id(network_name)

                sg_name = network.getValue("sg_name")
                if not sg_name:
                    sg_name = "im-%s-%s" % (str(inf.id), network_name)

                # Use the InfrastructureInfo lock to assure that only one VM create the SG
                with inf._lock:
                    success = True
                    sg_id = self._get_security_group(sg_name, auth_data)
                    if not sg_id:
                        sg_template = ""
                        # open always SSH port on public nets
                        if network.isPublic():
                            sg_template += "RULE = [ PROTOCOL = TCP, RULE_TYPE = inbound, RANGE = 22:22 ]\n"

                        outports = network.getOutPorts()
                        if outports:
                            for outport in outports:
                                if outport.is_range():
                                    sg_template += ("RULE = [ PROTOCOL = %s, RULE_TYPE = inbound, "
                                                    "RANGE = %d:%d ]\n" % (outport.get_protocol().upper(),
                                                                           outport.get_port_init(),
                                                                           outport.get_port_end()))
                                else:
                                    if outport.get_remote_port() != 22 or not network.isPublic():
                                        sg_template += ("RULE = [ PROTOCOL = %s, RULE_TYPE = inbound, "
                                                        "RANGE = %d:%d ]\n" % (outport.get_protocol().upper(),
                                                                               outport.get_remote_port(),
                                                                               outport.get_remote_port()))

                        if sg_template:
                            self.log_info("Creating security group: %s" % sg_name)
                            sg_template = ("NAME = %s\n" % sg_name) + sg_template
                            success, sg_id = server.one.secgroup.allocate(session_id, sg_template)[0:2]
                            if not success:
                                self.log_error("Error creating security group: %s" % sg_id)

                    if success and sg_id:
                        sgs[network_name] = sg_id

                i += 1

        return sgs

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return [(False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")]

        sgs = self.create_security_groups(inf, radl, auth_data)

        system = radl.systems[0]
        # Currently ONE plugin prioritizes user-password credentials
        if system.getValue('disk.0.os.credentials.password'):
            system.delValue('disk.0.os.credentials.private_key')
            system.delValue('disk.0.os.credentials.public_key')

        res = []
        i = 0
        while i < num_vm:
            vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
            vm.destroy = True
            inf.add_vm(vm)
            template = self.getONETemplate(vm.info, sgs, auth_data, vm)

            self.log_debug("ONE Template: %s" % template)

            success, res_id = server.one.vm.allocate(session_id, template)[0:2]

            if success:
                vm.id = str(res_id)
                vm.info.systems[0].setValue('instance_id', str(res_id))
                vm.destroy = False
                res.append((success, vm))
            else:
                res.append((success, "ERROR: " + str(res_id)))
            i += 1

        return res

    def delete_security_groups(self, inf, auth_data, timeout=90, delay=10):
        """
        Delete the SG of this node
        """
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)

        for net in inf.radl.networks:
            sg_name = "im-%s-%s" % (str(inf.id), net.id)

            # wait it to terminate and then remove the SG
            cont = 0
            deleted = False
            while not deleted and cont < timeout:
                # Get the SG to delete
                sg = self._get_security_group(sg_name, auth_data)
                if not sg:
                    self.log_info("The SG %s does not exist. Do not delete it." % sg_name)
                    deleted = True
                else:
                    try:
                        self.log_info("Deleting SG: %s" % sg_name)
                        success, sg_id = server.one.secgroup.delete(session_id, sg)[0:2]
                        if success:
                            self.log_info("Deleted.")
                            deleted = True
                        else:
                            self.log_info("Error deleting SG: %s." % sg_id)
                    except Exception as ex:
                        self.log_warn("Error deleting the SG: %s" % str(ex))

                    if not deleted:
                        time.sleep(delay)
                        cont += delay

            if not deleted:
                self.log_error("Error deleting the SG: Timeout.")

    def finalize(self, vm, last, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")

        # first delete the snapshots to avoid problems in EC3 deleting the IM front-end
        if last:
            self.delete_snapshots(vm, auth_data)

        if vm.id:
            success, err = server.one.vm.action(session_id, 'delete', int(vm.id))[0:2]
        else:
            self.log_warn("No VM ID. Ignoring")
            err = ""
            success = True

        if last and success:
            one_ver = self.getONEVersion(auth_data)
            # Security Groups appears in version 4.12.0
            if one_ver >= LooseVersion("4.12.0"):
                self.delete_security_groups(vm.inf, auth_data)

        return (success, err)

    def stop(self, vm, auth_data):
        return self.vm_action(vm, 'suspend', auth_data)

    def start(self, vm, auth_data):
        return self.vm_action(vm, 'resume', auth_data)

    def reboot(self, vm, auth_data):
        return self.vm_action(vm, 'reboot-hard', auth_data)

    def vm_action(self, vm, action, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")
        success, err = server.one.vm.action(session_id, action, int(vm.id))[0:2]
        return (success, err)

    def getONETemplate(self, radl, sgs, auth_data, vm):
        """
        Get the ONE template to create the VM

        Arguments:
           - vmi(:py:class:`dict` of str objects): VMI info.
           - radl(str): RADL document with the VM features to launch.
           - sgs(:py:class:`dict` of int objects): Map of RADL net name to created SG ID
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

         Returns: str with the ONE template
        """
        system = radl.systems[0]

        cpu = system.getValue('cpu.count')
        arch = system.getValue('cpu.arch')
        memory = system.getFeature('memory.size').getValue('M')
        name = self.gen_instance_name(system, False)
        url = urlparse(system.getValue("disk.0.image.url"))
        path = os.path.basename(url[2])

        if path.isdigit():
            disks = 'DISK = [ IMAGE_ID = "%s" ]\n' % path
        else:
            if ConfigOpenNebula.IMAGE_UNAME:
                # This only works if the user owns the image
                disks = 'DISK = [ IMAGE = "%s" ]\n' % path
            else:
                disks = 'DISK = [ IMAGE = "%s", IMAGE_UNAME = "%s" ]\n' % (
                    path, ConfigOpenNebula.IMAGE_UNAME)
        cont = 1
        while system.getValue("disk." + str(cont) + ".image.url") or system.getValue("disk." + str(cont) + ".size"):
            disk_image = system.getValue("disk." + str(cont) + ".image.url")
            disk_device = system.getValue("disk." + str(cont) + ".device")
            if disk_image:
                disks += 'DISK = [ IMAGE_ID = "%s"' % urlparse(disk_image)[2][1:]
            else:
                disk_size = system.getFeature(
                    "disk." + str(cont) + ".size").getValue('M')
                disk_fstype = system.getValue("disk." + str(cont) + ".fstype")
                if not disk_fstype:
                    disk_fstype = 'ext3'

                disks += ' DISK = [ SAVE = no, TYPE = fs , FORMAT = %s, SIZE = %d' % (disk_fstype, int(disk_size))

            if disk_device:
                disks += ', TARGET = %s' % disk_device
            disks += ' ]\n'

            cont += 1

        sched = ""
        if system.getValue('availability_zone'):
            sched = 'SCHED_REQUIREMENTS = "CLUSTER_ID=\\"%s\\""' % system.getValue('availability_zone')

        res = '''
            NAME = %s

            CPU = %s
            VCPU = %s
            MEMORY = %s
            OS = [ ARCH = "%s" ]

            %s

            %s

            %s
        ''' % (name, cpu, cpu, memory, arch, disks, sched, ConfigOpenNebula.TEMPLATE_OTHER)

        user_template = ""
        tags = self.get_instance_tags(system, auth_data, vm.inf)
        for key, value in tags.items():
            key = key.replace("-", "_")
            user_template += '%s = "%s", ' % (key, value)

        if user_template:
            res += "\nUSER_TEMPLATE = [%s]\n" % user_template[:-2]

        res += self.get_networks_template(radl, sgs, auth_data)

        # include the SSH_KEYS
        # It is supported since 3.8 version, (the VM must be prepared with the
        # ONE contextualization script)
        password = system.getValue('disk.0.os.credentials.password')
        private = system.getValue('disk.0.os.credentials.private_key')
        public = system.getValue('disk.0.os.credentials.public_key')

        if not password and (not private or not public):
            (public, private) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private)

        if (private and public) or ConfigOpenNebula.TEMPLATE_CONTEXT or Config.SSH_REVERSE_TUNNELS:
            context = ""
            if private and public:
                context += 'SSH_PUBLIC_KEY = "%s"' % public

            command = ""
            if Config.SSH_REVERSE_TUNNELS and not vm.hasPublicNet():
                inst_command = "apt update; apt install -y sshpass curl > /tmp/sshpass.out 2> /tmp/sshpass.err;"
                inst_command += "yum install sshpass curl -y;"
                inst_command += "zypper install -y sshpass curl;"

                command = "which sshpass && which curl || %s" % inst_command

                command += vm.get_boot_curl_commands()[0]

            if vm.getSSHPort() != 22:
                command += "sed -i '/Port 22/c\\Port %d' /etc/ssh/sshd_config; " % vm.getSSHPort()
                command += "service sshd restart; "

            if command:
                if context:
                    context += ", "
                context += 'START_SCRIPT = "%s"' % command.replace('"', '\\"')

            if ConfigOpenNebula.TEMPLATE_CONTEXT:
                if private and public or Config.SSH_REVERSE_TUNNELS:
                    context += ", "
                context += ConfigOpenNebula.TEMPLATE_CONTEXT
            if context:
                res += 'CONTEXT = [%s]' % context

        self.log_debug("Template: " + res)

        return res

    def getONEVersion(self, auth_data):
        """
        Get the ONE version

        Arguments:
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

         Returns: str with the ONE version (format: X.X.X)
        """
        server = ServerProxy(self.server_url, allow_none=True)

        version = "2.0.0"
        methods = server.system.listMethods()
        if "one.system.version" in methods:
            session_id = self.getSessionID(auth_data)
            success, res_info = server.one.system.version(session_id)[0:2]
            if success:
                version = res_info
            else:
                version = "3.8.0 or Higher"
        else:
            if "one.acl.info" in methods:
                version = "3.0.0"
                if "one.vm.chmod" in methods:
                    version = "3.2.0 to 3.6.0"

        self.log_debug("OpenNebula version: " + version)
        return version

    @staticmethod
    def free_range(ar_range, total_leases):
        """
        Check if there are at least one address free

        Arguments:
           - ar_range(:py:class:`AR_POOL`): a Range of a ONE network.
           - total_leases(str): Number of used leases

         Returns: bool, True if there are at least one lease free or False otherwise
        """
        start = int(''.join(["%02X" % int(i)
                             for i in ar_range.IP_START.split('.')]), 16)
        end = int(''.join(["%02X" % int(i)
                           for i in ar_range.IP_END.split('.')]), 16)
        if end - start > int(total_leases):
            return True
        return False

    @staticmethod
    def free_address(addres_pool, used_leases):
        """
        Check if there are at least one address free

        Arguments:
           - address_pool(:py:class:`AR_POOL`): List of AddressRange of a ONE network.
           - used_leases(str): Number of used leases

         Returns: bool, True if there are at least one lease free or False otherwise
        """
        size = 0
        for ar in addres_pool.AR:
            size += int(ar.SIZE)

        if size > int(used_leases):
            return True
        return False

    @staticmethod
    def free_leases(leases):
        """
        Check if there are at least one lease free

        Arguments:
           - leases(:py:class:`LEASE`): List of leases of a ONE network.

         Returns: bool, True if there are at least one lease free or False otherwise
        """
        for lease in leases.LEASE:
            if int(lease.USED) == 0:
                return True
        return False

    def getONENetworks(self, auth_data):
        """
        Get the all ONE (public/private) networks

        Arguments:
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

         Returns: a list of tuples (net_name, net_id, is_public) with the name, ID, and boolean specifying
         if it is a public network of the found network None if not found
        """
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return None
        success, info = server.one.vnpool.info(session_id, -2, -1, -1)[0:2]
        if success:
            pool_info = VNET_POOL(info)
        else:
            self.log_error("Error in the function one.vnpool.info: " + info)
            return None

        res = []
        for net in pool_info.VNET:
            if net.TEMPLATE.NETWORK_ADDRESS:
                ip = net.TEMPLATE.NETWORK_ADDRESS
            elif net.TEMPLATE.LEASES and len(net.TEMPLATE.LEASES) > 0:
                ip = net.TEMPLATE.LEASES[0].IP
            elif net.AR_POOL and net.AR_POOL.AR and len(net.AR_POOL.AR) > 0:
                # This is the case for one 4.8 and later
                if self.free_address(net.AR_POOL, net.USED_LEASES):
                    ip = net.AR_POOL.AR[0].IP
                else:
                    self.log_warn("The network with IPs like: " +
                                  net.AR_POOL.AR[0].IP + " does not have free leases")
                    continue
            elif net.RANGE and net.RANGE.IP_START:
                if self.free_range(net.RANGE, net.TOTAL_LEASES):
                    ip = net.RANGE.IP_START
                else:
                    self.log_warn("The network with IPs like: " +
                                  net.RANGE.IP_START + " does not have free leases")
            else:
                self.log_warn(
                    "IP information is not in the VNET POOL. Use the vn.info")
                success, info = server.one.vn.info(session_id, int(net.ID))[0:2]

                if not success:
                    self.log_warn(
                        "Error in the one.vn.info function: " + info + ". Ignoring network: " + net.NAME)
                    continue

                net = VNET(info)

                if net.LEASES and net.LEASES.LEASE and len(net.LEASES.LEASE) > 0:
                    if self.free_leases(net.LEASES):
                        ip = net.LEASES.LEASE[0].IP
                    else:
                        self.log_warn(
                            "The network with IPs like: " + net.LEASES.LEASE[0].IP + " does not have free leases")
                        break
                elif net.RANGE and net.RANGE.IP_START:
                    if self.free_range(net.RANGE, net.TOTAL_LEASES):
                        ip = net.RANGE.IP_START
                    else:
                        self.log_warn(
                            "The network with IPs like: " + net.RANGE.IP_START + " does not have free leases")
                else:
                    self.log_error("Unknown type of network")
                    continue

            if not ip:
                self.log_error("No IP found for network: %s. Ignoring network." % net.NAME)
                continue

            is_public = not (any([IPAddress(ip) in IPNetwork(mask)
                                  for mask in Config.PRIVATE_NET_MASKS]))

            res.append((net.NAME, net.ID, is_public))

        return res

    @staticmethod
    def map_radl_one_networks(radl_nets, one_nets):
        """
        Generate a mapping between the RADL networks and the ONE networks

        Arguments:
           - radl_nets(list of :py:class:`radl.network` objects): RADL networks.
           - one_nets(a list of tuples (net_name, net_id, is_public)): ONE networks
             (returned by getONENetworks function).

         Returns: a dict with key the RADL network id and value a tuple (one_net_name, one_net_id, is_public)
        """
        res = {}

        used_nets = []
        last_net = None
        for radl_net in radl_nets:
            # First check if the user has specified a provider ID
            net_provider_id = radl_net.getValue('provider_id')
            if net_provider_id:
                for (net_name, net_id, is_public) in one_nets:
                    # If the name is the same and have the same "publicity" value
                    if ((net_id == net_provider_id or net_name == net_provider_id) and
                            radl_net.isPublic() == is_public):
                        res[radl_net.id] = (net_name, net_id, is_public)
                        used_nets.append(net_id)
                        break
            else:
                for (net_name, net_id, is_public) in one_nets:
                    if net_id not in used_nets and radl_net.isPublic() == is_public:
                        res[radl_net.id] = (net_name, net_id, is_public)
                        used_nets.append(net_id)
                        last_net = (net_name, net_id, is_public)
                        break
                if radl_net.id not in res:
                    res[radl_net.id] = last_net

        # In case of there are no private network, use public ones for non
        # mapped networks
        used_nets = []
        for radl_net in radl_nets:
            if radl_net.id not in res or not res[radl_net.id]:
                net_provider_id = radl_net.getValue('provider_id')
                if net_provider_id:
                    for (net_name, net_id, is_public) in one_nets:
                        if net_name == net_provider_id:
                            res[radl_net.id] = (net_name, net_id, is_public)
                            used_nets.append(net_id)
                            break
                else:
                    for (net_name, net_id, is_public) in one_nets:
                        if net_id not in used_nets and is_public:
                            res[radl_net.id] = (net_name, net_id, is_public)
                            used_nets.append(net_id)
                            last_net = (net_name, net_id, is_public)
                            break
                    if radl_net.id not in res:
                        res[radl_net.id] = last_net

        return res

    def get_networks_template(self, radl, sgs, auth_data):
        """
        Generate the network part of the ONE template

        Arguments:
           - radl(str): RADL document with the VM features to launch.
           - sgs(:py:class:`dict` of int objects): Map of RADL net name to created SG ID
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

         Returns: str with the network part of the ONE template
        """
        res = ""
        one_ver = self.getONEVersion(auth_data)

        one_nets = self.getONENetworks(auth_data)
        if not one_nets:
            self.log_error("No ONE network found")
            return res
        nets = self.map_radl_one_networks(radl.networks, one_nets)

        system = radl.systems[0]
        # First set the public ones (onecloud issues...)
        for public in [True, False]:
            i = 0
            while system.getValue("net_interface." + str(i) + ".connection"):
                network = system.getValue("net_interface." + str(i) + ".connection")
                fixed_ip = system.getValue("net_interface." + str(i) + ".ip")

                # get the one network info
                if network in nets and nets[network]:
                    (net_name, net_id, is_public) = nets[network]
                    radl.get_network_by_id(network).setValue('provider_id', str(net_name))
                else:
                    self.log_error("No ONE network found for network: " + network)
                    raise Exception("No ONE network found for network: " + network)

                if public == is_public:
                    if net_id is not None:
                        if one_ver.startswith("2."):
                            res += 'NIC=[ \nNETWORK="' + net_name + '"\n'
                        else:
                            res += 'NIC=[ \nNETWORK_ID="' + net_id + '"\n'

                        if fixed_ip:
                            res += ',IP = "' + fixed_ip + '"\n'

                        if network in sgs:
                            res += ',SECURITY_GROUPS = "%d"\n' % sgs[network]

                        res += ']\n'
                    else:
                        self.log_error(
                            "The net: " + network + " cannot be defined in ONE")

                i += 1

        return res

    def checkResize(self):
        """
        Check if the one.vm.resize function appears in the ONE server

         Returns: bool, True if the one.vm.resize function appears in the ONE server or false otherwise
        """
        server = ServerProxy(self.server_url, allow_none=True)

        methods = server.system.listMethods()
        if "one.vm.resize" in methods:
            return True
        else:
            return False

    def poweroff(self, vm, auth_data, timeout=60):
        """
        Poweroff the VM and waits for it to be in poweredoff state
        """
        server = ServerProxy(self.server_url, allow_none=True)
        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")
        success, err = server.one.vm.action(session_id, 'poweroff', int(vm.id))[0:2]
        if not success:
            return (success, err)

        wait = 0
        powered_off = False
        while wait < timeout and not powered_off:
            success, res_info = server.one.vm.info(session_id, int(vm.id))[0:2]
            res_vm = VM(res_info)
            powered_off = res_vm.STATE == 8
            if not powered_off:
                time.sleep(2)
                wait += 2

        if powered_off:
            return (True, "")
        else:
            return (False, "Error waiting the VM to be powered off")

    def alterVM(self, vm, radl, auth_data):
        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")

        if not radl.systems:
            return (True, "")

        system = radl.systems[0]

        success, info = self.alter_mem_cpu(vm, system, session_id, auth_data)

        if not success:
            return (False, info)

        # TODO: wait the VM to be running
        time.sleep(5)

        success, info = self.attach_new_disks(vm, system, session_id)

        if not success:
            return (False, info)
        else:
            return (True, "")

    def attach_volume(self, vm, disk_size, disk_device, disk_fstype, session_id):
        server = ServerProxy(self.server_url, allow_none=True)

        disk_temp = '''
            DISK = [
                TYPE = fs ,
                FORMAT = %s,
                SIZE = %d,
                TARGET = %s,
                SAVE = no
                ]
        ''' % (disk_fstype, disk_size, disk_device)

        success, res_info = server.one.vm.attach(session_id, int(vm.id), disk_temp, False)[0:2]
        if success:
            return (True, "")
        else:
            return (False, res_info)

    def attach_new_disks(self, vm, system, session_id):
        orig_system = vm.info.systems[0]

        cont = 1
        while (orig_system.getValue("disk." + str(cont) + ".size") and
               orig_system.getValue("disk." + str(cont) + ".device")):
            cont += 1

        while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".device"):
            disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('M')
            disk_device = system.getValue("disk." + str(cont) + ".device")
            mount_path = system.getValue("disk." + str(cont) + ".mount_path")
            disk_fstype = system.getValue("disk." + str(cont) + ".fstype")
            # get the last letter and use vd
            disk_device = "vd" + disk_device[-1]
            system.setValue("disk." + str(cont) + ".device", disk_device)
            self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
            success, volume_id = self.attach_volume(vm, int(disk_size), disk_device, disk_fstype, session_id)
            if success:
                orig_system.setValue("disk." + str(cont) + ".size", disk_size, "M")
                orig_system.setValue("disk." + str(cont) + ".device", disk_device)
                orig_system.setValue("disk." + str(cont) + ".provider_id", volume_id)
                orig_system.setValue("disk." + str(cont) + ".mount_path", mount_path)
            else:
                self.log_error("Error creating a %d GB volume for the disk %d: %s." % (int(disk_size),
                                                                                       cont, volume_id))
                return (False, "Error creating a %d GB volume for the disk %d: %s." % (int(disk_size),
                                                                                       cont, volume_id))
            cont += 1

        return (True, "")

    def alter_mem_cpu(self, vm, system, session_id, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)

        cpu = vm.info.systems[0].getValue('cpu.count')
        memory = vm.info.systems[0].getFeature('memory.size').getValue('M')

        new_cpu = system.getValue('cpu.count')
        new_memory = system.getFeature('memory.size').getValue('M')

        new_temp = ""
        if new_cpu and new_cpu != cpu:
            new_temp += "CPU = %s\n" % new_cpu
            new_temp += "VCPU = %s\n" % new_cpu
        if new_memory and new_memory != memory:
            new_temp += "MEMORY = %s\n" % new_memory

        self.log_debug("New Template: " + new_temp)

        if new_temp:
            if self.checkResize():
                # First we must power off the VM
                (success, info) = self.poweroff(vm, auth_data)
                if not success:
                    return (success, info)
                success, info = server.one.vm.resize(session_id, int(vm.id), new_temp, False)[0:2]
                self.start(vm, auth_data)

                if success:
                    if new_cpu:
                        vm.info.systems[0].setValue('cpu.count', new_cpu)
                    if new_memory:
                        vm.info.systems[0].addFeature(
                            Feature("memory.size", "=", new_memory, 'M'), conflict="other", missing="other")
                    return (True, self.updateVMInfo(vm, auth_data))
                else:
                    return (False, info)
            else:
                return (False, "Not supported")
        else:
            # Nothing to do
            return (True, "")

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)

        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")

        image_type = ""  # Use the default one
        one_ver = self.getONEVersion(auth_data)
        if one_ver.startswith("5."):
            success, res_info = server.one.vm.disksaveas(session_id, int(vm.id), disk_num,
                                                         image_name, image_type, -1)[0:2]
        else:
            success, res_info = server.one.vm.savedisk(session_id, int(vm.id), disk_num,
                                                       image_name, image_type, True, False)[0:2]

        if success:
            new_url = "one://%s/%d" % (self.cloud.server, res_info)
            success, msg = self.wait_image(res_info, auth_data)
            if success:
                if auto_delete:
                    vm.inf.snapshots.append(new_url)
                return (True, new_url)
            else:
                try:
                    success, res_info, = server.one.image.delete(session_id, res_info)[0:2]
                except Exception:
                    self.logger.error("Error deleting image: %s" % res_info)
                return (False, "Error waiting image to be ready: %s" % msg)
        else:
            return (False, res_info)

    def wait_image(self, image_id, auth_data, timeout=180):
        server = ServerProxy(self.server_url, allow_none=True)

        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")

        state = 0
        wait = 0
        while state != IMAGE.STATE_ERROR and state != IMAGE.STATE_READY and wait < timeout:
            wait += 5
            time.sleep(5)

            success, res_info = server.one.image.info(session_id, image_id)[0:2]
            if success:
                image_info = IMAGE(res_info)
                state = image_info.STATE
            else:
                self.logger.error("Error in the function one.image.info: " + res_info)
                return False, "Error getting image info: %s" % res_info

        if state == IMAGE.STATE_READY:
            return True, ""
        elif state == IMAGE.STATE_ERROR:
            return False, "Image in Error state"
        else:
            return False, "Timeout waiting image to be ready"

    def delete_image(self, image_url, auth_data):
        server = ServerProxy(self.server_url, allow_none=True)

        session_id = self.getSessionID(auth_data)
        if session_id is None:
            return (False, "Incorrect auth data, username and password must be specified for OpenNebula provider.")

        image_id = self.get_image_id(image_url, session_id)
        if image_id is None:
            return (False, "Incorrect image name or id specified.")

        # Wait the image to be READY (not USED)
        success, msg = self.wait_image(image_id, auth_data)
        if not success:
            self.logger.warn("Error waiting image to be READY: " + msg)

        success, res_info = server.one.image.delete(session_id, image_id)[0:2]
        if success:
            return (True, "")
        else:
            return (False, res_info)

    def get_image_id(self, image_url, session_id):
        url = urlparse(image_url)
        image_id = url[2][1:]
        if image_id.isdigit():
            return int(image_id)
        else:
            # We have to find the ID of the image name
            server = ServerProxy(self.server_url, allow_none=True)
            success, res_info = server.one.imagepool.info(session_id, -2, -1, -1)[0:2]
            if success:
                pool_info = IMAGE_POOL(res_info)
            else:
                self.logger.error("Error in the function one.imagepool.info: " + res_info)
                return None

            for image in pool_info.IMAGE:
                if image.NAME == image_id:
                    return image.ID

            return None
