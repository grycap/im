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

import tempfile
import time
import os
from IM.SSH import SSH
from IM.xmlobject import XMLObject
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
from radl.radl import Feature
from netaddr import IPNetwork, IPAddress
from IM.config import Config

# clases para parsear el resultado de las llamadas a virsh


class forward(XMLObject):
    attributes = ['mode']


class bridge(XMLObject):
    attributes = ['name', 'stp', 'delay']


class ip(XMLObject):
    attributes = ['address', 'netmask']
    # de momento el tema del dhcp no me hace falta


class network(XMLObject):
    values = ['name', 'uuid']
    tuples = {'forward': forward, 'bridge': bridge, 'ip': ip}

# de momento solo pongo lo que me interesa


class mac(XMLObject):
    attributes = ['address']

# de momento solo pongo lo que me interesa


class interface(XMLObject):
    attributes = ['type']
    tuples = {'mac': mac}

# de momento solo pongo lo que me interesa


class devices(XMLObject):
    tuples_lists = {'interface': interface}

# de momento solo pongo lo que me interesa


class domain(XMLObject):
    attributes = ['type', 'id']
    values = ['name', 'uuid', 'vcpu', 'currentMemory', 'memory']
    tuples = {'devices': devices}


class LibVirtCloudConnector(CloudConnector):

    type = "LibVirt"

    virsh = '/usr/bin/virsh'

    VM_STATE_MAP = {'running': VirtualMachine.RUNNING,
                    'blocked': VirtualMachine.PENDING,
                    'paused': VirtualMachine.OFF,
                    'shutdown': VirtualMachine.OFF,
                    'shut off': VirtualMachine.OFF,
                    'crashed': VirtualMachine.FAILED,
                    '': VirtualMachine.UNKNOWN
                    }

    def concreteSystem(self, radl_system, auth_data):
        image_urls = radl_system.getValue("disk.0.image.url")
        if not image_urls:
            return [radl_system.clone()]
        else:
            if not isinstance(image_urls, list):
                image_urls = [image_urls]

            res = []
            for str_url in image_urls:
                url = uriparse(str_url)
                protocol = url[0]

                if protocol == "file":
                    res_system = radl_system.clone()

                    res_system.getFeature("cpu.count").operator = "="
                    res_system.getFeature("memory.size").operator = "="

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.host", "=", self.cloud.server), conflict="other", missing="other")

                    res.append(res_system)

            return res

    def get_ssh_from_auth_data(self, auth_data):
        auth = auth_data.getAuthInfo(LibVirtCloudConnector.type)
        if auth and 'username' in auth[0] and 'password' in auth[0] and 'host' in auth[0]:
            return SSH(auth[0]['host'], auth[0]['username'], auth[0]['password'])
        else:
            self.logger.error("Datos de autenticacion incorrectos")
            return None

    def virsh_command(self, command, auth_data, filename=None):
        ssh = self.get_ssh_from_auth_data(auth_data)

        if filename is not None:
            dest_file = "/tmp/" + os.path.basename(filename)
            ssh.sftp_put(filename, dest_file)
            command += " " + dest_file

        (out, err, code) = ssh.execute(self.virsh + " " + command)

        if code != 0:
            self.logger.error("Error al ejecutar el virsh: " + err + out)
            return None
        else:
            return out

    def create_disk_image(self, size, auth_data):
        ssh = self.get_ssh_from_auth_data(auth_data)

        now = str(int(time.time() * 100))
        (out, err, code) = ssh.execute(
            "dd if=/dev/zero of=/tmp/" + now + ".img bs=1M count=" + str(size))

        if code != 0:
            self.logger.error("Error al crear la imagen del disco")
            self.logger.error(err + out)
            return None
        else:
            return "/tmp/" + now + ".img"

    def getNetwork(self, outbound, auth_data):

        out = self.virsh_command('net-list', auth_data)

        if out is None:
            return None

        networks = out.split('\n')

        if len(networks) < 3:
            self.logger.error("No hay ninguna red")
            return None

        networks = networks[2:]

        res = []
        for net in networks:
            if len(net.strip()) > 0:
                net_name = net.strip().split(' ')[0]
                out = self.virsh_command('net-dumpxml ' + net_name, auth_data)
                if out is None:
                    return None
                res.append(network(out))

        net_priv = None
        net_pub = None
        for net in res:
            if any([IPAddress(net.ip.address) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS]):
                # Red privada
                net_priv = net
            else:
                # Red publica
                net_pub = net

            # Si nos piden una publica solo podemos devolver la publica
            if outbound and net_pub is not None:
                return net_pub

        # Si nos piden una no publica
        if not outbound:
            # primero probamos con la privada
            if net_priv is not None:
                return net_priv
            # y si no pues la publica
            elif net_pub is not None:
                return net_pub

        self.logger.error("No se ha encontrado ninguna red adecuada.")
        return None

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        res = []
        i = 0
        while i < num_vm:
            timestamp = str(int(time.time()))
            name = radl.systems[0].getValue("disk.0.image.name")
            if not name:
                name = "userimage"
            name += "-" + timestamp
            vm = VirtualMachine(inf, name, self.cloud, radl, requested_radl)

            template = self.getTemplate(vm, radl, timestamp, auth_data)

            temp = tempfile.NamedTemporaryFile(
                prefix='domain_', suffix='.xml', dir='/tmp')
            temp.file.write(template)
            temp.file.close()
            out = self.virsh_command('define', auth_data, temp.name)

            if out is not None:
                out = self.virsh_command('start ' + name, auth_data)

                if out is not None:
                    res.append((True, vm))
                else:
                    res.append((False, "ERROR iniciando la VM"))
            else:
                res.append((False, "ERROR creando la VM"))
            i += 1
        return res

    def getNetworksTemplate(self, radl, auth_data):
        system = radl.systems[0]
        res = ""

        i = 0
        while system.getValue("net_interface." + str(i) + ".connection"):
            network = system.getValue(
                "net_interface." + str(i) + ".connection")

            # check if the network is public
            outbound = False
            for net_def in radl.network:
                if net_def.id == network:
                    if net_def.getValue('outbound') == 'yes':
                        outbound = True

            net = self.getNetwork(outbound, auth_data)

            if net is not None:
                res += '''
                    <interface type='network'>
                      <source network='%s'/>
                    </interface>
                ''' % net.name

            else:
                self.logger.error("La red: " + network +
                                  " no puede ser definida para libvirt")

            i += 1

        return res

    def getTemplate(self, vm, radl, timestamp, auth_data):
        system = radl.systems[0]

        cpu = system.getValue('cpu.count')
        arch = system.getValue('cpu.arch')
        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name") + "-" + timestamp
        if not name:
            name = "userimage" + "-" + timestamp
        url = uriparse(system.getValue("disk.0.image.url"))
        path = url[2]
        template = ""
        hypervisor = system.getValue("virtual_system_type")

        memory = system.getFeature('memory.size').getValue('K')

        # esto hay que definirlo mejor, pero de momento es una solucion
        # sencilla
        if hypervisor == 'vmware':
            raise Exception('Tipo de VM ' + hypervisor + ' aun no soportado.')
        elif hypervisor == 'kvm':

            disks = '''
                    <disk type='file' device='disk'>
                        <driver name='qemu' type='qcow2' cache='none'/>
                        <source file='%s'/>
                        <target dev='hda'/>
                    </disk>''' % (path)

            vm.volumes = []
            cont = 1
            while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".device"):
                disk_size = system.getFeature(
                    "disk." + str(cont) + ".size").getValue('M')
                disk_device = system.getValue("disk." + str(cont) + ".device")
                disk_image = self.create_disk_image(int(disk_size), auth_data)
                vm.volumes.append(disk_image)

                disks += '''
                    <disk type='file' device='disk'>
                        <driver name='tap' type='aio'/>
                        <source file='%s'/>
                        <target dev='%s'/>
                    </disk>
                ''' % (disk_image, disk_device)

                cont += 1

            devices = '''
                <devices>
                    <emulator>/usr/bin/qemu-system-x86_64</emulator>
                    <graphics type='vnc' listen='0.0.0.0' port='-1'/>
                    %s
                    %s
                </devices>''' % (disks, self.getNetworksTemplate(radl, auth_data))

            template = '''
                <domain type='qemu' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
                    <name>%s</name>
                    <memory>%s</memory>
                    <vcpu>%s</vcpu>
                    <os>
                        <type arch='%s' machine='pc'>hvm</type>
                        <boot dev='hd'/>
                    </os>
                    <features>
                        <acpi/>
                    </features>
                    %s
                </domain> ''' % (name, memory, cpu, arch, devices)
        else:
            raise Exception('Tipo de VM ' + vm['hypervisor'] + ' desconocido.')

        self.logger.debug("Template: " + template)

        return template

    def updateVMInfo(self, vm, auth_data):
        try:
            out = self.virsh_command('domstate ' + vm.id, auth_data)

            if out is None:
                # Si no tiene salida es porque la VM no existe
                vm.state = VirtualMachine.OFF
            else:
                vm.state = self.VM_STATE_MAP.get(
                    out.strip(), VirtualMachine.UNKNOWN)

                # Actualizamos los datos de la red
                out = self.virsh_command('dumpxml ' + vm.id, auth_data)

                if out is None:
                    return (False, "Error al ejecutar el virsh")

                dom_info = domain(out)

                self.setIPs(vm, dom_info, auth_data)

                # de momento solo actualizamos esto que es lo unico que puede
                # cambiar
                vm.info.system[0].setValue(
                    'memory.size', str(dom_info.currentMemory), "K")

            return (True, vm)

        except Exception, ex:
            self.logger.error("Error conectando con el servidor libvirt")
            self.logger.error(ex)
            return (False, "Error conectando con el servidor libvirt")

    def setIPs(self, vm, domain, auth_data):
        public_ips = []
        private_ips = []

        # Tenemos que hacer esto
        # https://rwmj.wordpress.com/2010/10/26/tip-find-the-ip-address-of-a-virtual-machine/
        for interface in domain.devices.interface:
            ip = self.getIPfromMAC(interface.mac.address, auth_data)
            if any([IPAddress(ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS]):
                private_ips.append(ip)
            else:
                public_ips.append(ip)

        vm.setIps(public_ips, private_ips)

    def getIPfromMAC(self, mac, auth_data):
        ssh = self.get_ssh_from_auth_data(auth_data)
        (out, _, code) = ssh.execute("arp -an")

        if code != 0 and out is not None:
            for line in out.split("\n"):
                if line.find(mac) != -1:
                    # el formato de la linea es este:
                    # ? (192.168.2.2) at 00:22:19:92:d6:bb [ether] on br0
                    ini = line.find("(") + 1
                    fin = line.find(")")
                    ip = line[ini:fin]
                    return ip

            self.logger.warn("La MAC no aparece en el listado del ARP")
        else:
            self.logger.error("Error ejecutando el ARP")

        return None

    def finalize(self, vm, auth_data):
        self.delete_volumes(vm, auth_data)

        out = self.virsh_command('destroy ' + vm.id, auth_data)

        if out is None:
            return (False, "Error al eliminar el dominio: " + str(vm.id))

        out = self.virsh_command('undefine ' + vm.id, auth_data)

        if out is None:
            return (False, "Error al undefine el dominio: " + str(vm.id))

        return (True, "")

    def delete_volumes(self, vm, auth_data):
        if "volumes" in vm.__dict__.keys() and vm.volumes:
            try:
                for disk_image in vm.volumes:
                    ssh = self.get_ssh_from_auth_data(auth_data)
                    (out, err, code) = ssh.execute("rm -f " + disk_image)

                    if code != 0:
                        self.logger.error(
                            "Error al borrar la imagen del disco")
                        self.logger.error(err + out)
            except Exception, ex:
                self.logger.error("Error al borrar la imagen del disco")
                self.logger.error(ex)

    def stop(self, vm, auth_data):
        out = self.virsh_command('destroy ' + vm.id, auth_data)

        if out is None:
            return (False, "Error al parar el dominio: " + str(vm.id))

        return (True, "")

    def start(self, vm, auth_data):
        out = self.virsh_command('start ' + vm.id, auth_data)

        if out is None:
            return (False, "Error al iniciar el dominio: " + str(vm.id))

        return (True, "")

    def alterVM(self, vm, radl, auth_data):
        memory = radl.getFeature('memory.size').getValue('K')
        out = self.virsh_command('setmem ' + vm.id + " " + memory, auth_data)

        return self.updateVMInfo(vm, auth_data)
