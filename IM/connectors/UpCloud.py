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

from urllib.parse import urlparse
import re

try:
    from libcloud.compute.base import NodeAuthSSHKey
    from libcloud.compute.providers import get_driver
    from libcloud.compute.types import NodeState, Provider
except Exception as ex:
    print("WARN: libcloud library not correctly installed. UpCloudCloudConnector will not work!.")
    print(ex)

from IM.SSH import SSH
from IM.VirtualMachine import VirtualMachine
from IM.connectors.LibCloud import LibCloudCloudConnector
from IM.connectors.exceptions import CloudConnectorException, NoAuthData, NoCorrectAuthData
from radl.radl import Feature


class UpCloudCloudConnector(LibCloudCloudConnector):
    """Cloud connector for UpCloud using the Apache Libcloud driver."""

    type = "UpCloud"
    DEFAULT_USER = "root"
    DEFAULT_LOCATION = "fi-hel1"
    VM_STATE_MAP = {
        NodeState.RUNNING: VirtualMachine.RUNNING,
        NodeState.STARTING: VirtualMachine.PENDING,
        NodeState.RECONFIGURING: VirtualMachine.PENDING,
        NodeState.REBOOTING: VirtualMachine.RUNNING,
        NodeState.STOPPED: VirtualMachine.STOPPED,
        NodeState.STOPPING: VirtualMachine.RUNNING,
        NodeState.ERROR: VirtualMachine.FAILED,
        NodeState.UNKNOWN: VirtualMachine.UNKNOWN,
    }

    def __init__(self, cloud_info, inf):
        self.auth = None
        LibCloudCloudConnector.__init__(self, cloud_info, inf)

    def get_driver(self, auth_data):
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            # Authentication entries without a host are also valid because
            # the UpCloud API endpoint is defined by the libcloud driver.
            auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise NoAuthData(self.type)

        auth = auths[0]
        if self.driver and self.auth.compare(auth_data, self.type, self.cloud.server):
            return self.driver

        if auth.get("token"):
            driver_args = {"token": auth["token"]}
        elif auth.get("username") and auth.get("password"):
            driver_args = {"username": auth["username"], "password": auth["password"]}
        else:
            raise NoCorrectAuthData(self.type, "token or username and password")

        driver_cls = get_driver(Provider.UPCLOUD)
        self.driver = driver_cls(**driver_args)
        self.auth = auth_data
        return self.driver

    @staticmethod
    def get_image_id(path):
        url = urlparse(path)
        return "%s%s" % (url.netloc, url.path)

    def get_image(self, driver, image_id):
        """Return the complete libcloud image, including its UpCloud type."""
        for image in driver.list_images():
            if str(image.id) == str(image_id):
                return image
        raise CloudConnectorException("UpCloud image not found: %s" % image_id)

    @staticmethod
    def get_location(driver, location_name):
        for location in driver.list_locations():
            if location_name == location.id or location_name.lower() in location.name.lower():
                return location
        return None

    def get_instance_type(self, driver, radl, location=None):
        sizes = driver.list_sizes(location=location)
        instance_type_name = radl.getValue("instance_type")
        (cpu, cpu_op, memory, memory_op, disk, disk_op) = self.get_instance_selectors(radl, disk_unit="G")

        compatible = []
        for size in sizes:
            cores = size.extra.get("core_number", 0)
            if (cpu_op(cores, cpu) and memory_op(size.ram, memory) and
                    disk_op(size.disk, disk) and
                    (not instance_type_name or instance_type_name in (size.id, size.name))):
                compatible.append(size)

        if not compatible:
            self.log_error("No compatible size found")
            return None

        # A price may be unavailable when the API has no price for a zone.
        return min(compatible, key=lambda size: (
            size.price is None, size.price if size.price is not None else 0,
            size.extra.get("core_number", 0), size.ram, size.disk))

    def update_system_info_from_instance(self, system, instance_type):
        if instance_type:
            LibCloudCloudConnector.update_system_info_from_instance(system, instance_type)
            system.addFeature(Feature("instance_type", "=", instance_type.id),
                              conflict="other", missing="other")
            cores = instance_type.extra.get("core_number")
            if cores:
                system.addFeature(Feature("cpu.count", "=", cores),
                                  conflict="me", missing="other")

    def _get_location_from_system(self, driver, system):
        location_name = system.getValue("availability_zone") or self.DEFAULT_LOCATION
        location = self.get_location(driver, location_name)
        if not location:
            raise CloudConnectorException("Invalid UpCloud zone specified: %s" % location_name)
        return location

    @staticmethod
    def get_volume_id(path):
        """Extract an UpCloud storage UUID from an IM volume URL."""
        url = urlparse(path)
        if url.netloc == "volume":
            return url.path.lstrip("/")
        if url.path and url.path != "/":
            return url.path.rsplit("/", 1)[-1]
        return url.netloc

    def get_volume_specs(self, system):
        """Return the additional volume definitions requested in a RADL system."""
        volumes = []
        cont = 1
        while (system.getValue("disk.%d.size" % cont) or
               system.getValue("disk.%d.image.url" % cont)):
            disk_url = system.getValue("disk.%d.image.url" % cont)
            device = system.getValue("disk.%d.device" % cont)
            if disk_url:
                volume_id = self.get_volume_id(disk_url)
                if not volume_id:
                    raise CloudConnectorException("Incorrect UpCloud volume URL in disk.%d" % cont)
                volumes.append({"index": cont, "id": volume_id, "device": device})
            else:
                size = system.getFeature("disk.%d.size" % cont).getValue("G")
                tier = system.getValue("disk.%d.type" % cont) or "maxiops"
                volumes.append({"index": cont, "size": int(size), "tier": tier,
                                "device": device})
            cont += 1
        return volumes

    @staticmethod
    def device_to_upcloud(device, disk_index=None):
        """Translate a Linux block device name to an UpCloud bus address."""
        if not device:
            if disk_index is None or disk_index > 15:
                return None
            return "virtio:%d" % disk_index

        device = device.replace("/dev/", "")
        if re.match(r"^(virtio:\d+|scsi:0:\d+|ide:[01]:[01])$", device):
            return device

        match = re.match(r"^(vd|sd|hd)([a-p])$", device)
        if not match:
            raise CloudConnectorException("Invalid Linux/UpCloud disk device: %s" % device)

        prefix, letter = match.groups()
        index = ord(letter) - ord("a")
        if prefix == "vd":
            return "virtio:%d" % index
        if prefix == "sd":
            return "scsi:0:%d" % index
        if index > 3:
            raise CloudConnectorException("UpCloud IDE only supports devices /dev/hda to /dev/hdd")
        return "ide:%d:%d" % (index // 2, index % 2)

    @staticmethod
    def device_from_upcloud(address):
        """Translate an UpCloud bus address to the expected Linux device path."""
        match = re.match(r"^virtio:(\d+)$", address or "")
        if match:
            return "/dev/vd%s" % chr(ord("a") + int(match.group(1)))
        match = re.match(r"^scsi:0:(\d+)$", address or "")
        if match:
            return "/dev/sd%s" % chr(ord("a") + int(match.group(1)))
        match = re.match(r"^ide:([01]):([01])$", address or "")
        if match:
            index = int(match.group(1)) * 2 + int(match.group(2))
            return "/dev/hd%s" % chr(ord("a") + index)
        return None

    def prepare_volumes(self, system, instance_name):
        """Build UpCloud initial create/attach definitions for RADL disks."""
        storage_devices = []
        created_addresses = []
        for spec in self.get_volume_specs(system):
            address = self.device_to_upcloud(spec["device"], spec["index"])
            if not address:
                raise CloudConnectorException("UpCloud supports at most 15 additional disks")

            if "id" in spec:
                storage_device = {"action": "attach", "storage": spec["id"],
                                  "type": "disk", "address": address}
            else:
                storage_device = {
                    "action": "create",
                    "title": "%s-disk-%d" % (instance_name, spec["index"]),
                    "size": spec["size"],
                    "tier": spec["tier"],
                    "type": "disk",
                    "address": address,
                }
                created_addresses.append(address)

            system.setValue("disk.%d.device" % spec["index"],
                            self.device_from_upcloud(address))
            storage_devices.append(storage_device)
        return storage_devices, created_addresses

    def get_created_volume_ids(self, node_id, addresses, auth_data):
        """Get UUIDs assigned by UpCloud to inline-created storage devices."""
        if not addresses:
            return []
        node = self.get_node_with_id(node_id, auth_data)
        storage_devices = node.extra.get("storage_devices", {}).get("storage_device", [])
        if isinstance(storage_devices, dict):
            storage_devices = [storage_devices]
        volumes_by_address = {storage.get("address"): storage.get("storage")
                              for storage in storage_devices}
        missing = [address for address in addresses if not volumes_by_address.get(address)]
        if missing:
            raise CloudConnectorException("Cannot obtain IDs of created UpCloud volumes: %s" % missing)
        return [volumes_by_address[address] for address in addresses]

    def get_node_with_id(self, node_id, auth_data):
        """Return a node including the UpCloud fields omitted by libcloud."""
        driver = self.get_driver(auth_data)
        response = driver.connection.request("1.3/server/%s" % node_id)
        server = response.object["server"]
        node = driver._to_node(server)
        for field in ("core_number", "memory_amount", "plan", "zone", "storage_devices"):
            if field in server:
                node.extra[field] = server[field]
        return node

    def updateVMInfo(self, vm, auth_data):
        try:
            node = self.get_node_with_id(vm.id, auth_data)
            vm.state = self.VM_STATE_MAP.get(node.state, VirtualMachine.UNKNOWN)

            system = vm.info.systems[0]
            if node.extra.get("core_number") is not None:
                system.addFeature(Feature("cpu.count", "=", int(node.extra["core_number"])),
                                  conflict="me", missing="other")
            if node.extra.get("memory_amount") is not None:
                system.addFeature(Feature("memory.size", "=", int(node.extra["memory_amount"]), "M"),
                                  conflict="other", missing="other")
            if node.extra.get("plan"):
                system.addFeature(Feature("instance_type", "=", node.extra["plan"]),
                                  conflict="other", missing="other")
            if node.extra.get("zone"):
                system.setValue("availability_zone", node.extra["zone"])

            storage_devices = node.extra.get("storage_devices", {}).get("storage_device", [])
            if isinstance(storage_devices, dict):
                storage_devices = [storage_devices]
            for index, storage in enumerate(storage_devices[1:], 1):
                linux_device = self.device_from_upcloud(storage.get("address"))
                if linux_device:
                    system.setValue("disk.%d.device" % index, linux_device)
                if storage.get("storage_size") is not None:
                    system.setValue("disk.%d.size" % index, int(storage["storage_size"]), "G")
                if storage.get("storage_tier"):
                    system.setValue("disk.%d.type" % index, storage["storage_tier"])

            self.setIPsFromInstance(vm, node)
            self.attach_volumes(vm, node)
            return True, vm
        except Exception as ex:
            self.log_exception("Error updating UpCloud VM %s." % vm.id)
            return False, "Error updating UpCloud VM %s: %s" % (vm.id, ex)

    @staticmethod
    def get_node_location(node):
        zone = node.extra.get("zone")
        if zone:
            for location in node.driver.list_locations():
                if location.id == zone:
                    return location
        return None

    def concrete_system(self, radl_system, str_url, auth_data):
        if urlparse(str_url).scheme != "upc":
            return None

        driver = self.get_driver(auth_data)
        res_system = radl_system.clone()
        location = self._get_location_from_system(driver, res_system)
        instance_type = self.get_instance_type(driver, res_system, location)
        if not instance_type:
            return None

        self.update_system_info_from_instance(res_system, instance_type)
        res_system.setValue("availability_zone", location.id)
        if not res_system.getValue("disk.0.os.credentials.username"):
            res_system.setValue("disk.0.os.credentials.username", self.DEFAULT_USER)
        return res_system

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)
        system = radl.systems[0]
        location = self._get_location_from_system(driver, system)
        instance_type = self.get_instance_type(driver, system, location)
        if not instance_type:
            raise CloudConnectorException("No compatible UpCloud plan found")

        image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = self.get_image(driver, image_id)
        public_key = system.getValue("disk.0.os.credentials.public_key")
        if not public_key:
            public_key, private_key = SSH.keygen()
            system.setValue("disk.0.os.credentials.public_key", public_key)
            system.setValue("disk.0.os.credentials.private_key", private_key)

        username = system.getValue("disk.0.os.credentials.username") or self.DEFAULT_USER
        system.setValue("disk.0.os.credentials.username", username)
        name = self.gen_instance_name(system)
        base_args = {
            "name": name,
            "size": instance_type,
            "image": image,
            "location": location,
            "auth": NodeAuthSSHKey(public_key),
            "ex_hostname": name,
            "ex_username": username,
            # Current UpCloud cloud-init templates require the metadata
            # service while the boot storage is cloned.
            "ex_metadata": "yes",
        }

        res = []
        for _ in range(num_vm):
            vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl,
                                self.cloud.getCloudConnector(inf))
            vm.destroy = True
            vm.volumes = []
            inf.add_vm(vm)
            try:
                args = base_args.copy()
                storage_devices, created_addresses = self.prepare_volumes(system, name)
                if storage_devices:
                    args["ex_storage_devices"] = storage_devices
                node = driver.create_node(**args)
                vm.id = node.id
                vm.volumes = self.get_created_volume_ids(node.id, created_addresses, auth_data)
                vm.info.systems[0].setValue("instance_id", str(node.id))
                vm.info.systems[0].setValue("instance_name", str(node.name))
                vm.destroy = False
                res.append((True, vm))
                self.log_debug("Node %s successfully created." % node.id)
            except Exception as ex:
                self.log_exception("Error creating UpCloud node.")
                res.append((False, "Error creating the node: %s" % ex))

        return res

    def delete_volumes(self, driver, vm, timeout=300):
        """Delete the data volumes created by IM for this VM."""
        pending = []
        messages = []
        volumes = {volume.id: volume for volume in driver.list_volumes()}
        for volume_id in getattr(vm, "volumes", []):
            volume = volumes.get(volume_id)
            if not volume:
                continue
            try:
                if not volume.destroy():
                    pending.append(volume_id)
                    messages.append("Error destroying volume %s." % volume_id)
            except Exception as ex:
                pending.append(volume_id)
                messages.append("Error destroying volume %s: %s." % (volume_id, ex))
                self.log_exception("Error destroying UpCloud volume %s." % volume_id)
        vm.volumes = pending
        return not pending, " ".join(messages)

    def finalize(self, vm, last, auth_data):
        """Delete a server and only the storage resources created by IM."""
        try:
            node = self.get_node_with_id(vm.id, auth_data)
        except Exception as ex:
            self.log_exception("Error getting UpCloud VM %s during finalize." % vm.id)
            return False, "Error getting UpCloud VM %s: %s" % (vm.id, ex)

        if not node:
            self.log_warn("VM %s not found." % vm.id)
            return True, ""

        # The UpCloud driver creates the root storage from disk.0 but does
        # not delete it with destroy_node(). It is the first disk in the
        # server storage_devices list. Additional user-provided volumes must
        # be preserved, so only add that root UUID to the IM-owned volumes.
        storage_devices = node.extra.get("storage_devices", {}).get("storage_device", [])
        if isinstance(storage_devices, dict):
            storage_devices = [storage_devices]
        root_volume_id = None
        for storage in storage_devices:
            if storage.get("type", "disk") == "disk" and storage.get("storage"):
                root_volume_id = storage["storage"]
                break

        volumes_to_delete = list(getattr(vm, "volumes", []))
        if root_volume_id and root_volume_id not in volumes_to_delete:
            volumes_to_delete.append(root_volume_id)

        try:
            if not node.destroy():
                return False, "Error destroying node: %s" % vm.id
        except Exception as ex:
            self.log_exception("Error destroying UpCloud VM %s." % vm.id)
            return False, "Error destroying node %s: %s" % (vm.id, ex)

        vm.volumes = volumes_to_delete
        success, message = self.delete_volumes(node.driver, vm)
        if not success:
            return False, message

        self.log_debug("VM %s and its IM-owned volumes successfully destroyed." % vm.id)
        return True, ""

    def list_images(self, auth_data, filters=None):
        driver = self.get_driver(auth_data)
        images = []
        for image in driver.list_images():
            # Ignore templates which are not currently usable. Some older
            # libcloud versions do not expose a state, hence the default.
            if image.extra.get("state", "online") != "online":
                continue
            images.append({"uri": "upc://%s" % image.id, "name": image.name})
        return self._filter_images(images, filters)

    def _node_operation(self, vm, auth_data, operation, description):
        try:
            node = self.get_node_with_id(vm.id, auth_data)
            if not node:
                return False, "VM not found with id: %s" % vm.id
            if operation(node):
                return True, ""
            return False, "Error in %s operation" % description
        except Exception as ex:
            self.log_exception("Error in UpCloud %s operation for VM %s." % (description, vm.id))
            return False, "Error in %s operation: %s" % (description, ex)

    def reboot(self, vm, auth_data):
        return self._node_operation(vm, auth_data, lambda node: node.driver.reboot_node(node), "reboot")

    def start(self, vm, auth_data):
        return self._node_operation(vm, auth_data, lambda node: node.driver.start_node(node), "start")

    def stop(self, vm, auth_data):
        return self._node_operation(vm, auth_data, lambda node: node.driver.stop_node(node), "stop")

    def get_quotas(self, auth_data, region=None):
        """Return account limits and current compute/storage usage."""
        driver = self.get_driver(auth_data)
        account = driver.connection.request("1.3/account").object["account"]
        limits = account.get("resource_limits", {})
        servers = driver.connection.request("1.3/server").object["servers"].get("server", [])
        if isinstance(servers, dict):
            servers = [servers]

        cores = sum(int(server.get("core_number", 0)) for server in servers)
        memory_mib = sum(int(server.get("memory_amount", 0)) for server in servers)
        volumes = driver.list_volumes()

        storage_by_tier = {"hdd": 0, "maxiops": 0, "standard": 0}
        for volume in volumes:
            tier = volume.extra.get("tier")
            if tier in storage_by_tier:
                storage_by_tier[tier] += volume.size

        quotas = {
            "cores": {"used": cores, "limit": int(limits.get("cores", -1))},
            "ram": {"used": memory_mib / 1024.0,
                    "limit": int(limits["memory"]) / 1024.0 if "memory" in limits else -1},
            "instances": {"used": len(servers), "limit": -1},
            "volumes": {"used": len(volumes), "limit": -1},
            "volume_storage": {"used": sum(volume.size for volume in volumes),
                               "limit": int(limits["storage_total"]) / 1024.0
                               if "storage_total" in limits else -1},
        }
        for tier, used in storage_by_tier.items():
            limit_name = "storage_%s" % tier
            quotas["volume_storage_%s" % tier] = {
                "used": used,
                "limit": int(limits[limit_name]) / 1024.0 if limit_name in limits else -1,
            }
        return quotas
