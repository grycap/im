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
import json
import ipaddress
import re
import time
from types import SimpleNamespace

import requests

from IM.SSH import SSH
from IM.VirtualMachine import VirtualMachine
from IM.connectors.CloudConnector import CloudConnector
from IM.connectors.exceptions import CloudConnectorException, NoAuthData, NoCorrectAuthData
from radl.radl import Feature


class UpCloudRESTClient:
    """Small requests-based client exposing the objects needed by the connector."""

    STATE_MAP = {"started": "running", "stopped": "stopped",
                 "maintenance": "pending", "error": "error"}

    def __init__(self, base_url="https://api.upcloud.com/1.3", token=None,
                 username=None, password=None, verify=True, log_debug=None):
        self.base_url = base_url.rstrip("/")
        self.connection = self
        self.log_debug = log_debug or (lambda _message: None)
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if token:
            self.session.headers["Authorization"] = "Bearer %s" % token
        else:
            self.session.auth = (username, password)

    def request(self, path, method="GET", data=None):
        path = path.lstrip("/")
        if path.startswith("1.3/"):
            path = path[4:]
        response = self.session.request(method, "%s/%s" % (self.base_url, path), data=data)
        if not response.ok:
            try:
                error = response.json().get("error", {})
                message = error.get("error_message", response.text)
                code = error.get("error_code")
                if code:
                    message = "%s: %s" % (code, message)
            except Exception:
                message = response.text
            raise CloudConnectorException("UpCloud API error %s: %s" % (response.status_code, message))
        payload = response.json() if response.content else {}
        return SimpleNamespace(object=payload)

    @staticmethod
    def _items(value, collection, item):
        result = value.get(collection, {}).get(item, [])
        return [result] if isinstance(result, dict) else result

    def list_locations(self):
        zones = self._items(self.request("zone").object, "zones", "zone")
        return [SimpleNamespace(id=z["id"], name=z["description"], country=z["id"].split("-")[0].upper())
                for z in zones]

    def list_sizes(self, location=None):
        plans = self._items(self.request("plan").object, "plans", "plan")
        prices = self._items(self.request("price").object, "prices", "zone")
        zone_price = next((p for p in prices if location and p.get("name") == location.id), {})
        result = []
        for plan in plans:
            price = zone_price.get("server_plan_%s" % plan["name"], {}).get("price")
            result.append(SimpleNamespace(id=plan["name"], name=plan["name"],
                                          ram=int(plan["memory_amount"]), disk=int(plan["storage_size"]),
                                          price=float(price) if price is not None else None,
                                          extra={"core_number": int(plan["core_number"]),
                                                 "storage_tier": plan.get("storage_tier", "maxiops")}))
        return result

    def list_images(self):
        images = []
        for image_type in ("template", "cdrom"):
            storages = self._items(self.request("storage/%s" % image_type).object, "storages", "storage")
            for image in storages:
                images.append(SimpleNamespace(id=image["uuid"], name=image["title"],
                                              extra={"access": image.get("access"),
                                                     "license": image.get("license"),
                                                     "size": image.get("size"),
                                                     "state": image.get("state"),
                                                     "type": image_type}))
        return images

    def _to_node(self, server, state=None):
        ips = server.get("ip_addresses", {}).get("ip_address", [])
        if isinstance(ips, dict):
            ips = [ips]
        extra = dict(server)
        return SimpleNamespace(id=server["uuid"], name=server["title"],
                               state=state or self.STATE_MAP.get(server.get("state"), "unknown"),
                               public_ips=[ip["address"] for ip in ips if ip.get("access") == "public"],
                               private_ips=[ip["address"] for ip in ips
                                            if ip.get("access") in ("private", "utility")],
                               extra=extra, driver=self,
                               destroy=lambda: self.destroy_node(server["uuid"]))

    def get_node(self, node_id):
        return self._to_node(self.request("server/%s" % node_id).object["server"])

    def create_node(self, name, size, image, location, auth=None, ex_hostname="localhost",
                    ex_username="root", ex_storage_devices=None, ex_metadata=None,
                    ex_public_ip=True, ex_root_disk_size=None):
        root_disk_size = ex_root_disk_size or size.disk
        if image.extra["type"] == "template":
            devices = [{"action": "clone", "storage": image.id, "title": image.name,
                        "size": root_disk_size,
                        "tier": size.extra.get("storage_tier", "maxiops")}]
        else:
            devices = [{"action": "create", "title": image.name, "size": root_disk_size,
                        "tier": size.extra.get("storage_tier", "maxiops")},
                       {"action": "attach", "storage": image.id, "type": "cdrom"}]
        devices.extend(ex_storage_devices or [])
        server = {"title": name, "hostname": ex_hostname, "plan": size.id, "zone": location.id,
                  "metadata": ex_metadata or "no", "storage_devices": {"storage_device": devices},
                  "login_user": {"username": ex_username}}
        if auth:
            server["login_user"]["ssh_keys"] = {"ssh_key": [auth.pubkey]}
        else:
            server["login_user"]["create_password"] = "yes"
        if not ex_public_ip:
            server["networking"] = {"interfaces":
                                    {"interface": [{"type": "utility",
                                                    "ip_addresses": {"ip_address": [{"family": "IPv4"}]}}]}}
        created = self.request("server", method="POST", data=json.dumps({"server": server})).object["server"]
        return self._to_node(created, "pending")

    def list_volumes(self):
        volumes = self._items(self.request("storage/normal").object, "storages", "storage")
        result = []
        for volume in volumes:
            obj = SimpleNamespace(id=volume["uuid"], name=volume["title"], size=int(volume["size"]),
                                  extra=volume, driver=self)
            obj.destroy = lambda volume_id=obj.id: self.destroy_volume(volume_id)
            result.append(obj)
        return result

    def destroy_volume(self, volume_id):
        self.request("storage/%s" % volume_id, method="DELETE")
        return True

    def reboot_node(self, node):
        self.request("server/%s/restart" % node.id, method="POST",
                     data='{"restart_server":{"stop_type":"hard"}}')
        return True

    def start_node(self, node):
        self.request("server/%s/start" % node.id, method="POST")
        return True

    def stop_node(self, node):
        self.request("server/%s/stop" % node.id, method="POST",
                     data='{"stop_server":{"stop_type":"hard"}}')
        return True

    def set_firewall_rules(self, node_id, rules):
        self.request("server/%s/firewall_rule" % node_id, method="PUT",
                     data=json.dumps({"firewall_rules": {"firewall_rule": rules}}))
        return True

    def destroy_node(self, node_id, timeout=300, poll_interval=2):
        """Stop and delete a server, allowing for UpCloud maintenance transitions."""
        deadline = time.monotonic() + timeout
        stop_requested = False
        state = "unknown"
        while time.monotonic() < deadline:
            server = self.request("server/%s" % node_id).object["server"]
            state = server.get("state")
            if state == "stopped":
                self.log_debug("Deleting UpCloud server %s." % node_id)
                self.request("server/%s" % node_id, method="DELETE")
                return True
            if state == "started" and not stop_requested:
                self.log_debug("Stopping UpCloud server %s before deletion." % node_id)
                self.stop_node(SimpleNamespace(id=node_id))
                stop_requested = True
            elif state == "error":
                return False
            time.sleep(poll_interval)
        raise CloudConnectorException(
            "Timeout destroying UpCloud server %s after %d seconds (last state: %s)" %
            (node_id, timeout, state))


class UpCloudCloudConnector(CloudConnector):
    """Cloud connector for UpCloud using its REST API directly."""

    type = "UpCloud"
    DEFAULT_USER = "root"
    DEFAULT_LOCATION = "fi-hel1"
    VM_STATE_MAP = {
        "running": VirtualMachine.RUNNING,
        "pending": VirtualMachine.PENDING,
        "stopped": VirtualMachine.STOPPED,
        "error": VirtualMachine.FAILED,
        "unknown": VirtualMachine.UNKNOWN,
    }

    def __init__(self, cloud_info, inf):
        self.auth = None
        self.client = None
        CloudConnector.__init__(self, cloud_info, inf)

    def get_client(self, auth_data):
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            # Authentication entries without a host are also valid because
            # the UpCloud API has a well-known default endpoint.
            auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise NoAuthData(self.type)

        auth = auths[0]
        if self.client and self.auth.compare(auth_data, self.type, self.cloud.server):
            return self.client

        if auth.get("token"):
            client_args = {"token": auth["token"]}
        elif auth.get("username") and auth.get("password"):
            client_args = {"username": auth["username"], "password": auth["password"]}
        else:
            raise NoCorrectAuthData(self.type, "token or username and password")

        base_url = "https://api.upcloud.com/1.3"
        if self.cloud.server:
            protocol = self.cloud.protocol or "https"
            port = ":%d" % self.cloud.port if self.cloud.port != -1 else ""
            path = self.cloud.path.rstrip("/")
            base_url = "%s://%s%s%s" % (protocol, self.cloud.server, port, path)
            if not base_url.endswith("/1.3"):
                base_url += "/1.3"
        self.client = UpCloudRESTClient(base_url=base_url, verify=self.verify_ssl,
                                        log_debug=self.log_debug, **client_args)
        self.auth = auth_data
        return self.client

    @staticmethod
    def get_image_id(path):
        url = urlparse(path)
        return "%s%s" % (url.netloc, url.path)

    def get_image(self, driver, image_id):
        """Return the complete UpCloud image, including its UpCloud type."""
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
            system.addFeature(Feature("memory.size", "=", instance_type.ram, "M"),
                              conflict="other", missing="other")
            if instance_type.disk:
                system.addFeature(Feature("disk.0.free_size", "=", instance_type.disk, "G"),
                                  conflict="other", missing="other")
            if instance_type.price:
                system.addFeature(Feature("price", "=", instance_type.price),
                                  conflict="me", missing="other")
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

    def get_firewall_rules(self, radl, system):
        """Translate RADL outports into an ordered UpCloud firewall chain."""
        outports = []
        index = 0
        while system.getValue("net_interface.%d.connection" % index):
            network_id = system.getValue("net_interface.%d.connection" % index)
            network = radl.get_network_by_id(network_id)
            network_outports = network.getOutPorts() or []
            if network.isPublic() or network.getValue("proxy_host"):
                network_outports = self.add_ssh_port(network_outports)
            outports.extend(network_outports)
            index += 1

        rules = []
        seen = set()
        for outport in outports:
            protocol = outport.get_protocol().lower()
            port_start = outport.get_port_init() if outport.is_range() else outport.get_remote_port()
            port_end = outport.get_port_end() if outport.is_range() else outport.get_remote_port()
            network = ipaddress.ip_network(outport.get_remote_cidr(), strict=False)
            key = (protocol, port_start, port_end, str(network))
            if key in seen:
                continue
            seen.add(key)
            rule = {
                "direction": "in",
                "family": "IPv%d" % network.version,
                "protocol": protocol,
                "source_address_start": str(network.network_address),
                "source_address_end": str(network.broadcast_address),
                "action": "accept",
                "comment": "Created by Infrastructure Manager",
            }
            if protocol in ("tcp", "udp"):
                rule["destination_port_start"] = str(port_start)
                rule["destination_port_end"] = str(port_end)
            rules.append(rule)

        # Permit responses and arbitrary egress, then deny every other
        # inbound packet. UpCloud requires the default rule to be last and
        # to contain only direction, action and position.
        rules.append({"direction": "out", "action": "accept"})
        rules.append({"direction": "in", "action": "drop"})
        for position, rule in enumerate(rules, 1):
            rule["position"] = str(position)
        return rules

    def configure_firewall(self, driver, node_id, radl, system, timeout=120):
        try:
            rules = self.get_firewall_rules(radl, system)
        except Exception as ex:
            message = "Error creating UpCloud firewall for server %s: %s" % (node_id, ex)
            self.log_error(message)
            return message

        elapsed = 0
        while elapsed < timeout:
            try:
                driver.set_firewall_rules(node_id, rules)
                return None
            except Exception as ex:
                # UpCloud may accept firewall rules while a server is still being
                # prepared. Wait only when the API explicitly rejects its state.
                if "SERVER_STATE_ILLEGAL" in str(ex):
                    self.log_debug("UpCloud server %s not ready for firewall configuration, waiting..." % node_id)
                    time.sleep(2)
                    elapsed += 2
                    continue
                message = "Error creating UpCloud firewall for server %s: %s" % (node_id, ex)
                self.log_error(message)
                return message

        message = "Timeout configuring firewall for UpCloud server %s after %d seconds" % (node_id, timeout)
        self.log_error(message)
        return message

    @staticmethod
    def create_node(driver, args, public_ip=True):
        """Create a node, optionally requesting only the UpCloud utility network."""
        args = args.copy()
        args["ex_public_ip"] = public_ip
        return driver.create_node(**args)

    def get_node_with_id(self, node_id, auth_data):
        """Return a node including the UpCloud server details."""
        driver = self.get_client(auth_data)
        return driver.get_node(node_id)

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

            vm.setIps(node.public_ips, node.private_ips)
            return True, vm
        except Exception as ex:
            self.log_exception("Error updating UpCloud VM %s." % vm.id)
            return False, "Error updating UpCloud VM %s: %s" % (vm.id, ex)

    def concrete_system(self, radl_system, str_url, auth_data):
        if urlparse(str_url).scheme != "upc":
            return None

        driver = self.get_client(auth_data)
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
        driver = self.get_client(auth_data)
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
            "auth": SimpleNamespace(pubkey=public_key),
            "ex_hostname": name,
            "ex_username": username,
            # Current UpCloud cloud-init templates require the metadata
            # service while the boot storage is cloned.
            "ex_metadata": "yes",
        }
        root_disk = system.getFeature("disk.0.size")
        if root_disk:
            base_args["ex_root_disk_size"] = int(root_disk.getValue("G"))

        res = []
        public_ip = radl.hasPublicNet(system.name)
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
                node = self.create_node(driver, args, public_ip)
                vm.id = node.id
                firewall_error = self.configure_firewall(driver, node.id, radl, system)
                if firewall_error:
                    vm.error_msg = firewall_error
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
        driver = self.get_client(auth_data)
        images = []
        for image in driver.list_images():
            # Ignore templates which are not currently usable. The API may
            # omit a state, hence the default.
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
        driver = self.get_client(auth_data)
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
