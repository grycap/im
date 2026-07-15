#! /usr/bin/env python

import sys
import unittest
import json

sys.path.append(".")
sys.path.append("..")

from mock import ANY, MagicMock, patch
from radl import radl_parse

from IM.CloudInfo import CloudInfo
from IM.InfrastructureInfo import InfrastructureInfo
from IM.VirtualMachine import VirtualMachine
from IM.auth import Authentication
from IM.connectors.UpCloud import UpCloudCloudConnector, UpCloudRESTClient
from IM.connectors.exceptions import CloudConnectorException, NoCorrectAuthData
from .CloudConn import TestCloudConnectorBase


class TestUpCloudConnector(TestCloudConnectorBase):

    @staticmethod
    def get_connector():
        cloud_info = CloudInfo()
        cloud_info.type = "UpCloud"
        inf = MagicMock()
        inf.id = "1"
        return UpCloudCloudConnector(cloud_info, inf)

    @staticmethod
    def get_radl(zone="fi-hel1"):
        return radl_parse.parse_radl("""
            network net (outbound = 'yes')
            system test (
                cpu.count >= 2 and
                memory.size >= 2048m and
                disk.0.free_size >= 40g and
                disk.0.image.url = 'upc://01000000-0000-4000-8000-000030200200' and
                disk.0.os.credentials.username = 'root' and
                availability_zone = '%s' and
                net_interface.0.connection = 'net'
            )
        """ % zone)

    @staticmethod
    def configure_driver(driver):
        location = MagicMock(id="fi-hel1", name="Helsinki 1")
        driver.list_locations.return_value = [location]
        small = MagicMock(id="1xCPU-1GB", name="1xCPU-1GB", ram=1024, disk=25,
                          price=3.0, extra={"core_number": 1})
        medium = MagicMock(id="2xCPU-4GB", name="2xCPU-4GB", ram=4096, disk=80,
                           price=8.0, extra={"core_number": 2})
        driver.list_sizes.return_value = [small, medium]
        image = MagicMock(id="01000000-0000-4000-8000-000030200200",
                          extra={"type": "template", "state": "online"})
        image.name = "Ubuntu"
        driver.list_images.return_value = [image]
        return location, medium

    @patch("IM.connectors.UpCloud.UpCloudRESTClient")
    def test_get_client(self, client_cls):
        auth = Authentication([{"type": "UpCloud", "username": "user", "password": "secret"}])

        connector = self.get_connector()
        connector.get_client(auth)

        client_cls.assert_called_once_with(base_url="https://api.upcloud.com/1.3", verify=False,
                                           log_debug=ANY,
                                           username="user", password="secret")

    @patch("IM.connectors.UpCloud.UpCloudRESTClient")
    def test_get_client_requires_password(self, client_cls):
        auth = Authentication([{"type": "UpCloud", "username": "user"}])
        with self.assertRaises(NoCorrectAuthData):
            self.get_connector().get_client(auth)
        client_cls.assert_not_called()

    @patch("IM.connectors.UpCloud.UpCloudRESTClient")
    def test_get_client_with_token(self, client_cls):
        auth = Authentication([{"type": "UpCloud", "token": "api-token"}])

        self.get_connector().get_client(auth)

        client_cls.assert_called_once_with(base_url="https://api.upcloud.com/1.3", verify=False,
                                           log_debug=ANY,
                                           token="api-token")

    def test_concrete(self):
        connector = self.get_connector()
        driver = MagicMock()
        _, size = self.configure_driver(driver)
        connector.get_client = MagicMock(return_value=driver)
        auth = Authentication([])

        concrete = connector.concreteSystem(self.get_radl().systems[0], auth)

        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0].getValue("instance_type"), size.id)
        self.assertEqual(concrete[0].getValue("cpu.count"), 2)
        driver.list_sizes.assert_called_once()

    @patch("IM.connectors.UpCloud.SSH.keygen", return_value=("public", "private"))
    def test_launch(self, keygen):
        connector = self.get_connector()
        driver = MagicMock()
        location, size = self.configure_driver(driver)
        connector.get_client = MagicMock(return_value=driver)
        connector.cloud.getCloudConnector = MagicMock(return_value=connector)
        node = MagicMock(id="server-id", name="server-name")
        driver.create_node.return_value = node
        auth = Authentication([])
        radl = self.get_radl()
        radl.systems[0].setValue("disk.0.size", 120, "G")

        result = connector.launch(InfrastructureInfo(), radl, radl, 1, auth)

        self.assertTrue(result[0][0])
        self.assertEqual(result[0][1].id, "server-id")
        self.assertEqual(radl.systems[0].getValue("disk.0.os.credentials.private_key"), "private")
        driver.create_node.assert_called_once()
        args = driver.create_node.call_args.kwargs
        self.assertEqual(args["location"], location)
        self.assertEqual(args["size"], size)
        self.assertEqual(args["ex_username"], "root")
        self.assertEqual(args["ex_metadata"], "yes")
        self.assertEqual(args["ex_root_disk_size"], 120)
        driver.wait_server_ready.assert_not_called()
        driver.set_firewall_rules.assert_called_once()
        self.assertEqual(args["auth"].pubkey, "public")

    @patch("IM.connectors.UpCloud.SSH.keygen", return_value=("public", "private"))
    def test_launch_keeps_vm_when_firewall_fails(self, keygen):
        connector = self.get_connector()
        driver = MagicMock()
        self.configure_driver(driver)
        connector.get_client = MagicMock(return_value=driver)
        connector.cloud.getCloudConnector = MagicMock(return_value=connector)
        driver.create_node.return_value = MagicMock(id="server-id", name="server-name")
        driver.set_firewall_rules.side_effect = CloudConnectorException("FIREWALL_ERROR")
        radl = self.get_radl()

        result = connector.launch(InfrastructureInfo(), radl, radl, 1, Authentication([]))

        self.assertTrue(result[0][0])
        self.assertIn("FIREWALL_ERROR", result[0][1].error_msg)

    @patch("IM.connectors.UpCloud.SSH.keygen", return_value=("public", "private"))
    def test_launch_with_volumes(self, keygen):
        connector = self.get_connector()
        driver = MagicMock()
        location, _ = self.configure_driver(driver)
        connector.get_client = MagicMock(return_value=driver)
        connector.cloud.getCloudConnector = MagicMock(return_value=connector)
        driver.create_node.return_value = MagicMock(id="server-id", name="server-name")
        created_node = MagicMock()
        created_node.extra = {"storage_devices": {"storage_device": [
            {"address": "virtio:0", "storage": "boot-volume"},
            {"address": "virtio:1", "storage": "new-volume"},
            {"address": "scsi:0:2", "storage": "existing-volume"},
        ]}}
        connector.get_node_with_id = MagicMock(return_value=created_node)
        radl = radl_parse.parse_radl("""
            network net (outbound = 'yes')
            system test (
                cpu.count >= 2 and memory.size >= 2048m and
                disk.0.free_size >= 40g and
                disk.0.image.url = 'upc://01000000-0000-4000-8000-000030200200' and
                disk.0.os.credentials.username = 'root' and
                disk.1.size = 25g and disk.1.type = 'hdd' and
                disk.2.image.url = 'upc://volume/existing-volume' and
                disk.2.device = 'scsi:0:2' and
                availability_zone = 'fi-hel1' and
                net_interface.0.connection = 'net'
            )
        """)

        auth = Authentication([])
        result = connector.launch(InfrastructureInfo(), radl, radl, 1, auth)

        self.assertTrue(result[0][0])
        self.assertEqual(result[0][1].volumes, ["new-volume"])
        driver.create_volume.assert_not_called()
        storage_devices = driver.create_node.call_args.kwargs["ex_storage_devices"]
        self.assertEqual(storage_devices, [
            {"action": "create", "title": driver.create_node.call_args.kwargs["name"] + "-disk-1",
             "size": 25, "tier": "hdd", "type": "disk", "address": "virtio:1"},
            {"action": "attach", "storage": "existing-volume", "type": "disk",
             "address": "scsi:0:2"},
        ])
        connector.get_node_with_id.assert_called_once_with("server-id", auth)
        self.assertEqual(radl.systems[0].getValue("disk.1.device"), "/dev/vdb")
        self.assertEqual(radl.systems[0].getValue("disk.2.device"), "/dev/sdc")

    def test_create_node_without_public_ip(self):
        driver = MagicMock()
        node = MagicMock()
        driver.create_node.return_value = node
        args = {"name": "server", "size": MagicMock(), "image": MagicMock(),
                "location": MagicMock()}

        result = self.get_connector().create_node(driver, args, public_ip=False)

        self.assertEqual(result, node)
        driver.create_node.assert_called_once_with(ex_public_ip=False, **args)

    def test_rest_create_node_without_public_ip(self):
        client = UpCloudRESTClient(token="token")
        server = {"uuid": "server-id", "title": "server", "state": "maintenance",
                  "ip_addresses": {"ip_address": [
                      {"access": "utility", "address": "10.0.0.1"}
                  ]}}
        response = MagicMock()
        response.object = {"server": server}
        client.request = MagicMock(return_value=response)
        size = MagicMock(id="2xCPU-4GB", disk=80,
                         extra={"storage_tier": "maxiops"})
        image = MagicMock(id="image-id", extra={"type": "template"})
        image.name = "Ubuntu"
        location = MagicMock(id="fi-hel1")
        auth = MagicMock(pubkey="ssh-rsa public")

        node = client.create_node("server", size, image, location, auth=auth,
                                  ex_hostname="server", ex_username="root",
                                  ex_metadata="yes", ex_public_ip=False)

        payload = json.loads(client.request.call_args.kwargs["data"])
        interfaces = payload["server"]["networking"]["interfaces"]["interface"]
        self.assertEqual(interfaces, [{
            "type": "utility",
            "ip_addresses": {"ip_address": [{"family": "IPv4"}]},
        }])
        self.assertEqual(node.public_ips, [])
        self.assertEqual(node.private_ips, ["10.0.0.1"])

    def test_firewall_rules(self):
        connector = self.get_connector()
        radl = radl_parse.parse_radl("""
            network public (outbound = 'yes' and
                              outports = '192.0.2.0/24-80/tcp,1000:1002/udp,8/icmp')
            system test (
                net_interface.0.connection = 'public' and
                disk.0.image.url = 'upc://image-id'
            )
        """)

        rules = connector.get_firewall_rules(radl, radl.systems[0])

        # SSH is automatically added to public networks.
        ssh = next(rule for rule in rules if rule.get("destination_port_start") == "22")
        self.assertEqual(ssh["source_address_start"], "0.0.0.0")
        self.assertEqual(ssh["source_address_end"], "255.255.255.255")
        http = next(rule for rule in rules if rule.get("destination_port_start") == "80")
        self.assertEqual(http["source_address_start"], "192.0.2.0")
        self.assertEqual(http["source_address_end"], "192.0.2.255")
        udp = next(rule for rule in rules if rule.get("protocol") == "udp")
        self.assertEqual((udp["destination_port_start"], udp["destination_port_end"]),
                         ("1000", "1002"))
        icmp = next(rule for rule in rules if rule.get("protocol") == "icmp")
        self.assertNotIn("destination_port_start", icmp)
        self.assertEqual(rules[-2], {"direction": "out", "action": "accept",
                                     "position": str(len(rules) - 1)})
        self.assertEqual(rules[-1], {"direction": "in", "action": "drop",
                                     "position": str(len(rules))})

    def test_rest_set_firewall_rules(self):
        client = UpCloudRESTClient(token="token")
        client.request = MagicMock(return_value=MagicMock(object={}))
        rules = [{"direction": "out", "action": "accept", "position": "1"}]

        self.assertTrue(client.set_firewall_rules("server-id", rules))

        client.request.assert_called_once_with(
            "server/server-id/firewall_rule", method="PUT",
            data=json.dumps({"firewall_rules": {"firewall_rule": rules}}))

    def test_rest_destroy_node_waits_through_maintenance(self):
        client = UpCloudRESTClient(token="token")
        client.log_debug = MagicMock()
        responses = [
            MagicMock(object={"server": {"state": "started"}}),
            MagicMock(object={"server": {"state": "maintenance"}}),
            MagicMock(object={"server": {"state": "stopped"}}),
            MagicMock(object={}),
        ]
        client.request = MagicMock(side_effect=responses)
        client.stop_node = MagicMock(return_value=True)

        self.assertTrue(client.destroy_node("server-id", timeout=10, poll_interval=0))

        client.stop_node.assert_called_once()
        client.request.assert_called_with("server/server-id", method="DELETE")
        self.assertEqual(client.log_debug.call_count, 2)
        self.assertIn("Stopping", client.log_debug.call_args_list[0].args[0])
        self.assertIn("Deleting", client.log_debug.call_args_list[1].args[0])

    def test_firewall_waits_only_on_illegal_state(self):
        connector = self.get_connector()
        driver = MagicMock()
        driver.set_firewall_rules.side_effect = [
            CloudConnectorException("SERVER_STATE_ILLEGAL"), True]
        radl = self.get_radl()

        connector.configure_firewall(driver, "server-id", radl, radl.systems[0])

        driver.wait_server_ready.assert_not_called()
        self.assertEqual(driver.set_firewall_rules.call_count, 2)

    def test_firewall_is_skipped_for_trial_accounts(self):
        connector = self.get_connector()
        connector.log_error = MagicMock()
        driver = MagicMock()
        driver.set_firewall_rules.side_effect = CloudConnectorException(
            "UpCloud API error 403: TRIAL_FIREWALL: Trial mode firewall cannot be modified.")
        radl = self.get_radl()

        result = connector.configure_firewall(driver, "server-id", radl, radl.systems[0])

        driver.set_firewall_rules.assert_called_once()
        connector.log_error.assert_called_once()
        self.assertIn("TRIAL_FIREWALL", result)

    def test_device_translation(self):
        connector = self.get_connector()
        self.assertEqual(connector.device_to_upcloud("/dev/vdb"), "virtio:1")
        self.assertEqual(connector.device_to_upcloud("sdc"), "scsi:0:2")
        self.assertEqual(connector.device_to_upcloud("hdd"), "ide:1:1")
        self.assertEqual(connector.device_from_upcloud("virtio:3"), "/dev/vdd")
        self.assertEqual(connector.device_from_upcloud("scsi:0:1"), "/dev/sdb")
        self.assertEqual(connector.device_from_upcloud("ide:1:0"), "/dev/hdc")
        with self.assertRaises(CloudConnectorException):
            connector.device_to_upcloud("nvme0n1")

    def test_delete_created_volumes(self):
        connector = self.get_connector()
        volume = MagicMock(id="new-volume")
        volume.destroy.return_value = True
        driver = MagicMock()
        driver.list_volumes.return_value = [volume]
        vm = MagicMock(volumes=["new-volume"])

        success, message = connector.delete_volumes(driver, vm)

        self.assertTrue(success)
        self.assertEqual(message, "")
        self.assertEqual(vm.volumes, [])
        volume.destroy.assert_called_once_with()

    def test_finalize_deletes_only_im_owned_volumes(self):
        connector = self.get_connector()
        driver = MagicMock()
        node = MagicMock(driver=driver)
        node.extra = {"storage_devices": {"storage_device": [
            {"address": "virtio:0", "storage": "root-volume", "type": "disk"},
            {"address": "virtio:1", "storage": "new-volume", "type": "disk"},
            {"address": "virtio:2", "storage": "user-volume", "type": "disk"},
        ]}}
        node.destroy.return_value = True
        connector.get_node_with_id = MagicMock(return_value=node)
        root_volume = MagicMock(id="root-volume")
        root_volume.destroy.return_value = True
        new_volume = MagicMock(id="new-volume")
        new_volume.destroy.return_value = True
        user_volume = MagicMock(id="user-volume")
        driver.list_volumes.return_value = [root_volume, new_volume, user_volume]
        vm = MagicMock(id="server-id", volumes=["new-volume"])

        success, message = connector.finalize(vm, True, Authentication([]))

        self.assertTrue(success)
        self.assertEqual(message, "")
        node.destroy.assert_called_once_with()
        root_volume.destroy.assert_called_once_with()
        new_volume.destroy.assert_called_once_with()
        user_volume.destroy.assert_not_called()
        self.assertEqual(vm.volumes, [])

    def test_invalid_zone(self):
        connector = self.get_connector()
        driver = MagicMock()
        self.configure_driver(driver)
        connector.get_client = MagicMock(return_value=driver)

        with self.assertRaises(CloudConnectorException):
            connector.concrete_system(self.get_radl("unknown").systems[0],
                                      "upc://image", Authentication([]))

    def test_update_vm_info(self):
        connector = self.get_connector()
        driver = MagicMock()
        connector.get_client = MagicMock(return_value=driver)
        server = {
            "uuid": "server-id", "title": "server", "state": "started",
            "core_number": "2", "memory_amount": "4096", "plan": "2xCPU-4GB",
            "zone": "fi-hel1", "vnc_password": "secret",
            "ip_addresses": {"ip_address": [
                {"access": "public", "address": "198.51.100.1"},
                {"access": "private", "address": "10.0.0.1"},
            ]},
        }
        node = MagicMock()
        node.state = "running"
        node.public_ips = ["198.51.100.1"]
        node.private_ips = ["10.0.0.1"]
        node.extra = {key: server[key] for key in
                      ("core_number", "memory_amount", "plan", "zone")}
        node.driver = driver
        connector.get_node_with_id = MagicMock(return_value=node)
        connector.attach_volumes = MagicMock(return_value=True)
        connector.setIPsFromInstance = MagicMock()
        radl = self.get_radl()
        vm = VirtualMachine(MagicMock(), "server-id", connector.cloud, radl, radl, connector, 1)

        success, _ = connector.updateVMInfo(vm, Authentication([]))

        self.assertTrue(success)
        self.assertEqual(vm.info.systems[0].getValue("cpu.count"), 2)
        self.assertEqual(vm.info.systems[0].getFeature("memory.size").getValue("M"), 4096)
        self.assertEqual(vm.info.systems[0].getValue("instance_type"), "2xCPU-4GB")
        self.assertEqual(vm.info.systems[0].getValue("availability_zone"), "fi-hel1")
        self.assertEqual(vm.getPublicIP(), "198.51.100.1")

    def test_list_images(self):
        connector = self.get_connector()
        driver = MagicMock()
        connector.get_client = MagicMock(return_value=driver)
        online = MagicMock(id="image-1", extra={"state": "online"})
        online.name = "Ubuntu 24.04"
        offline = MagicMock(id="image-2", extra={"state": "maintenance"})
        offline.name = "Old Ubuntu"
        driver.list_images.return_value = [online, offline]

        images = connector.list_images(Authentication([]), {"distribution": "ubuntu"})

        self.assertEqual(images, [{"uri": "upc://image-1", "name": "Ubuntu 24.04"}])

    def test_node_operations(self):
        connector = self.get_connector()
        node = MagicMock()
        connector.get_node_with_id = MagicMock(return_value=node)
        node.driver.reboot_node.return_value = True
        node.driver.start_node.return_value = True
        node.driver.stop_node.return_value = True
        vm = MagicMock(id="server-id")
        auth = Authentication([])

        self.assertEqual(connector.reboot(vm, auth), (True, ""))
        self.assertEqual(connector.start(vm, auth), (True, ""))
        self.assertEqual(connector.stop(vm, auth), (True, ""))
        node.driver.reboot_node.assert_called_once_with(node)
        node.driver.start_node.assert_called_once_with(node)
        node.driver.stop_node.assert_called_once_with(node)

    def test_get_quotas(self):
        connector = self.get_connector()
        driver = MagicMock()
        connector.get_client = MagicMock(return_value=driver)
        account_response = MagicMock()
        account_response.object = {"account": {"resource_limits": {
            "cores": 20, "memory": 10240, "storage_total": 102400,
            "storage_hdd": 20480, "storage_maxiops": 81920,
        }}}
        servers_response = MagicMock()
        servers_response.object = {"servers": {"server": [
            {"core_number": "2", "memory_amount": "4096", "zone": "fi-hel1"},
            {"core_number": "1", "memory_amount": "2048", "zone": "de-fra1"},
        ]}}
        driver.connection.request.side_effect = [account_response, servers_response]
        volume1 = MagicMock(size=40, extra={"tier": "maxiops", "zone": "fi-hel1"})
        volume2 = MagicMock(size=20, extra={"tier": "hdd", "zone": "de-fra1"})
        driver.list_volumes.return_value = [volume1, volume2]

        quotas = connector.get_quotas(Authentication([]))

        self.assertEqual(quotas["cores"], {"used": 3, "limit": 20})
        self.assertEqual(quotas["ram"], {"used": 6.0, "limit": 10.0})
        self.assertEqual(quotas["instances"], {"used": 2, "limit": -1})
        self.assertEqual(quotas["volume_storage"], {"used": 60, "limit": 100.0})
        self.assertEqual(quotas["volume_storage_maxiops"], {"used": 40, "limit": 80.0})


if __name__ == "__main__":
    unittest.main()
