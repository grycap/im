import copy
import json
import tempfile
import unittest
from pathlib import Path

import yaml
from unittest.mock import Mock, patch

from IM.CloudInfo import CloudInfo
from IM.config import Config
from IM.ConfManager import ConfManager
from IM.InfrastructureInfo import InfrastructureInfo
from IM.VirtualMachine import VirtualMachine
# Initialize the application before importing its mutually dependent routers.
import IM.rest.REST
from IM.rest.routers.infrastructures import get_command
from radl.radl_parse import parse_radl


def _real_vm(inf, im_id, cloud_id, extra="", public=True):
    radl = parse_radl("""
network public (outbound = 'yes')
network private ()
system node (
    disk.0.os.name = 'linux' and
    disk.0.os.credentials.username = 'user' and
    disk.0.os.credentials.password = 'pass' and
    net_interface.0.connection = '%s' and
    net_interface.0.ip = '%s' %s
)
""" % ("public" if public else "private", "192.0.2.%s" % (im_id + 1) if public else "10.0.0.2",
       "and " + extra if extra else ""))
    cloud = CloudInfo()
    cloud.id = cloud_id
    cloud.type = "Dummy"
    vm = VirtualMachine(inf, "provider-%s" % im_id, cloud, radl, radl, im_id=im_id)
    vm.state = VirtualMachine.RUNNING
    vm.creating = False
    inf.vm_list.append(vm)
    return vm


def _vm(im_id, cloud_id, connected=0):
    vm = Mock()
    vm.im_id = im_id
    vm.cloud = Mock(id=cloud_id)
    vm.destroy = False
    vm.deleting = False
    vm.get_ansible_host.return_value = None
    vm.contextualize.return_value = True
    vm.getOS.return_value = "linux"
    vm.hasPublicNet.return_value = True
    vm.getProxyHost.return_value = None
    vm.isConnectedWith.side_effect = lambda other: other is not vm and connected > 0
    return vm


class TestMulticloudMasterSelection(unittest.TestCase):
    def test_selects_one_managed_master_per_cloud(self):
        inf = InfrastructureInfo()
        a1, a2 = _vm(0, "cloud-a"), _vm(1, "cloud-a")
        b1 = _vm(2, "cloud-b")
        inf.vm_list = [a1, a2, b1]

        masters = inf.select_vm_masters()

        self.assertEqual({"cloud-a", "cloud-b"}, set(masters))
        self.assertIn(masters["cloud-a"], [a1, a2])
        self.assertIs(masters["cloud-b"], b1)
        self.assertEqual(masters, inf.vm_masters)

    def test_does_not_select_candidate_from_another_cloud(self):
        inf = InfrastructureInfo()
        candidate = _vm(0, "cloud-a")
        target = _vm(1, "cloud-b")
        inf.vm_list = [candidate, target]
        target.contextualize.return_value = False

        masters = inf.select_vm_masters()

        self.assertEqual({"cloud-a"}, set(masters))
        self.assertIs(masters["cloud-a"], candidate)

    def test_external_hosts_do_not_need_or_supply_managed_masters(self):
        inf = InfrastructureInfo()
        external = _vm(0, "cloud-a")
        external.get_ansible_host.return_value = Mock()
        private = _vm(1, "cloud-a")
        private.hasPublicNet.return_value = False
        other = _vm(2, "cloud-b")
        inf.vm_list = [external, private, other]

        masters = inf.select_vm_masters()

        self.assertEqual({"cloud-b": other}, masters)
        private.contextualize.return_value = False
        other.get_ansible_host.return_value = Mock()
        self.assertEqual({}, inf.select_vm_masters())
        self.assertIsNone(inf.vm_master)

    def test_keeps_legacy_master_and_replaces_only_deleted_cloud_master(self):
        inf = InfrastructureInfo()
        a1, a2, b = _vm(0, "cloud-a"), _vm(1, "cloud-a"), _vm(2, "cloud-b")
        inf.vm_list = [a1, a2, b]
        inf.vm_master = a2
        self.assertEqual({"cloud-a": a2, "cloud-b": b}, inf.select_vm_masters())
        b.deleting = True
        replacement = _vm(3, "cloud-b")
        inf.vm_list.append(replacement)
        self.assertEqual({"cloud-a": a2, "cloud-b": replacement}, inf.select_vm_masters())

    def test_proxy_accessible_linux_vm_is_reused_without_creating_vms(self):
        inf = InfrastructureInfo()
        windows, deleting, proxy = _vm(0, "cloud-a"), _vm(1, "cloud-a"), _vm(2, "cloud-a")
        windows.getOS.return_value = "windows"
        deleting.deleting = True
        proxy.hasPublicNet.return_value = False
        proxy.getProxyHost.return_value = Mock()
        original_vms = [windows, deleting, proxy]
        inf.vm_list = list(original_vms)
        self.assertEqual({"cloud-a": proxy}, inf.select_vm_masters())
        self.assertEqual(original_vms, inf.vm_list)


class TestMulticloudSSH(unittest.TestCase):
    def setUp(self):
        self.inf = InfrastructureInfo()
        self.a = _real_vm(self.inf, 0, "cloud-a")
        self.b = _real_vm(self.inf, 1, "cloud-b")
        self.target = _real_vm(self.inf, 2, "cloud-b", public=False)
        self.inf.vm_master = self.a
        self.inf.vm_masters = {"cloud-a": self.a, "cloud-b": self.b}

    def test_ssh_routes_through_same_cloud_master(self):
        with patch.object(self.b, "get_ssh", return_value="cloud-b-ssh") as get_ssh:
            self.assertEqual("cloud-b-ssh", self.target.get_ssh_ansible_master(retry=False, auto_close=False))
        get_ssh.assert_called_once_with(retry=False, auto_close=False)

    def test_legacy_fallback_never_routes_to_another_cloud(self):
        self.inf.vm_masters = {}
        self.assertIsNone(self.target.get_ssh_ansible_master())
        self.assertEqual(self.a.getPublicIP(), self.a.get_ssh_ansible_master().host)

    def test_missing_controller_without_cloud_metadata_returns_no_ssh(self):
        self.inf.vm_masters = {}
        self.inf.vm_master = None
        self.target.cloud = None
        self.assertIsNone(self.target.get_ssh_ansible_master())

    def test_external_host_keeps_priority_over_managed_master(self):
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        self.target.requested_radl.ansible_hosts = [host]
        self.assertEqual("198.51.100.1", self.target.get_ssh_ansible_master(retry=False).host)

    def test_reverse_tunnel_checks_connectivity_with_own_cloud_master(self):
        ssh = Mock()
        ssh.test_connectivity.return_value = True
        self.b.get_ssh = Mock(return_value=ssh)
        self.target.isConnectedWith = Mock(side_effect=lambda vm: vm is self.b)
        self.target.get_ssh_command = Mock(return_value="tunnel")
        self.assertEqual("true", get_command(2, self.inf, self.inf.id, str(self.target.creation_im_id), Mock()))
        self.target.isConnectedWith.assert_called_once_with(self.b)

    def test_external_override_does_not_treat_legacy_master_as_local_controller(self):
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        self.a.requested_radl.ansible_hosts = [host]
        self.a.get_ssh_command = Mock(return_value="external-tunnel")
        with patch("IM.VirtualMachine.SSH") as ssh:
            ssh.return_value.test_connectivity.return_value = True
            self.assertEqual("external-tunnel", get_command(2, self.inf, self.inf.id, "0", Mock()))

    def test_launch_uses_routed_controller_and_matching_agent_mode(self):
        self.b.get_ssh = Mock(return_value=Mock())
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        cm = ConfManager(self.inf, None)
        with patch("IM.ConfManager.Config.VM_NUM_USE_CTXT_DIST", 1), \
                patch.object(self.target, "launch_check_ctxt_process"), patch("IM.VirtualMachine.SSHRetry") as external:
            for is_external in (False, True):
                self.target.requested_radl.ansible_hosts = [host] if is_external else []
                ssh = external.return_value if is_external else self.b.get_ssh.return_value
                ssh.execute.return_value = ("4242", "", 0)
                self.assertEqual("4242", cm.launch_ctxt_agent(self.target, ["basic"]))
                command = ssh.execute.call_args.args[0]
                self.assertIn("ctxt_agent.py" if is_external else "ctxt_agent_dist.py", command)
                self.assertEqual("4242", self.target.ctxt_pid)

    def test_monitor_and_kill_use_the_same_cloud_controller_as_launch(self):
        ssh = Mock()
        self.b.get_ssh = Mock(return_value=ssh)
        self.target.ctxt_pid = "4242"
        ssh.execute.side_effect = [("PGID\n4242\n", "", 0), ("", "", 0)]
        self.target.kill_check_ctxt_process()
        self.assertEqual("kill -9 -4242", ssh.execute.call_args.args[0])
        self.assertIsNone(self.target.ctxt_pid)
        self.assertFalse(self.target.configured)
        self.target.ctxt_pid = "4242"
        ssh.execute.side_effect = None
        ssh.execute.return_value = ("", "", 1)
        with patch.object(self.target, "get_ctxt_log", return_value="log"), \
                patch.object(self.target, "get_ctxt_output", return_value="output") as output:
            self.target.check_ctxt_process()
            self.assertIs(output.call_args.args[1], ssh)
        self.assertIsNone(self.target.ctxt_pid)
        self.assertEqual(2, self.b.get_ssh.call_count)


class TestMulticloudPersistence(unittest.TestCase):
    def test_legacy_record_without_cloud_metadata_keeps_single_master(self):
        inf = InfrastructureInfo()
        master = _real_vm(inf, 0, "cloud-a")
        master.cloud = None
        inf.vm_master = master
        inf.ansible_configured = True
        serialized = inf.serialize()
        del serialized["vm_masters"]
        del serialized["ansible_configured_masters"]
        restored = InfrastructureInfo.deserialize(json.dumps(serialized))
        self.assertIs(restored.vm_master, restored.vm_list[0])
        self.assertIs(restored.get_vm_master(restored.vm_list[0]), restored.vm_master)

    def test_round_trip_keeps_identity_and_legacy_field_without_mutating_input(self):
        inf = InfrastructureInfo()
        a, b = _real_vm(inf, 0, "cloud-a"), _real_vm(inf, 1, "cloud-b")
        inf.select_vm_masters()
        serialized = json.loads(json.dumps(inf.serialize()))
        original = copy.deepcopy(serialized)

        restored = InfrastructureInfo.deserialize(serialized)

        self.assertEqual(original, serialized)
        self.assertIs(restored.vm_masters["cloud-a"], restored.vm_list[0])
        self.assertIs(restored.vm_masters["cloud-b"], restored.vm_list[1])
        self.assertIs(restored.vm_master, restored.vm_list[0])
        self.assertEqual({"cloud-a": a.im_id, "cloud-b": b.im_id}, restored.serialize()["vm_masters"])

    def test_old_record_migrates_single_master_to_its_cloud(self):
        inf = InfrastructureInfo()
        a, b = _real_vm(inf, 0, "cloud-a"), _real_vm(inf, 1, "cloud-b")
        inf.vm_master = a
        inf.ansible_configured = True
        serialized = inf.serialize()
        del serialized["vm_masters"]
        del serialized["ansible_configured_masters"]
        restored = InfrastructureInfo.deserialize(json.dumps(serialized))
        self.assertIs(restored.vm_masters["cloud-a"], restored.vm_list[0])
        self.assertIsNone(restored.get_vm_master(restored.vm_list[1]))
        restored.select_vm_masters()
        self.assertEqual({"cloud-a", "cloud-b"}, set(restored.vm_masters))
        self.assertEqual({"cloud-a": 0}, restored.ansible_configured_masters)

    def test_legacy_selector_populates_per_cloud_masters(self):
        inf = InfrastructureInfo()
        a, b = _real_vm(inf, 0, "cloud-a"), _real_vm(inf, 1, "cloud-b")
        inf.select_vm_master()
        self.assertEqual({"cloud-a": a, "cloud-b": b}, inf.vm_masters)
        self.assertIs(inf.vm_master, a)


class TestMulticloudBootstrap(unittest.TestCase):
    def setUp(self):
        self.inf = InfrastructureInfo()
        self.a = _real_vm(self.inf, 0, "cloud-a")
        self.b = _real_vm(self.inf, 1, "cloud-b")
        self.cm = ConfManager(self.inf, None)

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    def test_waits_and_changes_credentials_on_every_cloud_master(self, save):
        self.cm.wait_vm_running = Mock(return_value=True)
        self.cm.wait_vm_ssh_acccess = Mock(return_value=(True, ""))
        self.a.get_ssh = Mock(return_value=Mock())
        self.b.get_ssh = Mock(return_value=Mock())
        for vm in (self.a, self.b):
            vm.info.systems[0].setValue("disk.0.os.credentials.new.password", "new-%s" % vm.im_id)
            vm.get_ssh.return_value.execute.return_value = ("OK", "", 0)

        self.assertTrue(self.cm.wait_master())

        self.assertEqual([self.a, self.b], [call.args[0] for call in self.cm.wait_vm_running.call_args_list])
        self.assertEqual("new-0", self.a.getCredentialValues()[1])
        self.assertEqual("new-1", self.b.getCredentialValues()[1])
        self.a.get_ssh.return_value.close.assert_called_once()
        self.b.get_ssh.return_value.close.assert_called_once()

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    def test_fails_when_any_managed_cloud_has_no_eligible_master(self, save):
        self.b.info.systems[0].setValue("disk.0.os.name", "windows")
        self.cm.wait_vm_running = Mock(return_value=True)
        self.cm.wait_vm_ssh_acccess = Mock(return_value=(True, ""))
        self.a.get_ssh = Mock(return_value=Mock())
        self.assertFalse(self.cm.wait_master())
        self.assertFalse(self.inf.configured)
        self.assertIn("cloud-b", self.inf.cont_out)

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    def test_wait_failure_is_not_success(self, save):
        self.cm.wait_vm_running = Mock(side_effect=[True, False])
        self.cm.wait_vm_ssh_acccess = Mock(return_value=(True, ""))
        self.a.get_ssh = Mock(return_value=Mock())
        self.assertFalse(self.cm.wait_master())
        self.assertFalse(self.inf.configured)

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.time.sleep")
    def test_installs_and_copies_agent_on_each_managed_master(self, sleep, save):
        self.inf.select_vm_masters()
        self.a.get_ssh = Mock(return_value=Mock())
        self.b.get_ssh = Mock(return_value=Mock())
        self.cm.configure_ansible = Mock(return_value=True)

        self.assertTrue(self.cm.configure_master())

        self.assertEqual([self.a.get_ssh.return_value, self.b.get_ssh.return_value],
                         [call.args[0] for call in self.cm.configure_ansible.call_args_list])
        for vm in (self.a, self.b):
            vm.get_ssh.return_value.sftp_put_files.assert_called_once()
            vm.get_ssh.return_value.close.assert_called_once()
        self.assertEqual({"cloud-a": 0, "cloud-b": 1}, self.inf.ansible_configured_masters)
        restored = InfrastructureInfo.deserialize(json.dumps(self.inf.serialize()))
        self.assertEqual(self.inf.ansible_configured_masters, restored.ansible_configured_masters)

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.time.sleep")
    def test_failed_cloud_retry_does_not_reinstall_successful_cloud(self, sleep, save):
        self.inf.select_vm_masters()
        self.a.get_ssh = Mock(return_value=Mock())
        self.b.get_ssh = Mock(return_value=Mock())
        self.a.get_ssh.return_value.sftp_list.return_value = ["file"] * 4
        self.b.get_ssh.return_value.sftp_list.return_value = ["file"] * 4
        self.cm.configure_ansible = Mock(side_effect=lambda ssh, *args: ssh is self.a.get_ssh.return_value)
        with patch("IM.ConfManager.Config.PLAYBOOK_RETRIES", 1):
            self.assertFalse(self.cm.configure_master())
        self.assertFalse(self.inf.ansible_configured)
        self.assertEqual({"cloud-a": 0}, self.inf.ansible_configured_masters)
        self.cm.configure_ansible = Mock(return_value=True)
        self.inf.configured = None
        self.assertTrue(self.cm.configure_master())
        self.assertEqual([self.b.get_ssh.return_value],
                         [call.args[0] for call in self.cm.configure_ansible.call_args_list])

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.time.sleep")
    def test_legacy_bootstrap_flag_does_not_skip_new_cloud(self, sleep, save):
        self.inf.vm_master = self.a
        self.inf.ansible_configured = True
        self.a.get_ssh = Mock(return_value=Mock())
        self.b.get_ssh = Mock(return_value=Mock())
        self.a.get_ssh.return_value.sftp_list.return_value = ["file"] * 4
        self.cm.configure_ansible = Mock(return_value=True)
        self.assertTrue(self.cm.configure_master())
        self.assertEqual([self.b.get_ssh.return_value],
                         [call.args[0] for call in self.cm.configure_ansible.call_args_list])

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.time.sleep")
    def test_reselected_master_is_not_bootstrapped_by_stale_aggregate_flag(self, sleep, save):
        self.inf.vm_master = self.a
        self.inf.vm_masters = {"cloud-a": self.a}
        self.inf.ansible_configured = True
        self.inf.ansible_configured_masters = {"cloud-a": self.a.im_id}
        self.a.destroy = True
        self.b.destroy = True
        replacement = _real_vm(self.inf, 2, "cloud-a")
        replacement.get_ssh = Mock(return_value=Mock())
        replacement.get_ssh.return_value.sftp_list.return_value = ["file"] * 4
        self.inf.select_vm_masters()
        self.cm.configure_ansible = Mock(return_value=True)
        self.assertTrue(self.cm.configure_master())
        self.cm.configure_ansible.assert_called_once()

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.time.sleep")
    def test_legacy_scalar_bootstrap_flag_is_honored_for_unchanged_single_master(self, sleep, save):
        self.b.destroy = True
        self.inf.select_vm_masters()
        self.inf.ansible_configured = True
        self.a.get_ssh = Mock(return_value=Mock())
        self.a.get_ssh.return_value.sftp_list.return_value = ["file"] * 4
        self.cm.configure_ansible = Mock(return_value=True)
        self.assertTrue(self.cm.configure_master())
        self.cm.configure_ansible.assert_not_called()

    def test_proxy_password_controller_bootstrap_has_proxy_inventory(self):
        ssh = Mock(host="10.0.0.2", port=22, username="user", password="pass", private_key=None)
        ssh.proxy_host = Mock(host="proxy.example.org", port=22, username="proxy", password="proxy-pass",
                              private_key=None)
        ssh.execute.return_value = ("", "", 0)
        self.cm.call_ansible = Mock(return_value=(True, "OK"))
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertTrue(self.cm.configure_ansible(ssh, tmp_dir))
            inventory = Path(tmp_dir, "inventory.cfg").read_text()
        self.assertIn("ProxyCommand", inventory)
        self.assertIn("proxy@proxy.example.org", inventory)
        self.cm.call_ansible.assert_called_once()

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.SSHRetry")
    def test_external_only_bootstrap_does_not_require_linux_master(self, ssh_retry, save):
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        for vm in (self.a, self.b):
            vm.requested_radl.ansible_hosts = [host]
            vm.info.systems[0].setValue("disk.0.os.name", "windows")
        self.inf.radl.ansible_hosts = [host]
        self.cm.wait_vm_running = Mock()
        self.cm.configure_ansible = Mock()
        self.assertTrue(self.cm.wait_master())
        self.assertTrue(self.cm.configure_master())
        self.assertEqual({}, self.inf.vm_masters)
        self.cm.wait_vm_running.assert_not_called()
        self.cm.configure_ansible.assert_not_called()
        ssh_retry.return_value.sftp_put_files.assert_called_once()

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.SSHRetry")
    @patch("IM.ConfManager.time.sleep")
    def test_mixed_external_and_multiple_managed_clouds_bootstrap_every_controller(self, sleep, ssh_retry, save):
        ext = _real_vm(self.inf, 2, "cloud-external")
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        ext.requested_radl.ansible_hosts = [host]
        self.inf.radl.ansible_hosts = [host]
        self.a.get_ssh = Mock(return_value=Mock())
        self.b.get_ssh = Mock(return_value=Mock())
        self.cm.configure_ansible = Mock(return_value=True)
        self.assertTrue(self.cm.configure_master())
        self.assertEqual({"cloud-a", "cloud-b"}, set(self.inf.vm_masters))
        self.assertEqual(2, self.cm.configure_ansible.call_count)
        ssh_retry.return_value.sftp_put_files.assert_called_once()
        for vm in (self.a, self.b):
            vm.get_ssh.return_value.sftp_put_files.assert_called_once()

    @patch("IM.InfrastructureList.InfrastructureList.save_data")
    @patch("IM.ConfManager.SSHRetry")
    @patch("IM.ConfManager.time.sleep")
    def test_external_agent_upload_retains_bootstrap_retries(self, sleep, ssh_retry, save):
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        for vm in (self.a, self.b):
            vm.requested_radl.ansible_hosts = [host]
        self.inf.radl.ansible_hosts = [host]
        ssh_retry.return_value.sftp_put_files.side_effect = [IOError("transient upload failure"), None]
        with patch("IM.ConfManager.Config.PLAYBOOK_RETRIES", 2):
            self.assertTrue(self.cm.configure_master())
        self.assertEqual(2, ssh_retry.return_value.sftp_put_files.call_count)


class TestMulticloudFiles(unittest.TestCase):
    def setUp(self):
        self.inf = InfrastructureInfo()
        self.a = _real_vm(self.inf, 0, "cloud-a")
        self.b = _real_vm(self.inf, 1, "cloud-b")
        self.target = _real_vm(self.inf, 2, "cloud-b", public=False)
        self.inf.select_vm_masters()
        self.cm = ConfManager(self.inf, None)
        self.uploaded = {}
        for master in (self.a, self.b):
            master.get_ssh = Mock(return_value=self.controller_ssh(master.cloud.id))

    def controller_ssh(self, key):
        ssh = Mock()

        def upload(files):
            self.uploaded[key] = {Path(local).name: Path(local).read_text() for local, remote in files}

        ssh.sftp_put_files.side_effect = upload
        return ssh

    def assert_controller_files(self, key, vms, master=None):
        files = self.uploaded[key]
        conf = json.loads(files["general_info.cfg"])
        self.assertEqual([vm.im_id for vm in vms], [vm["id"] for vm in conf["vms"]])
        self.assertEqual([master.im_id] if master else [], [vm["id"] for vm in conf["vms"] if vm["master"]])
        inventory = yaml.safe_load(files["hosts"])["all"]
        hosts = inventory["children"]["node"]["hosts"]
        self.assertEqual({"%s_%s" % (vm.getPublicIP() or vm.getPrivateIP(), vm.im_id) for vm in vms}, set(hosts))
        self.assertEqual([str(master.im_id)] if master else [],
                         [data["IM_NODE_NUM"] for data in hosts.values() if data.get("ansible_connection") == "local"])
        self.assertIn("basic_task_all.yml", files)
        self.assertIn("main_node_task.yml", files)
        if master:
            name = master.getRequestedName(default_hostname=Config.DEFAULT_VM_NAME,
                                           default_domain=Config.DEFAULT_DOMAIN)[0]
            self.assertEqual(name, inventory["vars"]["IM_MASTER_HOSTNAME"])

    def test_uploads_inventory_and_general_config_scoped_to_each_cloud(self):
        self.cm.generate_playbooks_and_hosts()
        self.assertTrue(self.inf.configured)
        self.assertEqual({"cloud-a", "cloud-b"}, set(self.uploaded))
        self.assert_controller_files("cloud-a", [self.a], self.a)
        self.assert_controller_files("cloud-b", [self.b, self.target], self.b)

    @patch("IM.ConfManager.SSHRetry")
    def test_external_override_and_managed_clouds_have_separate_files(self, ssh_retry):
        ext = _real_vm(self.inf, 3, "cloud-a")
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        ext.requested_radl.ansible_hosts = [host]
        self.inf.radl.ansible_hosts = [host]
        ssh_retry.return_value = self.controller_ssh("external")

        self.cm.generate_playbooks_and_hosts()

        self.assertTrue(self.inf.configured)
        self.assertEqual({"cloud-a", "cloud-b", "external"}, set(self.uploaded))
        self.assert_controller_files("cloud-a", [self.a], self.a)
        self.assert_controller_files("cloud-b", [self.b, self.target], self.b)
        self.assert_controller_files("external", [ext])

    def test_disabled_vm_without_controller_is_not_in_controller_files(self):
        self.target.cloud.id = "disabled-cloud"
        self.target.contextualize = Mock(return_value=False)
        self.cm.generate_playbooks_and_hosts()
        self.assertTrue(self.inf.configured)
        self.assert_controller_files("cloud-a", [self.a], self.a)
        self.assert_controller_files("cloud-b", [self.b], self.b)


class TestMulticloudPlanning(unittest.TestCase):
    def setUp(self):
        self.inf = InfrastructureInfo()
        self.disabled = _real_vm(self.inf, 0, "disabled")
        self.disabled.contextualize = Mock(return_value=False)
        self.a = _real_vm(self.inf, 1, "cloud-a")
        self.b = _real_vm(self.inf, 2, "cloud-b")
        self.worker = _real_vm(self.inf, 3, "cloud-b", public=False)

    def plan(self, threshold):
        with patch("IM.ConfManager.ConfManager.start"), patch.object(VirtualMachine, "update_status"), \
                patch("IM.InfrastructureInfo.Config.VM_NUM_USE_CTXT_DIST", threshold):
            self.inf.Contextualize(None)
        return {vm.im_id: {step: tasks for step, _, target, tasks in self.inf.ctxt_tasks.queue if target is vm}
                for vm in self.inf.vm_list}

    def test_each_controller_gets_one_ssh_barrier_ignoring_disabled_vms(self):
        planned = self.plan(100)
        self.assertEqual(["wait_all_ssh"], planned[self.a.im_id][0])
        self.assertEqual(["wait_all_ssh"], planned[self.b.im_id][0])
        self.assertEqual([], planned[self.worker.im_id][0])
        self.assertEqual({}, planned[self.disabled.im_id])

    def test_each_distributed_controller_has_its_own_facts_seed(self):
        planned = self.plan(1)
        for seed in (self.a, self.b):
            self.assertEqual(["gen_facts_cache"], planned[seed.im_id][2])
            self.assertEqual([], planned[seed.im_id][3])
        self.assertEqual([], planned[self.worker.im_id][2])
        self.assertEqual(["copy_facts_cache"], planned[self.worker.im_id][3])

    def test_external_controllers_keep_controller_local_execution_in_distributed_infrastructure(self):
        host = parse_radl("ansible ext (host = '198.51.100.1' and credentials.username = 'external')").ansible_hosts[0]
        self.b.requested_radl.ansible_hosts = [host]
        planned = self.plan(1)
        self.assertEqual(["wait_all_ssh"], planned[self.b.im_id][0])
        self.assertEqual(["main_node"], planned[self.b.im_id][4])
        self.assertEqual([], planned[self.b.im_id][2])
        self.assertEqual([], planned[self.b.im_id][3])


class TestMulticloudDistributedAgent(unittest.TestCase):
    @patch("contextualization.ctxt_agent_dist.os.path.isfile", return_value=True)
    @patch("contextualization.ctxt_agent_dist.time.sleep")
    def test_single_vm_controller_does_not_create_zero_worker_pool(self, sleep, isfile):
        from contextualization.ctxt_agent_dist import CtxtAgent
        agent = CtxtAgent("", "")
        agent.logger = Mock()
        master = {"id": 0, "master": True, "os": "linux", "ip": "192.0.2.1"}
        general = {"vms": [master], "conf_dir": "unused"}
        conf = {"tasks": ["install_ansible"], "remote_dir": "unused"}
        result = agent.contextualize_vm(general, conf, master, False)
        self.assertTrue(result["OK"])


class TestMulticloudExecution(unittest.TestCase):
    def run_contextualization(self, fail_cloud=None):
        inf = InfrastructureInfo()
        a, b = _real_vm(inf, 0, "cloud-a"), _real_vm(inf, 1, "cloud-b")
        worker = _real_vm(inf, 2, "cloud-b", public=False)
        controllers = {"cloud-a": Mock(), "cloud-b": Mock()}
        launched = []
        uploaded = {}
        for master in (a, b):
            ssh = controllers[master.cloud.id]
            master.get_ssh = Mock(return_value=ssh)

            def execute(command, *args, cloud=master.cloud.id):
                if command.startswith("nohup"):
                    launched.append(cloud)
                return "4242", "", 0

            def upload(files, cloud=master.cloud.id):
                for local, remote in files:
                    if Path(local).name == "general_info.cfg":
                        uploaded[cloud] = json.loads(Path(local).read_text())

            ssh.execute.side_effect = execute
            ssh.sftp_put_files.side_effect = upload

        def finish(vm):
            if vm.ctxt_pid:
                vm.ctxt_pid = None
                vm.configured = True
            return None

        for vm in inf.vm_list:
            vm.is_ctxt_process_running = Mock(side_effect=lambda vm=vm: finish(vm))
            vm.launch_check_ctxt_process = Mock()

        with patch("IM.ConfManager.ConfManager.start"), patch.object(VirtualMachine, "update_status"):
            inf.Contextualize(None)
        cm = inf.cm
        cm.wait_vm_running = Mock(return_value=True)
        cm.wait_vm_ssh_acccess = Mock(return_value=(True, ""))
        cm.configure_ansible = Mock(side_effect=lambda ssh, *args: ssh is not controllers.get(fail_cloud))

        queue = inf.ctxt_tasks
        adapter = Mock()
        adapter.empty.side_effect = queue.empty
        adapter.put.side_effect = queue.put
        adapter.queue = queue.queue

        def get_task():
            if queue.empty():
                cm._stop_thread = True
                return -10, 0, None, None
            return queue.get_nowait()

        adapter.get.side_effect = get_task
        inf.ctxt_tasks = adapter

        def thread(name, target, args=()):
            result = Mock(name=name)
            result.is_alive.return_value = False
            result.start.side_effect = lambda: target(*args)
            return result

        with patch("IM.ConfManager.threading.Thread", side_effect=thread), \
                patch("IM.InfrastructureList.InfrastructureList.save_data"), \
                patch.object(VirtualMachine, "update_status"), patch("IM.ConfManager.time.sleep"), \
                patch("IM.ConfManager.Config.PLAYBOOK_RETRIES", 1), \
                patch("IM.ConfManager.Config.VM_NUM_USE_CTXT_DIST", 100):
            cm.run()
        return inf, launched, uploaded

    def test_real_scheduler_bootstraps_uploads_and_dispatches_all_clouds(self):
        inf, launched, uploaded = self.run_contextualization()
        self.assertTrue(inf.is_configured())
        self.assertTrue(all(vm.is_configured() for vm in inf.vm_list))
        self.assertEqual(3, launched.count("cloud-a"))
        self.assertEqual(5, launched.count("cloud-b"))
        self.assertEqual([0], [vm["id"] for vm in uploaded["cloud-a"]["vms"]])
        self.assertEqual([1, 2], [vm["id"] for vm in uploaded["cloud-b"]["vms"]])

    def test_bootstrap_failure_keeps_global_barrier_and_does_not_dispatch_vm_tasks(self):
        inf, launched, uploaded = self.run_contextualization(fail_cloud="cloud-b")
        self.assertFalse(inf.is_configured())
        self.assertEqual([], launched)
        self.assertEqual({}, uploaded)
        self.assertEqual({"cloud-a": 0}, inf.ansible_configured_masters)


if __name__ == "__main__":
    unittest.main()
