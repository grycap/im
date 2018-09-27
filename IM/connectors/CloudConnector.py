import logging
import subprocess
import shutil
import tempfile
import time
import yaml
from IM.config import Config


class CloudConnector:
    """
    Base class to all the Cloud connectors

    Arguments:
            - cloud_info(:py:class:`IM.CloudInfo`): Data about the Cloud Provider
    """

    def __init__(self, cloud_info, inf):
        self.cloud = cloud_info
        """Data about the Cloud Provider."""
        self.inf = inf
        """Infrastructure this CloudConnector is associated with."""
        self.logger = logging.getLogger('CloudConnector')
        """Logger object."""
        self.error_messages = ""
        """String with error messages to be shown to the user."""
        self.verify_ssl = Config.VERIFI_SSL
        """Verify SSL connections """
        if not self.verify_ssl:
            try:
                # To avoid annoying InsecureRequestWarning messages in some Connectors
                import requests.packages
                from requests.packages.urllib3.exceptions import InsecureRequestWarning
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            except:
                pass

    def concreteSystem(self, radl_system, auth_data):
        """
        Return a list of compatible systems with the cloud

        Arguments:

           - radl_system(:py:class:`radl.system`): a system.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns(list of system): list of compatible systems.
        """

        return [radl_system.clone()]

    def updateVMInfo(self, vm, auth_data):
        """
        Updates the information of a VM

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information to update.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a :py:class:`IM.VirtualMachine` with the updated information if
             the operation finished successfully or a str with an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def alterVM(self, vm, radl, auth_data):
        """
        Modifies the features of a VM

        Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to modify.
                - radl(str): RADL document with the VM features to modify.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
                - The first value is True if the operation finished successfully or false otherwise.
                - The second value is a :py:class:`IM.VirtualMachine` with the modified information if the operation
                  finished successfully or a str with an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        """
        Launch a set of VMs to the Cloud provider

        Args:

        - inf(InfrastructureInfo): InfrastructureInfo object the VM is part of.
        - radl(RADL): RADL document.
        - num_vm(int): number of instances to deploy.
        - auth_data(Authentication): Authentication data to access cloud provider.

                Returns: a list of tuples with the format (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a :py:class:`IM.VirtualMachine` of the launched VMs if the operation
             finished successfully or a str with an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def launch_with_retry(self, inf, radl, requested_radl, num_vm, auth_data, max_num, delay):
        """
        Launch a set of VMs to the Cloud provider with a set of retries in case of failure

        Args:

        - inf(InfrastructureInfo): InfrastructureInfo object the VM is part of.
        - radl(RADL): RADL document.
        - num_vm(int): number of instances to deploy.
        - auth_data(Authentication): Authentication data to access cloud provider.
        - max_num: Number of retries.
        - delay: a sleep time between retries

                Returns: a list of tuples with the format (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a :py:class:`IM.VirtualMachine` of the launched VMs if the operation
             finished successfully or a str with an error message otherwise.
        """
        res_ok = []
        res_err = {}
        retries = 0
        while len(res_ok) < num_vm and retries < max_num:
            if retries != 0:
                time.sleep(delay)
            retries += 1
            err_count = 0
            try:
                vms = self.launch(inf, radl, requested_radl, num_vm - len(res_ok), auth_data)
            except Exception as ex:
                self.log_exception("Error launching some of the VMs")
                vms = []
                for _ in range(num_vm - len(res_ok)):
                    vms.append((False, "Error: %s" % ex))
            for success, vm in vms:
                if success:
                    res_ok.append(vm)
                else:
                    if err_count not in res_err:
                        res_err[err_count] = [vm]
                    else:
                        res_err[err_count].append(vm)
                    err_count += 1

        res = []
        for elem in res_ok:
            res.append((True, elem))

        for i in range(num_vm - len(res_ok)):
            msgs = ""
            for n, msg in enumerate(res_err[i]):
                msgs += "Attempt %d: %s\n" % (n + 1, msg)
            res.append((False, msgs))

        return res

    def finalize(self, vm, last, auth_data):
        """ Terminates a VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to terminate.
                - last(boolean): Flag that specifies that the VM is that last one, to clean all related resources.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the removed VM if the operation finished successfully
             or an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def start(self, vm, auth_data):
        """ Starts a (previously stopped) VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to start.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the started VM if the operation finished successfully
             or an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def stop(self, vm, auth_data):
        """ Stops (but not finalizes) a VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to stop.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the stopped VM if the operation finished successfully
             or an error message otherwise.

        """

        raise NotImplementedError("Should have implemented this")

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        """
        Create a snapshot of the specified num disk in a virtual machine.

        Arguments:
          - vm(:py:class:`IM.VirtualMachine`): VM to stop.
          - disk_num(int): Number of the disk.
          - image_name(str): Name of the new image.
          - auto_delete(bool): A flag to specify that the snapshot will be deleted when the
            infrastructure is destroyed.
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
          - The first value is True if the operation finished successfully or false otherwise.
          - The second value is a str with the url of the new image if the operation finished successfully
             or an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def delete_image(self, image_url, auth_data):
        """
        Delete an image on the cloud provider.

        Arguments:
          - image_url(str): URL of the image to delete.
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
          - The first value is True if the operation finished successfully or false otherwise.
          - The second value is an empty str if the operation finished successfully
             or an error message otherwise.
        """
        raise NotImplementedError("Should have implemented this")

    def keygen(self):
        """
        Generates a keypair using the ssh-keygen command and returns a tuple (public, private)
        """
        tmp_dir = tempfile.mkdtemp()
        pk_file = tmp_dir + "/im-ssh-key"
        command = 'ssh-keygen -t rsa -b 2048 -q -N "" -f ' + pk_file
        p = subprocess.Popen(command, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        (out, err) = p.communicate()
        if p.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            self.log_error("Error executing ssh-keygen: " + out + err)
            return (None, None)
        else:
            public = None
            private = None
            try:
                with open(pk_file) as f:
                    private = f.read().strip()
            except:
                self.log_exception("Error reading private_key file.")

            try:
                with open(pk_file + ".pub") as f:
                    public = f.read().strip()
            except:
                self.log_exception("Error reading public_key file.")

            shutil.rmtree(tmp_dir, ignore_errors=True)
            return (public, private)

    def delete_snapshots(self, vm, auth_data):
        """
        Delete the snapshots created with auto_delete option
        """
        try:
            for image_url in vm.inf.snapshots:
                self.log_debug("Deleting snapshot: %s" % image_url)
                success, msg = self.delete_image(image_url, auth_data)
                if not success:
                    self.log_error("Error deleting snapshot: %s" % msg)
        except:
            self.log_exception("Error deleting snapshots.")

    def _gen_cloud_config(self, public_key, user, cloud_config_str=None):
        """
        Generate the cloud-config file to be used in the user_data of the VM
        """
        user_data = {}
        user_data['name'] = user
        user_data['sudo'] = "ALL=(ALL) NOPASSWD:ALL"
        user_data['lock-passwd'] = True
        user_data['ssh-import-id'] = user
        user_data['ssh-authorized-keys'] = [public_key.strip()]
        config_data = {"users": [user_data]}
        if cloud_config_str:
            cloud_config = yaml.load(cloud_config_str)
            # If the client has included the "users" section, append it to the current one
            if 'users' in cloud_config:
                config_data["users"].extend(cloud_config['users'])
                del cloud_config["users"]

            config_data.update(cloud_config)

        return yaml.dump(config_data, default_flow_style=False, width=512)

    def get_cloud_init_data(self, radl, vm=None, public_key=None, user=None):
        """
        Get the cloud init data specified by the user in the RADL
        """
        configure_name = None
        if radl.contextualize.items:
            system_name = radl.systems[0].name

            for item in radl.contextualize.items.values():
                if item.system == system_name and item.get_ctxt_tool() == "cloud_init":
                    configure_name = item.configure

        if configure_name:
            cloud_init_str = radl.get_configure_by_name(configure_name).recipes
        else:
            cloud_init_str = None

        res = None
        # Only for those VMs with private IP
        if Config.SSH_REVERSE_TUNNELS and vm and not vm.hasPublicNet():
            res = self._add_curl_cloud_init_data(vm, cloud_init_str)

        if public_key:
            res = self._gen_cloud_config(public_key, user, res)

        if res:
            return "#cloud-config\n%s" % res
        else:
            return res

    def _add_curl_cloud_init_data(self, vm, cloud_init_str):
        if cloud_init_str:
            cloud_config = yaml.load(cloud_init_str)
        else:
            cloud_config = {}
        # If the client has included the "users" section, append it to the current one
        if 'packages' in cloud_config:
            cloud_config["packages"].extend(["curl", "sshpass"])
        else:
            cloud_config["packages"] = ["curl", "sshpass"]

        curl_command = vm.get_boot_curl_commands()
        if 'runcmd' in cloud_config:
            cloud_config["runcmd"].extend(curl_command)
        else:
            cloud_config["runcmd"] = curl_command

        return yaml.dump(cloud_config, default_flow_style=False, width=512)

    def log_msg(self, level, msg, exc_info=0):
        msg = "Inf ID: %s: %s" % (self.inf.id, msg)
        self.logger.log(level, msg, exc_info=exc_info)

    def log_error(self, msg):
        self.log_msg(logging.ERROR, msg)

    def log_debug(self, msg):
        self.log_msg(logging.DEBUG, msg)

    def log_warn(self, msg):
        self.log_msg(logging.WARNING, msg)

    def log_exception(self, msg):
        self.log_msg(logging.ERROR, msg, exc_info=1)

    def log_info(self, msg):
        self.log_msg(logging.INFO, msg)
