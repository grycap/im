import logging
import subprocess
import shutil
import tempfile


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
