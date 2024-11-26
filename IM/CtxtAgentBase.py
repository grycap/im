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
""" Base Class for the Contextualization Agent """
import time
import subprocess
import socket
import logging
import json
import os
import re
import yaml
from multiprocessing import Queue

from IM.SSH import SSH, AuthenticationException


class CtxtAgentBase:
    """ Base Class for the Contextualization Agent """

    SSH_WAIT_TIMEOUT = 600
    PK_FILE = "/tmp/ansible_key"  # nosec
    # This value enables to retry the playbooks to avoid some SSH connectivity problems
    # The minimum value is 1. This value will be in the data file generated by
    # the ConfManager
    PLAYBOOK_RETRIES = 1
    INTERNAL_PLAYBOOK_RETRIES = 1

    def __init__(self, conf_data_filename):
        self.logger = None
        self.conf_data_filename = conf_data_filename

    def init_logger(self, log_file):
        # Root logger: is used by paramiko
        logging.basicConfig(filename=log_file,
                            level=logging.WARNING,
                            # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            format='%(message)s',
                            datefmt='%m-%d-%Y %H:%M:%S')
        # ctxt_agent logger
        self.logger = logging.getLogger('ctxt_agent')
        self.logger.setLevel(logging.DEBUG)

    def wait_winrm_access(self, vm, max_wait=None):
        """
         Test the WinRM access to the VM
        """
        if max_wait is None:
            max_wait = CtxtAgentBase.SSH_WAIT_TIMEOUT
        delay = 10
        wait = 0
        last_tested_private = False
        while wait < max_wait:
            if 'ctxt_ip' in vm:
                vm_ip = vm['ctxt_ip']
            elif 'private_ip' in vm and not last_tested_private:
                # First test the private one
                vm_ip = vm['private_ip']
                last_tested_private = True
            else:
                vm_ip = vm['ip']
                last_tested_private = False
            try:
                self.logger.debug("Testing WinRM access to VM: " + vm_ip)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((vm_ip, vm['remote_port']))
            except Exception:
                self.logger.exception("Error connecting with WinRM with: " + vm_ip)
                result = -1

            if result == 0:
                vm['ctxt_ip'] = vm_ip
                return True
            else:
                wait += delay
                time.sleep(delay)

    def test_ssh(self, vm, vm_ip, remote_port, quiet, delay=10, proxy_host=None):
        """
         Test the SSH access to the VM
         return: init, new or pk_file or None if it fails
        """
        success = False
        res = None
        if not quiet:
            if proxy_host:
                self.logger.debug("Testing SSH access to VM: %s:%s (via: %s)" % (vm_ip, remote_port, proxy_host.host))
            else:
                self.logger.debug("Testing SSH access to VM: %s:%s" % (vm_ip, remote_port))
        try:
            ssh_client = SSH(vm_ip, vm['user'], vm['passwd'], vm['private_key'], remote_port, proxy_host=proxy_host)
            success = ssh_client.test_connectivity(delay)
            res = 'init'
        except AuthenticationException:
            try_ansible_key = True
            if 'new_passwd' in vm:
                try_ansible_key = False
                # If the process of changing credentials has finished in the
                # VM, we must use the new ones
                if not quiet:
                    self.logger.debug("Error connecting with SSH with initial credentials with: " +
                                      vm_ip + ". Try to use new ones.")
                try:
                    ssh_client = SSH(vm_ip, vm['user'], vm['new_passwd'], vm['private_key'],
                                     remote_port, proxy_host=proxy_host)
                    success = ssh_client.test_connectivity()
                    res = "new"
                except AuthenticationException:
                    try_ansible_key = True
                except Exception:
                    if not quiet:
                        self.logger.exception("Error connecting with SSH with: " + vm_ip)
                    success = False

            if try_ansible_key:
                # In some very special cases the last two cases fail, so check
                # if the ansible key works
                if not quiet:
                    self.logger.debug("Error connecting with SSH with initial credentials with: " +
                                      vm_ip + ". Try to ansible_key.")
                try:
                    ssh_client = SSH(vm_ip, vm['user'], None, CtxtAgentBase.PK_FILE, remote_port, proxy_host=proxy_host)
                    success = ssh_client.test_connectivity()
                    res = 'pk_file'
                except Exception:
                    if not quiet:
                        self.logger.exception("Error connecting with SSH with: " + vm_ip)
                    success = False
        except Exception:
            if not quiet:
                self.logger.exception("Error connecting with SSH with: " + vm_ip)
            success = False

        return success, res

    def wait_ssh_access(self, vm, delay=10, max_wait=None, quiet=False):
        """
         Wait the SSH access to the VM
         return: init, new or pk_file or None if it fails
        """
        if max_wait is None:
            max_wait = CtxtAgentBase.SSH_WAIT_TIMEOUT
        wait = 0
        success = False
        res = None
        while wait < max_wait:
            if 'ctxt_ip' in vm and 'ctxt_port' in vm:
                # These have been previously tested and worked use it
                vm_ip = vm['ctxt_ip']
                remote_port = vm['ctxt_port']
                success, res = self.test_ssh(vm, vm['ctxt_ip'], vm['ctxt_port'], quiet)
            else:
                # First test the private one
                if not success and 'private_ip' in vm:
                    vm_ip = vm['private_ip']
                    remote_port = vm['remote_port']
                    success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)
                    if not success and remote_port != 22:
                        remote_port = 22
                        success, res = self.test_ssh(vm, vm_ip, 22, quiet)

                # if not use the default one
                if not success:
                    vm_ip = vm['ip']
                    remote_port = vm['remote_port']
                    success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)
                    if not success and remote_port != 22:
                        remote_port = 22
                        success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)

                # if not use the reverse port
                if not success and 'reverse_port' in vm:
                    vm_ip = '127.0.0.1'
                    remote_port = vm['reverse_port']
                    success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)

                # In case os using a proxy host
                if not success and 'proxy_host' in vm:
                    proxy = vm['proxy_host']
                    proxy_host = SSH(proxy['host'], proxy['user'], proxy['passwd'], proxy['private_key'], proxy['port'])
                    success, res = self.test_ssh(vm, vm['ip'], vm['remote_port'], quiet, proxy_host=proxy_host)
                    return "proxy_host"

            wait += delay

            if success:
                vm['ctxt_ip'] = vm_ip
                vm['ctxt_port'] = remote_port
                return res
            else:
                time.sleep(delay)

        return None

    @staticmethod
    def run_command(command, timeout=None, poll_delay=5):
        """
         Function to run a command
        """
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=True)  # nosec

            if timeout is not None:
                wait = 0
                while p.poll() is None and wait < timeout:
                    time.sleep(poll_delay)
                    wait += poll_delay

                if p.poll() is None:
                    p.kill()
                    return "TIMEOUT"

            (out, err) = p.communicate()

            if p.returncode != 0:
                return "ERROR: " + err + out
            else:
                return out
        except Exception as ex:
            return "ERROR: Exception msg: " + str(ex)

    @staticmethod
    def get_ssh(vm, pk_file, changed_pass=None, use_proxy=False):
        """
        Get VM ssh connection
        """
        private_key = vm['private_key']
        if pk_file:
            private_key = pk_file
        proxy_host = None
        if use_proxy and 'proxy_host' in vm:
            proxy = vm['proxy_host']
            proxy_host = SSH(proxy['host'], proxy['user'], proxy['passwd'], proxy['private_key'], proxy['port'])
        return SSH(vm.get('ctxt_ip', vm.get('ip')), vm['user'], vm['passwd'],
                   private_key, vm.get('ctxt_port', vm.get('remote_port')), proxy_host=proxy_host)

    def removeRequiretty(self, vm, pk_file, changed_pass=None, use_proxy=False):
        """
        Remove requiretty option from sudoers
        """
        if not vm['master']:
            self.logger.info("Removing requiretty to VM: " + vm['ip'])
            try:
                ssh_client = self.get_ssh(vm, pk_file, changed_pass, use_proxy=use_proxy)
                # Activate tty mode to avoid some problems with sudo in REL
                ssh_client.tty = True
                sudo_pass = ""
                if ssh_client.password:
                    sudo_pass = "echo '" + ssh_client.password + "' | "
                res = ssh_client.execute_timeout(
                    sudo_pass + "sudo -S sed -i 's/.*requiretty$/#Defaults requiretty/' /etc/sudoers", 30)
                if res is not None:
                    (stdout, stderr, code) = res
                    self.logger.debug("OUT: " + stdout + stderr)
                    return code == 0
                else:
                    self.logger.error("No output.")
                    return False
            except Exception:
                self.logger.exception("Error removing requiretty to VM: " + vm['ip'])
                return False
        else:
            return True

    def add_proxy_host_line(self, vm_data):
        """
        Add the ProxyHost SSH command to the VM in the inventory file
        """
        with open(self.conf_data_filename) as f:
            general_conf_data = json.load(f)
        filename = general_conf_data['conf_dir'] + "/hosts"

        proxy = vm_data['proxy_host']
        if proxy['private_key']:
            # we must create it in the localhost to use it later with ansible
            priv_key_filename = "/var/tmp/%s_%s_%s.pem" % (proxy['user'],
                                                           vm_data['user'],
                                                           vm_data['ip'])
            with open(priv_key_filename, 'w') as f:
                f.write(proxy['private_key'])
            os.chmod(priv_key_filename, 0o600)

            ssh_options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

            cmd = "ssh -W %%h:%%p -i %s -p %d %s %s@%s" % (priv_key_filename,
                                                           proxy['port'],
                                                           ssh_options,
                                                           proxy['user'],
                                                           proxy['host'])
        else:
            cmd = "sshpass -p %s ssh -W %%h:%%p -p %d %s %s@%s" % (proxy['password'],
                                                                   proxy['port'],
                                                                   ssh_options,
                                                                   proxy['user'],
                                                                   proxy['host'])
        proxy_command = "ansible_ssh_extra_args=\"%s -oProxyCommand='%s'\"" % (ssh_options, cmd)

        with open(filename) as f:
            inventoy_data = ""
            for line in f:
                if line.startswith("%s_%s " % (vm_data['ip'], vm_data['id'])) and "ProxyCommand" not in line:
                    line = re.sub(" ansible_host=%s " % vm_data['ip'],
                                  " ansible_host=%s %s " % (vm_data['ip'], proxy_command), line)

                inventoy_data += line

        with open(filename, 'w+') as f:
            f.write(inventoy_data)

    def replace_vm_ip(self, vm_data, rep=False):
        """
        Add the Ctxt IP with the one that is actually working
        in the inventory and in the general info file
        """
        with open(self.conf_data_filename) as f:
            general_conf_data = json.load(f)

        for vm in general_conf_data['vms']:
            if vm['id'] == vm_data['id']:
                vm['ctxt_ip'] = vm_data['ctxt_ip']
                vm['ctxt_port'] = vm_data['ctxt_port']

        conf_data_filename = self.conf_data_filename
        if rep:
            conf_data_filename = conf_data_filename + ".rep"
        with open(conf_data_filename, 'w+') as f:
            json.dump(general_conf_data, f, indent=2)

        # Now in the ansible inventory
        filename = general_conf_data['conf_dir'] + "/hosts"
        with open(filename) as f:
            inventoy_data = ""
            for line in f:
                if line.startswith("%s_%s " % (vm_data['ip'], vm_data['id'])):
                    line = re.sub(" ansible_host=%s " % vm_data['ip'],
                                  " ansible_host=%s " % vm_data['ctxt_ip'], line)
                    line = re.sub(" ansible_ssh_host=%s " % vm_data['ip'],
                                  " ansible_ssh_host=%s " % vm_data['ctxt_ip'], line)
                    line = re.sub(" ansible_port=%s " % vm_data['remote_port'],
                                  " ansible_port=%s " % vm_data['ctxt_port'], line)
                    line = re.sub(" ansible_ssh_port=%s " % vm_data['remote_port'],
                                  " ansible_ssh_port=%s " % vm_data['ctxt_port'], line)
                inventoy_data += line

        with open(filename, 'w+') as f:
            f.write(inventoy_data)

    def changeVMCredentials(self, vm, pk_file, use_proxy=False):
        """
        Update VM credentials
        """
        if vm['os'] == "windows":
            if 'passwd' in vm and vm['passwd'] and 'new_passwd' in vm and vm['new_passwd']:
                try:
                    import winrm
                except Exception:
                    self.logger.exception("Error importing winrm.")
                    return False
                try:
                    url = "https://" + vm['ip'] + ":5986"
                    s = winrm.Session(url, auth=(vm['user'], vm['passwd']), server_cert_validation='ignore')
                    r = s.run_cmd('net', ['user', vm['user'], vm['new_passwd']])

                    # this part of the code is never reached ...
                    if r.status_code == 0:
                        vm['passwd'] = vm['new_passwd']
                        return True
                    else:
                        self.logger.error("Error changing password to Windows VM: " + r.std_out)
                        return False
                except winrm.exceptions.AuthenticationError:
                    # if the password is correctly changed the command returns this
                    # error
                    try:
                        # let's check that the new password works
                        s = winrm.Session(url, auth=(vm['user'], vm['new_passwd']), server_cert_validation='ignore')
                        r = s.run_cmd('echo', ['OK'])
                        if r.status_code == 0:
                            vm['passwd'] = vm['new_passwd']
                            return True
                        else:
                            self.logger.error("Error changing password to Windows VM: " + r.std_out)
                            return False
                    except Exception:
                        self.logger.exception("Error changing password to Windows VM: " + vm['ip'] + ".")
                        return False
                except Exception:
                    self.logger.exception("Error changing password to Windows VM: " + vm['ip'] + ".")
                    return False
        else:  # Linux VMs
            # Check if we must change user credentials in the VM
            if 'passwd' in vm and vm['passwd'] and 'new_passwd' in vm and vm['new_passwd']:
                self.logger.info("Changing password to VM: " + vm['ip'])
                try:
                    ssh_client = self.get_ssh(vm, pk_file, False, use_proxy=use_proxy)

                    sudo_pass = ""
                    if ssh_client.password:
                        sudo_pass = "echo '" + ssh_client.password + "' | "
                    (out, err, code) = ssh_client.execute(sudo_pass + 'sudo -S bash -c \'echo "' +
                                                          vm['user'] + ':' + vm['new_passwd'] +
                                                          '" | /usr/sbin/chpasswd && echo "OK"\' 2> /dev/null')
                except Exception:
                    self.logger.exception("Error changing password to VM: " + vm['ip'] + ".")
                    return False

                if code == 0:
                    vm['passwd'] = vm['new_passwd']
                    return True
                else:
                    self.logger.error("Error changing password to VM: " + vm['ip'] + ". " + out + err)
                    return False

            if 'new_public_key' in vm and vm['new_public_key'] and 'new_private_key' in vm and vm['new_private_key']:
                self.logger.info("Changing public key to VM: " + vm['ip'])
                try:
                    ssh_client = self.get_ssh(vm, pk_file, False, use_proxy=use_proxy)
                    (out, err, code) = ssh_client.execute_timeout('echo ' + vm['new_public_key'] +
                                                                  ' >> .ssh/authorized_keys', 5)
                except Exception:
                    self.logger.exception("Error changing public key to VM: " + vm['ip'] + ".")
                    return False

                if code != 0:
                    self.logger.error("Error changing public key to VM:: " + vm['ip'] + ". " + out + err)
                    return False
                else:
                    vm['private_key'] = vm['new_private_key']
                    return True

        return False

    @staticmethod
    def add_nat_gateway_tasks(playbook):
        """
        Add tasks to enable NAT (Tested in GCE instances)
        https://cloud.google.com/vpc/docs/special-configurations
        """
        play_dir = os.path.dirname(playbook)
        play_filename = os.path.basename(playbook)
        new_playbook = os.path.join(play_dir, "nat_" + play_filename)

        with open(playbook) as f:
            yaml_data = yaml.safe_load(f)

            task = {"raw": ("sudo sysctl -w net.ipv4.ip_forward=1; "
                            "sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; "
                            "sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; "
                            "sudo iptables -t nat -D POSTROUTING -o ens4 -j MASQUERADE; "
                            "sudo iptables -t nat -A POSTROUTING -o ens4 -j MASQUERADE")}
            task["name"] = "Activate NAT Gateway"
            task["become"] = "yes"
            task["ignore_errors"] = "yes"
            yaml_data[0]['tasks'].append(task)

            with open(new_playbook, 'w+') as f:
                yaml.safe_dump(yaml_data, f)

        return new_playbook

    def install_ansible_roles(self, general_conf_data, playbook):
        new_playbook = playbook
        if (('ansible_roles' in general_conf_data and general_conf_data['ansible_roles']) or
                ('ansible_collections' in general_conf_data and general_conf_data['ansible_collections'])):
            play_dir = os.path.dirname(playbook)
            play_filename = os.path.basename(playbook)
            new_playbook = os.path.join(play_dir, "mod_" + play_filename)

            with open(playbook) as f:
                yaml_data = yaml.safe_load(f)

            # First add collections
            galaxy_collections = []
            if 'ansible_collections' in general_conf_data and general_conf_data['ansible_collections']:
                for galaxy_name in general_conf_data['ansible_collections']:
                    if galaxy_name:
                        self.logger.debug("Install %s collection with ansible-galaxy.", galaxy_name)

                        parts = galaxy_name.split(",")
                        if len(parts) > 1:
                            name = parts[0]
                            version = parts[1]
                            dep = {"name": name, "version": version}
                        else:
                            dep = {"name": galaxy_name}

                        galaxy_collections.append(dep)

            if galaxy_collections:
                now = str(int(time.time() * 100))
                filename = "/tmp/galaxy_collections_%s.yml" % now
                yaml_deps = yaml.safe_dump({"collections": galaxy_collections}, default_flow_style=True)
                self.logger.debug("Galaxy collections file: %s" % yaml_deps)
                task = {"copy": 'dest=%s content="%s"' % (filename, yaml_deps)}
                task["name"] = "Create YAML file to install the collections with ansible-galaxy"
                yaml_data[0]['tasks'].append(task)

                task = {"command": "/var/tmp/.ansible/bin/ansible-galaxy collection install -c -r %s" % filename}
                task["name"] = "Install galaxy collections"
                task["become"] = "yes"
                task["register"] = "collections_install"
                task["until"] = "collections_install is not failed"
                task["retries"] = "5"
                task["delay"] = "10"
                # Some times ansible is installed at /usr/local/bin and it is not in root path
                task["environment"] = [{"PATH": "{{ ansible_env.PATH }}:/usr/local/bin"}]
                yaml_data[0]['tasks'].append(task)

            # and then add roles
            galaxy_dependencies = []
            needs_git = False
            if 'ansible_roles' in general_conf_data and general_conf_data['ansible_roles']:
                for galaxy_name in general_conf_data['ansible_roles']:
                    if galaxy_name:
                        self.logger.debug("Install %s with ansible-galaxy.", galaxy_name)

                        if galaxy_name.startswith("git"):
                            needs_git = True

                        parts = galaxy_name.split("|")
                        if len(parts) > 1:
                            url = parts[0]
                            rolename = parts[1]
                            dep = {"src": url, "name": rolename}
                        else:
                            url = rolename = galaxy_name
                            dep = {"src": url}

                        parts = url.split(",")
                        if len(parts) > 1:
                            url = parts[0]
                            version = parts[1]
                            dep = {"src": url, "version": version}

                        galaxy_dependencies.append(dep)

            if needs_git:
                task = {"package": "name=git state=present"}
                task["name"] = "Install git"
                task["become"] = "yes"
                yaml_data[0]['tasks'].append(task)

            if galaxy_dependencies:
                now = str(int(time.time() * 100))
                filename = "/tmp/galaxy_roles_%s.yml" % now
                yaml_deps = yaml.safe_dump(galaxy_dependencies, default_flow_style=True)
                self.logger.debug("Galaxy depencies file: %s" % yaml_deps)
                task = {"copy": 'dest=%s content="%s"' % (filename, yaml_deps)}
                task["name"] = "Create YAML file to install the roles with ansible-galaxy"
                yaml_data[0]['tasks'].append(task)

                task = {"command": "/var/tmp/.ansible/bin/ansible-galaxy install -c -r %s" % filename}
                task["name"] = "Install galaxy roles"
                task["become"] = "yes"
                task["register"] = "roles_install"
                task["until"] = "roles_install is not failed"
                task["retries"] = "5"
                task["delay"] = "10"
                # Some times ansible is installed at /usr/local/bin and it is not in root path
                task["environment"] = [{"PATH": "{{ ansible_env.PATH }}:/usr/local/bin"}]
                yaml_data[0]['tasks'].append(task)

            with open(new_playbook, 'w+') as f:
                yaml.safe_dump(yaml_data, f)

        return new_playbook

    def LaunchAnsiblePlaybook(self, output, remote_dir, playbook_file, vm, threads, inventory_file,
                              pk_file, retries, change_pass_ok, vault_pass):
        self.logger.debug('Call Ansible')

        extra_vars = {'IM_HOST': vm['ip'] + "_" + str(vm['id'])}
        user = None
        if vm['os'] == "windows":
            gen_pk_file = None
            passwd = vm['passwd']
            if 'new_passwd' in vm and vm['new_passwd'] and change_pass_ok:
                passwd = vm['new_passwd']
        else:
            passwd = vm['passwd']
            if 'new_passwd' in vm and vm['new_passwd'] and change_pass_ok:
                passwd = vm['new_passwd']
            if pk_file:
                gen_pk_file = pk_file
            else:
                if vm['private_key'] and not vm['passwd']:
                    gen_pk_file = "/tmp/pk_" + vm['ip'] + ".pem"
                    pk_out = open(gen_pk_file, 'w')
                    pk_out.write(vm['private_key'])
                    pk_out.close()
                    os.chmod(gen_pk_file, 0o600)
                else:
                    gen_pk_file = None

        # Set local_tmp dir different for any VM
        os.environ['DEFAULT_LOCAL_TMP'] = remote_dir + "/.ansible_tmp"
        # it must be set before doing the import
        from IM.ansible_utils.ansible_launcher import AnsibleThread

        result = Queue()
        t = AnsibleThread(result, output, playbook_file, threads, gen_pk_file,
                          passwd, retries, inventory_file, user, vault_pass, extra_vars)
        t.start()
        return (t, result)
