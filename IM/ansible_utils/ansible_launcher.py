# IM - Infrastructure Manager
# Copyright (C) 2015 - GRyCAP - Universitat Politecnica de Valencia
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
#
# Some parts of this code are taken from the Ansible code
# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
#

import sys
import time
import os
from multiprocessing import Process
import subprocess
import signal
import logging
from distutils.version import LooseVersion
from ansible import errors
from ansible import __version__ as ansible_version

if ansible_version.startswith("1."):
    import ansible.playbook
    import ansible.inventory
    import ansible.constants as C
    from ansible import utils

    from .ansible_callbacks import banner, AggregateStats, PlaybookCallbacks, PlaybookRunnerCallbacks
else:
    from ansible.cli import CLI
    from ansible.parsing.dataloader import DataLoader
    try:
        # for Ansible version 2.4.0 or higher
        from ansible.vars.manager import VariableManager
        from ansible.inventory.manager import InventoryManager
    except ImportError:
        # for Ansible version 2.3.2 or lower
        from ansible.vars import VariableManager
        from ansible.inventory import Inventory
    import ansible.inventory

    from .ansible_executor_v2 import IMPlaybookExecutor


def display(msg, color=None, stderr=False, screen_only=False, log_only=False, output=None):
    if output:
        if isinstance(output, logging.Logger):
            output.info(msg)
        else:
            output.write("%s\n" % msg)
    else:
        sys.stdout.write(msg)
        sys.stdout.flush()


def colorize(lead, num, color):
    """ Print 'lead' = 'num' in 'color' """
    return "%s=%-4s" % (lead, str(num))


def hostcolor(host, stats, color=True):
    return "%-26s" % host


class AnsibleThread(Process):
    """
    Class to call the ansible playbooks in a Thread
    """

    def __init__(self, result, output, playbook_file, host=None, threads=1, pk_file=None, passwd=None, retries=1,
                 inventory_file=None, user=None, vault_pass=None, extra_vars=None):
        super(AnsibleThread, self).__init__()
        self.playbook_file = playbook_file
        self.host = host
        self.passwd = passwd
        self.threads = threads
        self.pk_file = pk_file
        self.retries = retries
        self.inventory_file = inventory_file
        self.user = user
        self.extra_vars = {}
        if extra_vars:
            self.extra_vars = extra_vars
        self.output = output
        self.result = result
        self.vault_pass = vault_pass

    def teminate(self):
        try:
            self._kill_childs()
        except:
            pass
        Process.terminate(self)

    def _get_childs(self, parent_id=None):
        if parent_id is None:
            parent_id = os.getpid()
        ps_command = subprocess.Popen("ps -o pid --ppid %d --noheaders" % parent_id, shell=True, stdout=subprocess.PIPE)
        ps_command.wait()
        ps_output = str(ps_command.stdout.read())
        childs = ps_output.strip().split("\n")[:-1]
        if childs:
            res = childs
            for child in childs:
                res.extend(self._get_childs(int(child)))
            return res
        else:
            return childs

    def _kill_childs(self):
        for pid_str in self._get_childs():
            os.kill(int(pid_str), signal.SIGTERM)
        # assure to kill all the processes using KILL signal
        time.sleep(1)
        for pid_str in self._get_childs():
            os.kill(int(pid_str), signal.SIGKILL)

    def run(self):
        try:
            output = self.output
            if isinstance(output, logging.Logger):
                output = None
            if ansible_version.startswith("1."):
                self.result.put((0, self.launch_playbook_v1(), output))
            elif ansible_version.startswith("2."):
                self.result.put((0, self.launch_playbook_v2(), output))
            else:
                display("ERROR: Unknown Ansible version.", output=self.output)
                self.result.put((0, (1, []), output))
        except errors.AnsibleError as e:
            display("ERROR: %s" % e, output=self.output)
            self.result.put((0, (1, []), output))

    def get_play_prereqs(self, options):
        if LooseVersion(ansible_version) >= LooseVersion("2.4.0"):
            # for Ansible version 2.4.0 or higher
            return self.get_play_prereqs_2_4(options)
        else:
            # for Ansible version 2.3.2 or lower
            return self.get_play_prereqs_2(options)

    def get_play_prereqs_2(self, options):
        loader = DataLoader()

        if self.vault_pass:
            loader.set_vault_password(self.vault_pass)

        variable_manager = VariableManager()
        variable_manager.extra_vars = self.extra_vars
        variable_manager.options_vars = {'ansible_version': self.version_info(ansible_version)}

        # Add this to avoid the Ansible bug:  no host vars as host is not in inventory
        # In version 2.0.1 it must be fixed
        ansible.inventory.HOSTS_PATTERNS_CACHE = {}

        inventory = Inventory(loader=loader, variable_manager=variable_manager, host_list=options.inventory)
        variable_manager.set_inventory(inventory)

        if self.host:
            inventory.subset(self.host)
        # let inventory know which playbooks are using so it can know the
        # basedirs
        inventory.set_playbook_basedir(os.path.dirname(self.playbook_file))

        return loader, inventory, variable_manager

    def get_play_prereqs_2_4(self, options):
        loader = DataLoader()

        if self.vault_pass:
            loader.set_vault_password(self.vault_pass)

        # create the inventory, and filter it based on the subset specified (if any)
        inventory = InventoryManager(loader=loader, sources=options.inventory)

        # create the variable manager, which will be shared throughout
        # the code, ensuring a consistent view of global variables
        variable_manager = VariableManager(loader=loader, inventory=inventory)
        variable_manager.extra_vars = self.extra_vars
        variable_manager.options_vars = {'ansible_version': self.version_info(ansible_version)}

        return loader, inventory, variable_manager

    def version_info(self, ansible_version_string):
        ''' return full ansible version info '''
        ansible_ver = ansible_version_string.split()[0]
        ansible_versions = ansible_ver.split('.')
        for counter in range(len(ansible_versions)):
            if ansible_versions[counter] == "":
                ansible_versions[counter] = 0
            try:
                ansible_versions[counter] = int(ansible_versions[counter])
            except:
                pass
        if len(ansible_versions) < 3:
            for counter in range(len(ansible_versions), 3):
                ansible_versions.append(0)
        return {'string': ansible_version_string.strip(),
                'full': ansible_ver,
                'major': ansible_versions[0],
                'minor': ansible_versions[1],
                'revision': ansible_versions[2]}

    def launch_playbook_v2(self):
        ''' run ansible-playbook operations v2.X'''
        # create parser for CLI options
        parser = CLI.base_parser(
            usage="%prog playbook.yml",
            connect_opts=True,
            meta_opts=True,
            runas_opts=True,
            subset_opts=True,
            check_opts=True,
            inventory_opts=True,
            runtask_opts=True,
            vault_opts=True,
            fork_opts=True,
            module_opts=True,
        )

        options, _ = parser.parse_args([])

        sshpass = None
        if not options.become_user:
            options.become_user = "root"

        if self.pk_file:
            options.private_key_file = self.pk_file
        else:
            sshpass = self.passwd

        passwords = {'conn_pass': sshpass, 'become_pass': self.passwd}

        if self.user:
            options.remote_user = self.user

        if not os.path.exists(self.playbook_file):
            raise errors.AnsibleError(
                "the playbook: %s could not be found" % self.playbook_file)
        if not os.path.isfile(self.playbook_file):
            raise errors.AnsibleError(
                "the playbook: %s does not appear to be a file" % self.playbook_file)

        if self.inventory_file:
            options.inventory = self.inventory_file

        options.forks = self.threads

        loader, inventory, variable_manager = self.get_play_prereqs(options)

        num_retries = 0
        return_code = 4
        results = None

        while return_code != 0 and num_retries < self.retries:
            time.sleep(5 * num_retries)
            num_retries += 1
            return_code = 0

            try:
                # create the playbook executor, which manages running the plays
                # via a task queue manager
                pbex = IMPlaybookExecutor(playbooks=[self.playbook_file],
                                          inventory=inventory,
                                          variable_manager=variable_manager,
                                          loader=loader,
                                          options=options,
                                          passwords=passwords,
                                          output=self.output)

                return_code = pbex.run()

            except errors.AnsibleError as e:
                display("ERROR: %s" % e, output=self.output)
                return_code = 1

            if return_code != 0:
                display("ERROR executing playbook (%s/%s)" %
                        (num_retries, self.retries), output=self.output)

        return (return_code, results)

    def launch_playbook_v1(self):
        ''' run ansible-playbook operations v1.X'''
        # create parser for CLI options
        parser = utils.base_parser(
            constants=C,
            usage="%prog playbook.yml",
            connect_opts=True,
            runas_opts=True,
            subset_opts=True,
            check_opts=True,
            diff_opts=True
        )

        options, _ = parser.parse_args([])

        sshpass = None
        if self.pk_file:
            options.private_key_file = self.pk_file
        else:
            sshpass = self.passwd

        if self.user:
            remote_user = self.user
        else:
            remote_user = options.remote_user

        if not os.path.exists(self.playbook_file):
            raise errors.AnsibleError(
                "the playbook: %s could not be found" % self.playbook_file)
        if not os.path.isfile(self.playbook_file):
            raise errors.AnsibleError(
                "the playbook: %s does not appear to be a file" % self.playbook_file)

        num_retries = 0
        return_code = 4
        hosts_with_errors = []
        while return_code != 0 and num_retries < self.retries:
            time.sleep(5 * num_retries)
            num_retries += 1
            return_code = 0

            if self.inventory_file:
                inventory = ansible.inventory.Inventory(self.inventory_file)
            else:
                inventory = ansible.inventory.Inventory(options.inventory)

            if self.host:
                inventory.subset(self.host)
            # let inventory know which playbooks are using so it can know the
            # basedirs
            inventory.set_playbook_basedir(os.path.dirname(self.playbook_file))

            stats = AggregateStats()
            playbook_cb = PlaybookCallbacks(
                verbose=utils.VERBOSITY, output=self.output)
            runner_cb = PlaybookRunnerCallbacks(
                stats, verbose=utils.VERBOSITY, output=self.output)

            pb = ansible.playbook.PlayBook(
                playbook=self.playbook_file,
                module_path=options.module_path,
                inventory=inventory,
                forks=self.threads,
                remote_user=remote_user,
                remote_pass=sshpass,
                callbacks=playbook_cb,
                runner_callbacks=runner_cb,
                stats=stats,
                extra_vars=self.extra_vars,
                private_key_file=options.private_key_file,
                only_tags=['all']
            )

            try:
                failed_hosts = []
                unreachable_hosts = []

                pb.run()

                hosts = sorted(pb.stats.processed.keys())
                display(banner("PLAY RECAP"), output=self.output)
                playbook_cb.on_stats(pb.stats)

                for h in hosts:
                    t = pb.stats.summarize(h)
                    if t['failures'] > 0:
                        failed_hosts.append(h)
                    if t['unreachable'] > 0:
                        unreachable_hosts.append(h)

                hosts_with_errors = failed_hosts + unreachable_hosts

                for h in hosts:
                    t = pb.stats.summarize(h)

                    display("%s : %s %s %s %s" % (
                        hostcolor(h, t),
                        colorize('ok', t['ok'], 'green'),
                        colorize('changed', t['changed'], 'yellow'),
                        colorize('unreachable', t['unreachable'], 'red'),
                        colorize('failed', t['failures'], 'red')),
                        screen_only=True, output=self.output
                    )

                    display("%s : %s %s %s %s" % (
                        hostcolor(h, t, False),
                        colorize('ok', t['ok'], None),
                        colorize('changed', t['changed'], None),
                        colorize('unreachable', t['unreachable'], None),
                        colorize('failed', t['failures'], None)),
                        log_only=True, output=self.output
                    )

                if len(failed_hosts) > 0:
                    return_code = 2
                if len(unreachable_hosts) > 0:
                    return_code = 3

            except errors.AnsibleError as e:
                display("ERROR: %s" % e, color='red', output=self.output)
                return_code = 1

            if return_code != 0:
                display("ERROR executing playbook (%s/%s)" %
                        (num_retries, self.retries), color='red', output=self.output)

        return (return_code, hosts_with_errors)
