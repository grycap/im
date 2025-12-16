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
# GNU General Public License for more/etc/sudoers details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Some parts of this code are taken from the Ansible code
# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
#
# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import tempfile
import shutil
from ansible import constants as C

from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.playbook import Playbook
from ansible.template import Templar
from ansible.plugins.loader import callback_loader
from ansible.executor.task_queue_manager import TaskQueueManager
from IM.ansible_utils.callback_plugins.im_callback import CallbackModule, CallbackContext


class IMPlaybookExecutor(PlaybookExecutor):
    '''
    Simplified version of the PlaybookExecutor
    '''

    def __init__(self, playbook, inventory, variable_manager,
                 loader, options, passwords, output):
        self._playbook = playbook
        self._inventory = inventory
        self._variable_manager = variable_manager
        self._loader = loader
        self._options = options
        self.passwords = passwords
        self._unreachable_hosts = dict()

        try:
            self._tqm = TaskQueueManager(inventory=inventory,
                                         variable_manager=variable_manager,
                                         loader=loader, options=options,
                                         passwords=self.passwords,
                                         stdout_callback=CallbackModule(output))
        except TypeError:
            try:
                # In case of ansible 2.8 options parameter has been removed
                self._tqm = TaskQueueManager(inventory=inventory,
                                             variable_manager=variable_manager,
                                             loader=loader,
                                             passwords=self.passwords,
                                             stdout_callback=CallbackModule(output))
            except TypeError:
                # In case of ansible 2.19 stdout_callback parameter has been changed to stdout_callback_name
                # and the way to load the callbacks
                CallbackContext.executor = self
                CallbackContext.config = {"output": output}
                base_dir = os.path.dirname(__file__)
                callback_dir = os.path.abspath(os.path.join(base_dir, "callback_plugins"))
                callback_loader.add_directory(callback_dir)
                self._tqm = TaskQueueManager(inventory=inventory,
                                             variable_manager=variable_manager,
                                             loader=loader,
                                             passwords=self.passwords,
                                             stdout_callback_name="im_callback")

    def run(self):
        '''
        Run the given playbook, based on the settings in the play which
        may limit the runs to serialized groups, etc.
        '''
        # Create a specific dir for the local temp
        C.DEFAULT_LOCAL_TMP = tempfile.mkdtemp()

        try:
            # Initialize the plugin loader for ansible 2.15.0 or higher
            from ansible.plugins.loader import init_plugin_loader
            init_plugin_loader([])
        except ImportError:
            pass

        result = 0
        try:
            pb = Playbook.load(self._playbook, variable_manager=self._variable_manager, loader=self._loader)

            # make sure the tqm has callbacks loaded
            self._tqm.load_callbacks()
            self._tqm.send_callback('v2_playbook_on_start', pb)

            for play in pb.get_plays():
                if play._included_path is not None:
                    self._loader.set_basedir(play._included_path)
                else:
                    self._loader.set_basedir(pb._basedir)

                # clear any filters which may have been applied to the
                # inventory
                self._inventory.remove_restriction()

                # Create a temporary copy of the play here, so we can run post_validate
                # on it without the templating changes affecting the
                # original object.
                try:
                    # for Ansible version 2.3.2 or lower
                    all_vars = self._variable_manager.get_vars(loader=self._loader, play=play)
                except TypeError:
                    # for Ansible version 2.4.0 or higher
                    all_vars = self._variable_manager.get_vars(play=play)
                templar = Templar(loader=self._loader, variables=all_vars)
                new_play = play.copy()
                new_play.post_validate(templar)

                self._tqm._unreachable_hosts.update(self._unreachable_hosts)

                # we are actually running plays
                for batch in self._get_serialized_batches(new_play):
                    if len(batch) == 0:
                        self._tqm.send_callback('v2_playbook_on_play_start', new_play)
                        self._tqm.send_callback('v2_playbook_on_no_hosts_matched')
                        break
                    # restrict the inventory to the hosts in the serialized
                    # batch
                    self._inventory.restrict_to_hosts(batch)
                    # and run it...
                    result = self._tqm.run(play=play)

                    # check the number of failures here, to see if they're above the maximum
                    # failure percentage allowed, or if any errors are fatal. If either of those
                    # conditions are met, we break out, otherwise we only break out if the entire
                    # batch failed
                    failed_hosts_count = len(self._tqm._failed_hosts) + len(self._tqm._unreachable_hosts)
                    if new_play.any_errors_fatal and failed_hosts_count > 0:
                        break
                    elif new_play.max_fail_percentage is not None and \
                            (int((new_play.max_fail_percentage) / 100.0 * len(batch)) >
                             int((len(batch) - failed_hosts_count) / len(batch) * 100.0)):
                        break
                    elif len(batch) == failed_hosts_count:
                        break

                    # clear the failed hosts dictionaires in the TQM for
                    # the next batch
                    self._unreachable_hosts.update(self._tqm._unreachable_hosts)
                    self._tqm.clear_failed_hosts()

                # if the last result wasn't zero or 3 (some hosts were unreachable),
                # break out of the serial batch loop
                if result not in (0, 3):
                    break

            self._tqm.send_callback('v2_playbook_on_stats', self._tqm._stats)

        finally:
            if self._tqm is not None:
                self._tqm.cleanup()

        try:
            # Remove the local temp
            shutil.rmtree(C.DEFAULT_LOCAL_TMP, True)
        except Exception:
            pass

        return result
