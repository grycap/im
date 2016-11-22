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

import ansible.utils
import sys
import getpass
import fnmatch
import datetime
import logging


def display(msg, color=None, stderr=False, screen_only=False, log_only=False, runner=None, output=sys.stdout):
    if not log_only:
        msg2 = msg
        if isinstance(output, logging.Logger):
            output.info(msg2)
        else:
            print >>output, msg2


class AggregateStats(object):
    ''' holds stats about per-host activity during playbook runs '''

    def __init__(self):

        self.processed = {}
        self.failures = {}
        self.ok = {}
        self.dark = {}
        self.changed = {}
        self.skipped = {}

    def _increment(self, what, host):
        ''' helper function to bump a statistic '''

        self.processed[host] = 1
        prev = (getattr(self, what)).get(host, 0)
        getattr(self, what)[host] = prev + 1

    def compute(self, runner_results, setup=False, poll=False, ignore_errors=False):
        ''' walk through all results and increment stats '''

        for (host, value) in runner_results.get('contacted', {}).iteritems():
            if not ignore_errors and (('failed' in value and bool(value['failed'])) or
                                      ('rc' in value and value['rc'] != 0)):
                self._increment('failures', host)
            elif 'skipped' in value and bool(value['skipped']):
                self._increment('skipped', host)
            elif 'changed' in value and bool(value['changed']):
                if not setup and not poll:
                    self._increment('changed', host)
                self._increment('ok', host)
            else:
                if not poll or ('finished' in value and bool(value['finished'])):
                    self._increment('ok', host)

        for (host, value) in runner_results.get('dark', {}).iteritems():
            self._increment('dark', host)

    def summarize(self, host):
        ''' return information about a particular host '''

        return dict(
            ok=self.ok.get(host, 0),
            failures=self.failures.get(host, 0),
            unreachable=self.dark.get(host, 0),
            changed=self.changed.get(host, 0),
            skipped=self.skipped.get(host, 0)
        )

########################################################################


def banner(msg):
    str_date = str(datetime.datetime.now())
    width = 78 - len(str_date + " - " + msg)
    if width < 3:
        width = 3
    filler = "*" * width
    return "\n%s %s " % (str_date + " - " + msg, filler)

########################################################################


class PlaybookRunnerCallbacks(object):
    ''' callbacks used for Runner() from /usr/bin/ansible-playbook '''

    def __init__(self, stats, verbose=ansible.utils.VERBOSITY, output=sys.stdout):
        self.output = output
        self.verbose = verbose
        self.stats = stats
        self._async_notified = {}

    def on_unreachable(self, host, results):
        item = None
        if type(results) == dict:
            item = results.get('item', None)
        if item:
            msg = "fatal: [%s] => (item=%s) => %s" % (host, item, results)
        else:
            msg = "fatal: [%s] => %s" % (host, results)
        display(msg, color='red', runner=self.runner, output=self.output)

    def on_failed(self, host, results, ignore_errors=False):
        results2 = results.copy()
        results2.pop('invocation', None)

        item = results2.get('item', None)
        parsed = results2.get('parsed', True)
        module_msg = ''
        if not parsed:
            module_msg = results2.pop('msg', None)
        stderr = results2.pop('stderr', None)
        stdout = results2.pop('stdout', None)
        returned_msg = results2.pop('msg', None)

        if item:
            msg = "failed: [%s] => (item=%s) => %s" % (
                host, item, ansible.utils.jsonify(results2))
        else:
            msg = "failed: [%s] => %s" % (
                host, ansible.utils.jsonify(results2))
        display(msg, color='red', runner=self.runner, output=self.output)

        if stderr:
            display("stderr: %s" % stderr, color='red',
                    runner=self.runner, output=self.output)
        if stdout:
            display("stdout: %s" % stdout, color='red',
                    runner=self.runner, output=self.output)
        if returned_msg:
            display("msg: %s" % returned_msg, color='red',
                    runner=self.runner, output=self.output)
        if not parsed and module_msg:
            display("invalid output was: %s" % module_msg, color='red',
                    runner=self.runner, output=self.output)
        if ignore_errors:
            display("...ignoring", color='cyan',
                    runner=self.runner, output=self.output)

    def on_ok(self, host, host_result):

        item = host_result.get('item', None)

        host_result2 = host_result.copy()
        host_result2.pop('invocation', None)
        verbose_always = host_result2.pop('verbose_always', None)
        changed = host_result.get('changed', False)
        ok_or_changed = 'ok'
        if changed:
            ok_or_changed = 'changed'

        # show verbose output for non-setup module results if --verbose is used
        msg = ''
        if (not self.verbose or host_result2.get("verbose_override", None) is not
                None) and verbose_always is None:
            if item:
                msg = "%s: [%s] => (item=%s)" % (ok_or_changed, host, item)
            else:
                if 'ansible_job_id' not in host_result or 'finished' in host_result:
                    msg = "%s: [%s]" % (ok_or_changed, host)
        else:
            # verbose ...
            if item:
                msg = "%s: [%s] => (item=%s) => %s" % (
                    ok_or_changed, host, item, ansible.utils.jsonify(host_result2))
            else:
                if 'ansible_job_id' not in host_result or 'finished' in host_result2:
                    msg = "%s: [%s] => %s" % (
                        ok_or_changed, host, ansible.utils.jsonify(host_result2))

        if msg != '':
            if not changed:
                display(msg, color='green',
                        runner=self.runner, output=self.output)
            else:
                display(msg, color='yellow',
                        runner=self.runner, output=self.output)

    def on_error(self, host, err):

        item = err.get('item', None)
        msg = ''
        if item:
            msg = "err: [%s] => (item=%s) => %s" % (host, item, err)
        else:
            msg = "err: [%s] => %s" % (host, err)

        display(msg, color='red', stderr=True,
                runner=self.runner, output=self.output)

    def on_skipped(self, host, item=None):
        msg = ''
        if item:
            msg = "skipping: [%s] => (item=%s)" % (host, item)
        else:
            msg = "skipping: [%s]" % host
        display(msg, color='cyan', runner=self.runner, output=self.output)

    def on_no_hosts(self):
        display("FATAL: no hosts matched or all hosts have already failed -- aborting\n",
                color='red', runner=self.runner, output=self.output)

    def on_async_poll(self, host, res, jid, clock):
        if jid not in self._async_notified:
            self._async_notified[jid] = clock + 1
        if self._async_notified[jid] > clock:
            self._async_notified[jid] = clock
            msg = "<job %s> polling, %ss remaining" % (jid, clock)
            display(msg, color='cyan', runner=self.runner, output=self.output)

    def on_async_ok(self, host, res, jid):
        msg = "<job %s> finished on %s" % (jid, host)
        display(msg, color='cyan', runner=self.runner, output=self.output)

    def on_async_failed(self, host, res, jid):
        msg = "<job %s> FAILED on %s" % (jid, host)
        display(msg, color='red', stderr=True,
                runner=self.runner, output=self.output)

    def on_file_diff(self, host, diff):
        display(ansible.utils.get_diff(diff),
                runner=self.runner, output=self.output)

########################################################################


class PlaybookCallbacks(object):
    ''' playbook.py callbacks used by /usr/bin/ansible-playbook '''

    def __init__(self, verbose=False, output=sys.stdout):

        self.verbose = verbose
        self.output = output

    def on_start(self):
        pass

    def on_notify(self, host, handler):
        pass

    def on_no_hosts_matched(self):
        display("skipping: no hosts matched", color='cyan', output=self.output)

    def on_no_hosts_remaining(self):
        display("\nFATAL: all hosts have already failed -- aborting",
                color='red', output=self.output)

    def on_task_start(self, name, is_conditional):
        msg = "TASK: [%s]" % name
        if is_conditional:
            msg = "NOTIFIED: [%s]" % name

        if hasattr(self, 'start_at'):
            if name == self.start_at or fnmatch.fnmatch(name, self.start_at):
                # we found out match, we can get rid of this now
                del self.start_at

        if hasattr(self, 'start_at'):  # we still have start_at so skip the task
            self.skip_task = True
        elif hasattr(self, 'step') and self.step:
            msg = ('Perform task: %s (y/n/c): ' %
                   name).encode(sys.stdout.encoding)
            resp = raw_input(msg)
            if resp.lower() in ['y', 'yes']:
                self.skip_task = False
                display(banner(msg), output=self.output)
            elif resp.lower() in ['c', 'continue']:
                self.skip_task = False
                self.step = False
                display(banner(msg), output=self.output)
            else:
                self.skip_task = True
        else:
            self.skip_task = False
            display(banner(msg), output=self.output)

    def on_vars_prompt(self, varname, private=True, prompt=None, encrypt=None, confirm=False,
                       salt_size=None, salt=None, default=None):

        if prompt and default:
            msg = "%s [%s]: " % (prompt, default)
        elif prompt:
            msg = "%s: " % prompt
        else:
            msg = 'input for %s: ' % varname

        def prompt(prompt, private):
            if private:
                return getpass.getpass(prompt)
            return raw_input(prompt)

        if confirm:
            while True:
                result = prompt(msg, private)
                second = prompt("confirm " + msg, private)
                if result == second:
                    break
                display("***** VALUES ENTERED DO NOT MATCH ****",
                        output=self.output)
        else:
            result = prompt(msg, private)

        # if result is false and default is not None
        if not result and default:
            result = default

        if encrypt:
            result = ansible.utils.do_encrypt(result, encrypt, salt_size, salt)

        return result

    def on_setup(self):
        display(banner("GATHERING FACTS"), output=self.output)

    def on_import_for_host(self, host, imported_file):
        msg = "%s: importing %s" % (host, imported_file)
        display(msg, color='cyan', output=self.output)

    def on_not_import_for_host(self, host, missing_file):
        msg = "%s: not importing file: %s" % (host, missing_file)
        display(msg, color='cyan', output=self.output)

    def on_play_start(self, pattern):
        display(banner("PLAY [%s]" % pattern), output=self.output)

    def on_stats(self, stats):
        pass
