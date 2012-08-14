# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright (c) 2012 NTT DOCOMO, INC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Class for IPMI power manager.
"""

import os
import stat
import tempfile
import time

from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova import utils
from nova.virt.baremetal import baremetal_states

opts = [
    cfg.StrOpt('baremetal_term',
               default='shellinaboxd',
               help='path to baremetal terminal program'),
    cfg.StrOpt('baremetal_term_cert_dir',
               default=None,
               help='path to baremetal terminal SSL cert(PEM)'),
    cfg.StrOpt('baremetal_term_pid_dir',
               default='/var/lib/nova/baremetal/console',
               help='path to directory stores pidfiles of baremetal_term'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(opts)

LOG = logging.getLogger(__name__)


def _make_password_file(password):
    fd, path = tempfile.mkstemp()
    os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(password)
    return path


def _unlink_without_raise(path):
    try:
        os.unlink(path)
    except OSError:
        LOG.exception("failed to unlink %s" % path)


class IpmiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.msg = message

    def __str__(self):
        return "%s: %s" % (self.status, self.msg)


class Ipmi(object):

    def __init__(self, node):
        self._address = node['pm_address']
        self._user = node['pm_user']
        self._password = node['pm_password']
        self._interface = "lanplus"
        if self._address == None:
            raise IpmiError(-1, "address is None")
        if self._user == None:
            raise IpmiError(-1, "user is None")
        if self._password == None:
            raise IpmiError(-1, "password is None")

    def _exec_ipmitool(self, command):
        args = []
        args.append("ipmitool")
        args.append("-I")
        args.append(self._interface)
        args.append("-H")
        args.append(self._address)
        args.append("-U")
        args.append(self._user)
        args.append("-f")
        pwfile = _make_password_file(self._password)
        try:
            args.append(pwfile)
            args.extend(command.split(" "))
            out, err = utils.execute(*args, attempts=3)
        finally:
            _unlink_without_raise(pwfile)
        LOG.debug("out: %s", out)
        LOG.debug("err: %s", err)
        return out, err

    def activate_node(self):
        self._power_off()
        state = self._power_on()
        return state

    def reboot_node(self):
        self._power_off()
        state = self._power_on()
        return state

    def deactivate_node(self):
        state = self._power_off()
        return state

    def _power_on(self):
        count = 0
        while not self.is_power_on():
            count += 1
            if count > 3:
                return baremetal_states.ERROR
            try:
                self._exec_ipmitool("power on")
            except Exception:
                LOG.exception("power_on failed")
            time.sleep(5)
        return baremetal_states.ACTIVE

    def _power_off(self):
        count = 0
        while not self._is_power_off():
            count += 1
            if count > 3:
                return baremetal_states.ERROR
            try:
                self._exec_ipmitool("power off")
            except Exception:
                LOG.exception("power_off failed")
            time.sleep(5)
        return baremetal_states.DELETED

    def _power_status(self):
        out_err = self._exec_ipmitool("power status")
        return out_err[0]

    def _is_power_off(self):
        r = self._power_status()
        return r == "Chassis Power is off\n"

    def is_power_on(self):
        r = self._power_status()
        return r == "Chassis Power is on\n"

    def start_console(self, port, node_id):
        pidfile = self._console_pidfile(node_id)

        TERMINAL = FLAGS.baremetal_term
        CERTDIR = FLAGS.baremetal_term_cert_dir

        args = []

        args.append(TERMINAL)
        if CERTDIR:
            args.append("-c")
            args.append(CERTDIR)
        else:
            args.append("-t")
        args.append("-p")
        args.append(str(port))
        if pidfile:
            args.append("--background=%s" % pidfile)
        else:
            args.append("--background")
        args.append("-s")

        uid = os.getuid()
        gid = os.getgid()

        pwfile = _make_password_file(self._password)

        ipmi_args = "/:%s:%s:HOME:ipmitool -H %s -I lanplus " \
                    " -U %s -f %s sol activate" \
                    % (str(uid), str(gid), self._address, self._user, pwfile)

        args.append(ipmi_args)
        # Run shellinaboxd without pipes. Otherwise utils.execute() waits
        # infinitly since shellinaboxd does not close passed fds.
        x = ["'" + arg.replace("'", "'\\''") + "'" for arg in args]
        x.append('</dev/null')
        x.append('>/dev/null')
        x.append('2>&1')
        return utils.execute(' '.join(x), shell=True)

    def stop_console(self, node_id):
        console_pid = self._console_pid(node_id)
        if console_pid:
            utils.execute('kill', str(console_pid),
                          run_as_root=True,
                          check_exit_code=[0, 1])
        _unlink_without_raise(self._console_pidfile(node_id))

    def _console_pidfile(self, node_id):
        name = "%s.pid" % node_id
        path = os.path.join(FLAGS.baremetal_term_pid_dir, name)
        return path

    def _console_pid(self, node_id):
        pidfile = self._console_pidfile(node_id)
        if os.path.exists(pidfile):
            with open(pidfile, 'r') as f:
                return int(f.read())
        return None


class DummyIpmi(object):

    def __init__(self, node):
        pass

    def activate_node(self):
        return baremetal_states.ACTIVE

    def reboot_node(self):
        return baremetal_states.ACTIVE

    def deactivate_node(self):
        return baremetal_states.DELETED

    def is_power_on(self):
        return True

    def start_console(self, port, node_id):
        pass

    def stop_console(self, node_id):
        pass
