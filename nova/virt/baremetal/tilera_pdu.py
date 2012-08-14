# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 University of Southern California / ISI
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
Class for PDU power manager.
"""

import subprocess
import time

from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova import utils
from nova.virt.baremetal import baremetal_states

flags.DECLARE('tile_monitor', 'nova.virt.baremetal.tilera')

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


class PduError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.status, self.message)


class Pdu(object):

    def __init__(self, node):
        self._address = node['pm_address']
        self._node_id = node['id']
        if self._address == None:
            raise PduError(-1, "address is None")
        if self._node_id == None:
            raise PduError(-1, "node_id is None")

    def _exec_status(self):
        LOG.debug(_("Before ping to the bare-metal node"))
        tile_output = "/tftpboot/tile_output_" + str(self._node_id)
        grep_cmd = ("ping -c1 " + self._address + " | grep Unreachable > " +
                    tile_output)
        subprocess.Popen(grep_cmd, shell=True)
        time.sleep(5)
        file = open(tile_output, "r")
        out = file.readline().find("Unreachable")
        utils.execute('sudo', 'rm', tile_output)
        return out

    def activate_node(self):
        state = self._power_on()
        return state

    def reboot_node(self):
        self._power_off()
        state = self._power_on()
        return state

    def deactivate_node(self):
        state = self._power_off()
        return state

    def _power_mgr(self, mode):
        """
        Changes power state of the given node.

        According to the mode (1-ON, 2-OFF, 3-REBOOT), power state can be
        changed. /tftpboot/pdu_mgr script handles power management of
        PDU (Power Distribution Unit).
        """
        if self._node_id < 5:
            pdu_num = 1
            pdu_outlet_num = self._node_id + 5
        else:
            pdu_num = 2
            pdu_outlet_num = self._node_id
        path1 = "10.0.100." + str(pdu_num)
        utils.execute('/tftpboot/pdu_mgr', path1, str(pdu_outlet_num),
                      str(mode), '>>', 'pdu_output')

    def _power_on(self):
        count = 1
        self._power_mgr(2)
        self._power_mgr(3)
        time.sleep(100)
        while not self.is_power_on():
            count += 1
            if count > 3:
                LOG.exception("power_on failed")
                return baremetal_states.ERROR
            self._power_mgr(2)
            self._power_mgr(3)
            time.sleep(120)
        return baremetal_states.ACTIVE

    def _power_off(self):
        count = 1
        try:
            self._power_mgr(2)
        except Exception:
            LOG.exception("power_off failed")
            return baremetal_states.ERROR
        return baremetal_states.DELETED

    def _is_power_off(self):
        r = self._exec_status()
        return (r != -1)

    def is_power_on(self):
        r = self._exec_status()
        return (r == -1)

    def start_console(self, port, node_id):
        pass

    def stop_console(self, node_id):
        pass


class DummyPdu(object):

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
