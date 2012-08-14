# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from nova import flags
from nova.openstack.common import log as logging
from nova import utils


LOG = logging.getLogger(__name__)


FLAGS = flags.FLAGS


def _execute(*cmd, **kwargs):
    """Wrapper around utils._execute for fake_network."""
    if FLAGS.fake_network:
        LOG.debug('FAKE NET: %s', ' '.join(map(str, cmd)))
        return 'fake', 0
    else:
        return utils.execute(*cmd, **kwargs)


def _device_exists(device):
    """Check if ethernet device exists."""
    (_out, err) = _execute('ip', 'link', 'show', 'dev', device,
                           check_exit_code=False)
    return not err


@utils.synchronized('ensure_vlan', external=True)
def ensure_vlan(vlan_num, parent_interface, mac_address=None):
    """Create a vlan unless it already exists."""
    _execute('ip', 'link', 'set', parent_interface, 'up', run_as_root=True)
    vlan_interface = 'vlan%s' % vlan_num
    if not _device_exists(vlan_interface):
        LOG.debug(_('Starting VLAN interface %s'), vlan_interface)
        _execute('vconfig', 'set_name_type', 'VLAN_PLUS_VID_NO_PAD',
                 run_as_root=True)
        _execute('vconfig', 'add', parent_interface, vlan_num,
                 run_as_root=True)
        if mac_address:
            _execute('ip', 'link', 'set', vlan_interface,
                     "address", mac_address,
                     run_as_root=True)
    _execute('ip', 'link', 'set', vlan_interface, 'up', run_as_root=True)
    return vlan_interface


@utils.synchronized('ensure_vlan', external=True)
def ensure_no_vlan(vlan_num, parent_interface):
    """Delete a vlan if it exists."""
    vlan_interface = 'vlan%s' % vlan_num
    if _device_exists(vlan_interface):
        LOG.debug(_('Stopping VLAN interface %s'), vlan_interface)
        _execute('ip', 'link', 'set', vlan_interface, 'down', run_as_root=True)
        _execute('vconfig', 'rem', vlan_interface, run_as_root=True)
