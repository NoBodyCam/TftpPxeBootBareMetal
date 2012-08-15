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
Tests for baremetal volume driver.
"""

import mox

from nova import flags
from nova import test
from nova import utils

from nova.virt.baremetal import volume_driver

FLAGS = flags.FLAGS

SHOW_OUTPUT = """Target 1: iqn.2010-10.org.openstack:volume-00000001
    System information:
        Driver: iscsi
        State: ready
    I_T nexus information:
        I_T nexus: 8
            Initiator: iqn.1993-08.org.debian:01:7780c6a16b4
            Connection: 0
                IP Address: 172.17.12.10
    LUN information:
        LUN: 0
            Type: controller
            SCSI ID: IET     00010000
            SCSI SN: beaf10
            Size: 0 MB, Block size: 1
            Online: Yes
            Removable media: No
            Readonly: No
            Backing store type: null
            Backing store path: None
            Backing store flags:
        LUN: 1
            Type: disk
            SCSI ID: IET     00010001
            SCSI SN: beaf11
            Size: 1074 MB, Block size: 512
            Online: Yes
            Removable media: No
            Readonly: No
            Backing store type: rdwr
            Backing store path: /dev/nova-volumes/volume-00000001
            Backing store flags:
    Account information:
    ACL information:
        ALL
Target 2: iqn.2010-10.org.openstack:volume-00000002
    System information:
        Driver: iscsi
        State: ready
    I_T nexus information:
    LUN information:
        LUN: 0
            Type: controller
            SCSI ID: IET     00020000
            SCSI SN: beaf20
            Size: 0 MB, Block size: 1
            Online: Yes
            Removable media: No
            Readonly: No
            Backing store type: null
            Backing store path: None
            Backing store flags:
        LUN: 1
            Type: disk
            SCSI ID: IET     00020001
            SCSI SN: beaf21
            Size: 2147 MB, Block size: 512
            Online: Yes
            Removable media: No
            Readonly: No
            Backing store type: rdwr
            Backing store path: /dev/nova-volumes/volume-00000002
            Backing store flags:
    Account information:
    ACL information:
        ALL
Target 1000001: iqn.2010-10.org.openstack.baremetal:1000001-dev.vdc
    System information:
        Driver: iscsi
        State: ready
    I_T nexus information:
    LUN information:
        LUN: 0
            Type: controller
            SCSI ID: IET     f42410000
            SCSI SN: beaf10000010
            Size: 0 MB, Block size: 1
            Online: Yes
            Removable media: No
            Readonly: No
            Backing store type: null
            Backing store path: None
            Backing store flags:
        LUN: 1
            Type: disk
            SCSI ID: IET     f42410001
            SCSI SN: beaf10000011
            Size: 1074 MB, Block size: 512
            Online: Yes
            Removable media: No
            Readonly: No
            Backing store type: rdwr
            Backing store path: /dev/disk/by-path/ip-172.17.12.10:3260-iscsi-\
iqn.2010-10.org.openstack:volume-00000001-lun-1
            Backing store flags:
    Account information:
    ACL information:
        ALL
"""


class BaremetalVolumeTestCase(test.TestCase):

    def test_list_backingstore_path(self):
        self.stubs.Set(utils, 'execute', lambda *args,
                       **kwargs: (SHOW_OUTPUT, ''))
        l = volume_driver._list_backingstore_path()
        self.assertEqual(len(l), 3)
        self.assertIn('/dev/nova-volumes/volume-00000001', l)
        self.assertIn('/dev/nova-volumes/volume-00000002', l)
        self.assertIn('/dev/disk/by-path/ip-172.17.12.10:3260-iscsi-\
iqn.2010-10.org.openstack:volume-00000001-lun-1', l)
