# Copyright (c) 2011 University of Southern California / ISI
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
Tests for baremetal tilera_pdu driver.
"""

import os
import stat

import mox

from nova import flags
from nova import test
from nova import utils

from nova.tests.baremetal import bmdb as bmdb_utils
from nova.virt.baremetal import tilera_pdu

FLAGS = flags.FLAGS


class BaremetalPduTestCase(test.TestCase):

    def setUp(self):
        super(BaremetalPduTestCase, self).setUp()

    def tearDown(self):
        super(BaremetalPduTestCase, self).tearDown()

    def test_get_power_manager(self):
        n1 = bmdb_utils.new_bm_node(
                pm_address='10.1.1.1',
                id='1')
        pm1 = tilera_pdu.Pdu(n1)
        self.assertEqual(pm1._address, '10.1.1.1')
        self.assertEqual(pm1._node_id, '1')

        n2 = bmdb_utils.new_bm_node(
                pm_address='10.2.2.2',
                id='2')
        pm2 = tilera_pdu.Pdu(n2)
        self.assertEqual(pm2._address, '10.2.2.2')
        self.assertEqual(pm2._node_id, '2')
