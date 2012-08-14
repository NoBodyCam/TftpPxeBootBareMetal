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
Tests for baremetal ipmi driver.
"""

import os
import stat

import mox

from nova import flags
from nova import test
from nova import utils

from nova.tests.baremetal import bmdb as bmdb_utils
from nova.virt.baremetal import ipmi

FLAGS = flags.FLAGS


class BaremetalIPMITestCase(test.TestCase):

    def setUp(self):
        super(BaremetalIPMITestCase, self).setUp()

    def tearDown(self):
        super(BaremetalIPMITestCase, self).tearDown()

    def test_ipmi(self):
        n1 = bmdb_utils.new_bm_node(
                pm_address='10.1.1.1',
                pm_user='n1_user',
                pm_password='n1_password')
        pm1 = ipmi.Ipmi(n1)
        self.assertEqual(pm1._address, '10.1.1.1')
        self.assertEqual(pm1._user, 'n1_user')
        self.assertEqual(pm1._password, 'n1_password')

        n2 = bmdb_utils.new_bm_node(
                pm_address='10.2.2.2',
                pm_user='n2_user',
                pm_password='n2_password')
        pm2 = ipmi.Ipmi(n2)
        self.assertEqual(pm2._address, '10.2.2.2')
        self.assertEqual(pm2._user, 'n2_user')
        self.assertEqual(pm2._password, 'n2_password')

    def test_make_password_file(self):
        PASSWORD = 'xyz'
        path = ipmi._make_password_file(PASSWORD)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.stat(path)[stat.ST_MODE] & 0777, 0600)
        try:
            with open(path, "r") as f:
                s = f.read(100)
            self.assertEqual(s, PASSWORD)
        finally:
            os.unlink(path)

    def test_exec_ipmitool(self):
        H = 'address'
        U = 'user'
        P = 'password'
        I = 'lanplus'
        F = 'password_file'

        n1 = bmdb_utils.new_bm_node(
                pm_address=H,
                pm_user=U,
                pm_password=P)

        self.mox.StubOutWithMock(ipmi, '_make_password_file')
        self.mox.StubOutWithMock(utils, 'execute')
        self.mox.StubOutWithMock(ipmi, '_unlink_without_raise')
        ipmi._make_password_file(P).AndReturn(F)
        args = [
                'ipmitool',
                '-I', I,
                '-H', H,
                '-U', U,
                '-f', F,
                'A', 'B', 'C',
                ]
        utils.execute(*args, attempts=3).AndReturn(('', ''))
        ipmi._unlink_without_raise(F).AndReturn(None)
        self.mox.ReplayAll()

        i = ipmi.Ipmi(n1)
        i._exec_ipmitool('A B C')
        self.mox.VerifyAll()
