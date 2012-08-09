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
Baremetal DB testcase for PhyHost
"""

from nova import exception
from nova.tests.baremetal.bmdb import BMDBTestCase
from nova.tests.baremetal.bmdb import new_bm_node
from nova.virt.baremetal import bmdb

from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_models


def new_bm_pxe_ip(**kwargs):
    x = baremetal_models.BareMetalPxeIp()
    x.id = kwargs.pop('id', None)
    x.address = kwargs.pop('address', None)
    x.server_address = kwargs.pop('server_address', None)
    x.bm_node_id = kwargs.pop('bm_node_id', None)
    if len(kwargs) > 0:
        raise Exception("unknown field: %s" % ','.join(kwargs.keys()))
    return x


class BareMetalPxeIpTestCase(BMDBTestCase):

    def setUp(self):
        super(BareMetalPxeIpTestCase, self).setUp()

    def _create_pxe_ip(self):
        i1 = new_bm_pxe_ip(address='10.1.1.1')
        i2 = new_bm_pxe_ip(address='10.1.1.2')
        i3 = new_bm_pxe_ip(address='10.1.1.3')

        i1_ref = bmdb.bm_pxe_ip_create_direct(self.context, i1)
        self.assertTrue(i1_ref['id'] is not None)

        i2_ref = bmdb.bm_pxe_ip_create_direct(self.context, i2)
        self.assertTrue(i2_ref['id'] is not None)

        i3_ref = bmdb.bm_pxe_ip_create_direct(self.context, i3)
        self.assertTrue(i3_ref['id'] is not None)

        self.i1 = i1_ref
        self.i2 = i2_ref
        self.i3 = i3_ref

    def test_bm_pxe_ip_associate(self):
        self._create_pxe_ip()
        node = bmdb.bm_node_create(self.context, new_bm_node())
        ip_id = bmdb.bm_pxe_ip_associate(self.context, node['id'])
        ref = bmdb.bm_pxe_ip_get(self.context, ip_id)
        self.assertEqual(ref['bm_node_id'], node['id'])

    def test_bm_pxe_ip_associate_raise(self):
        self._create_pxe_ip()
        node_id = 123
        self.assertRaises(exception.NovaException,
                          bmdb.bm_pxe_ip_associate,
                          self.context, node_id)
