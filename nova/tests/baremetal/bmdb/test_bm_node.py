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

from nova.tests.baremetal.bmdb import BMDBTestCase
from nova.tests.baremetal.bmdb import new_bm_node
from nova.virt.baremetal import bmdb


class BareMetalNodesTestCase(BMDBTestCase):

    def setUp(self):
        super(BareMetalNodesTestCase, self).setUp()

    def _create_hosts(self):
        h1 = new_bm_node(service_host="host1")
        h2 = new_bm_node(service_host="host2")
        h3 = new_bm_node(service_host="host2")

        h1_ref = bmdb.bm_node_create(self.context, h1)
        self.assertTrue(h1_ref['id'] is not None)

        h2_ref = bmdb.bm_node_create(self.context, h2)
        self.assertTrue(h2_ref['id'] is not None)

        h3_ref = bmdb.bm_node_create(self.context, h3)
        self.assertTrue(h3_ref['id'] is not None)

        self.h1 = h1_ref
        self.h2 = h2_ref
        self.h3 = h3_ref

    def test_get_all(self):
        r = bmdb.bm_node_get_all(self.context)
        self.assertEquals(r, [])

        self._create_hosts()

        r = bmdb.bm_node_get_all(self.context)
        self.assertEquals(len(r), 3)

    def test_get(self):
        self._create_hosts()

        r = bmdb.bm_node_get(self.context, self.h1['id'])
        self.assertEquals(self.h1['id'], r['id'])

        r = bmdb.bm_node_get(self.context, self.h2['id'])
        self.assertEquals(self.h2['id'], r['id'])

        r = bmdb.bm_node_get(self.context, self.h3['id'])
        self.assertEquals(self.h3['id'], r['id'])

        r = bmdb.bm_node_get(self.context, 0)
        self.assertTrue(r is None)

    def test_get_by_service_host(self):
        self._create_hosts()

        r = bmdb.bm_node_get_all(self.context, service_host="host1")
        self.assertEquals(len(r), 1)
        self.assertEquals(r[0]['id'], self.h1['id'])

        r = bmdb.bm_node_get_all(self.context, service_host="host2")
        self.assertEquals(len(r), 2)
        ids = [x['id'] for x in r]
        self.assertIn(self.h2['id'], ids)
        self.assertIn(self.h3['id'], ids)

        r = bmdb.bm_node_get_all(self.context, service_host="host3")
        self.assertEquals(r, [])

    def test_destroy(self):
        self._create_hosts()

        bmdb.bm_node_destroy(self.context, self.h1['id'])

        r = bmdb.bm_node_get(self.context, self.h1['id'])
        self.assertTrue(r is None)

        r = bmdb.bm_node_get_all(self.context)
        self.assertEquals(len(r), 2)
