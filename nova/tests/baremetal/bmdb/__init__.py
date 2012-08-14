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

"""Baremetal DB utils for test."""

from nova import context as nova_context
from nova import flags
from nova import test
from nova.virt.baremetal import bmdb
from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_models

flags.DECLARE('baremetal_sql_connection',
              'nova.virt.baremetal.bmdb.sqlalchemy.baremetal_session')


def new_bm_node(**kwargs):
    h = baremetal_models.BareMetalNode()
    h.id = kwargs.pop('id', None)
    h.service_host = kwargs.pop('service_host', None)
    h.instance_id = kwargs.pop('instance_id', None)
    h.cpus = kwargs.pop('cpus', 1)
    h.memory_mb = kwargs.pop('memory_mb', 1024)
    h.local_gb = kwargs.pop('local_gb', 64)
    h.pm_address = kwargs.pop('pm_address', '192.168.1.1')
    h.pm_user = kwargs.pop('pm_user', 'ipmi_user')
    h.pm_password = kwargs.pop('pm_password', 'ipmi_password')
    h.prov_mac_address = kwargs.pop('prov_mac_address', '12:34:56:78:90:ab')
    h.registration_status = kwargs.pop('registration_status', 'done')
    h.task_state = kwargs.pop('task_state', None)
    h.prov_vlan_id = kwargs.pop('prov_vlan_id', None)
    h.terminal_port = kwargs.pop('terminal_port', 8000)
    if len(kwargs) > 0:
        raise Exception("unknown field: %s" % ','.join(kwargs.keys()))
    return h


def clear_tables():
    baremetal_models.unregister_models()
    baremetal_models.register_models()


class BMDBTestCase(test.TestCase):

    def setUp(self):
        super(BMDBTestCase, self).setUp()
        self.flags(baremetal_sql_connection='sqlite:///:memory:')
        clear_tables()
        self.context = nova_context.get_admin_context()
