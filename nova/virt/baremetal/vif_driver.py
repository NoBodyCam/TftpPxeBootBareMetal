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

from nova import context
from nova import exception
from nova import flags
from nova.openstack.common import log as logging
from nova.virt.baremetal import bmdb
from nova.virt.vif import VIFDriver

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


class BareMetalVIFDriver(VIFDriver):

    def _after_plug(self, instance, network, mapping, pif):
        pass

    def _after_unplug(self, instance, network, mapping, pif):
        pass

    def plug(self, instance, vif):
        LOG.debug("plug: instance_uuid=%s vif=%s", instance['uuid'], vif)
        network, mapping = vif
        ctx = context.get_admin_context()
        node = bmdb.bm_node_get_by_instance_uuid(ctx, instance['uuid'])
        if not node:
            return
        pifs = bmdb.bm_interface_get_all_by_bm_node_id(ctx, node['id'])
        for pif in pifs:
            if not pif['vif_uuid']:
                bmdb.bm_interface_set_vif_uuid(ctx, pif['id'],
                                               mapping.get('vif_uuid'))
                LOG.debug("pif:%s is plugged (vif_uuid=%s)",
                          pif['id'], mapping.get('vif_uuid'))
                self._after_plug(instance, network, mapping, pif)
                return
        raise exception.NovaException(
                "baremetalnode:%s has no vacant pif for vif_uuid=%s"
                % (node['id'], mapping['vif_uuid']))

    def unplug(self, instance, vif):
        LOG.debug("unplug: instance_uuid=%s vif=%s", instance['uuid'], vif)
        network, mapping = vif
        ctx = context.get_admin_context()
        pif = bmdb.bm_interface_get_by_vif_uuid(ctx, mapping['vif_uuid'])
        if pif:
            bmdb.bm_interface_set_vif_uuid(ctx, pif['id'], None)
            LOG.debug("pif:%s is unplugged (vif_uuid=%s)",
                      pif['id'], mapping.get('vif_uuid'))
            self._after_unplug(instance, network, mapping, pif)
        else:
            LOG.warn("no pif for vif_uuid=%s" % mapping['vif_uuid'])
