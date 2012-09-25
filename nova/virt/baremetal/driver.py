# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
# Copyright (c) 2012 NTT DOCOMO, INC
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
A driver for Bare-metal platform.
"""
import os
from nova.compute import power_state
from nova import context as nova_context
from nova import db
from nova import exception
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova.virt.baremetal import baremetal_states
from nova.virt.baremetal import bmdb
from nova.virt import driver
from nova.virt.libvirt import imagecache

opts = [
    cfg.BoolOpt('baremetal_inject_password',
                default=True,
                help='Whether baremetal compute injects password or not'),
    cfg.StrOpt('baremetal_injected_network_template',
               default='$pybasedir/nova/virt/baremetal/interfaces.template',
               help='Template file for injected network'),
    cfg.StrOpt('baremetal_vif_driver',
               default='nova.virt.baremetal.vif_driver.BareMetalVIFDriver',
               help='Baremetal VIF driver.'),
    cfg.StrOpt('baremetal_firewall_driver',
                default='nova.virt.firewall.NoopFirewallDriver',
                help='Baremetal firewall driver.'),
    cfg.StrOpt('baremetal_volume_driver',
               default='nova.virt.baremetal.volume_driver.LibvirtVolumeDriver',
               help='Baremetal volume driver.'),
    cfg.ListOpt('instance_type_extra_specs',
               default=[],
               help='a list of additional capabilities corresponding to '
               'instance_type_extra_specs for this compute '
               'host to advertise. Valid entries are name=value, pairs '
               'For example, "key1:val1, key2:val2"'),
    cfg.StrOpt('baremetal_driver',
               default='nova.virt.baremetal.tilera.TILERA',
               help='Bare-metal driver runs on'),
    cfg.StrOpt('power_manager',
               default='nova.virt.baremetal.ipmi.Ipmi',
               help='power management method'),
    cfg.StrOpt('baremetal_tftp_root',
               default='/tftpboot',
               help='BareMetal compute nodes tftp root path'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(opts)

LOG = logging.getLogger(__name__)


class NoSuitableBareMetalNode(exception.NovaException):
    message = _("Failed to find suitable BareMetalNode")


def _get_baremetal_nodes(context):
    nodes = bmdb.bm_node_get_all(context, service_host=FLAGS.host)
    return nodes


def _get_baremetal_node_by_instance_uuid(instance_uuid):
    ctx = nova_context.get_admin_context()
    node = bmdb.bm_node_get_by_instance_uuid(ctx, instance_uuid)
    if not node:
        return None
    if node['service_host'] != FLAGS.host:
        return None
    return node


def _find_suitable_baremetal_node(context, instance):
    result = None
    for node in _get_baremetal_nodes(context):
        if node['instance_uuid']:
            continue
        if node['registration_status'] != 'done':
            continue
        if node['cpus'] < instance['vcpus']:
            continue
        if node['memory_mb'] < instance['memory_mb']:
            continue
        if result == None:
            result = node
        else:
            if node['cpus'] < result['cpus']:
                result = node
            elif node['cpus'] == result['cpus'] \
                    and node['memory_mb'] < result['memory_mb']:
                result = node
    return result


def _update_baremetal_state(context, node, instance, state):
    instance_uuid = None
    if instance:
        instance_uuid = instance['uuid']
    bmdb.bm_node_update(context, node['id'],
        {'instance_uuid': instance_uuid,
        'task_state': state,
        })


def get_power_manager(node, **kwargs):
    cls = importutils.import_class(FLAGS.power_manager)
    return cls(node, **kwargs)


class BareMetalDriver(driver.ComputeDriver):
    """BareMetal hypervisor driver."""

    def __init__(self):
        super(BareMetalDriver, self).__init__()

        self.baremetal_nodes = importutils.import_object(
                FLAGS.baremetal_driver)
        self._vif_driver = importutils.import_object(
                FLAGS.baremetal_vif_driver)
        self._firewall_driver = importutils.import_object(
                FLAGS.baremetal_firewall_driver)
        self._volume_driver = importutils.import_object(
                FLAGS.baremetal_volume_driver)
        self._image_cache_manager = imagecache.ImageCacheManager()

        extra_specs = {}
        extra_specs["hypervisor_type"] = self.get_hypervisor_type()
        extra_specs["baremetal_driver"] = FLAGS.baremetal_driver
        for pair in FLAGS.instance_type_extra_specs:
            keyval = pair.split(':', 1)
            keyval[0] = keyval[0].strip()
            keyval[1] = keyval[1].strip()
            extra_specs[keyval[0]] = keyval[1]
        if not 'cpu_arch' in extra_specs:
            LOG.warning('cpu_arch is not found in instance_type_extra_specs')
            extra_specs['cpu_arch'] = ''
        self._extra_specs = extra_specs

    @classmethod
    def instance(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance

    def init_host(self, host):
        return

    def get_hypervisor_type(self):
        return 'baremetal'

    def get_hypervisor_version(self):
        return 1

    def list_instances(self):
        l = []
        ctx = nova_context.get_admin_context()
        for node in _get_baremetal_nodes(ctx):
            if node['instance_uuid']:
                inst = db.instance_get_by_uuid(ctx, node['instance_uuid'])
                if inst:
                    l.append(inst['name'])
        return l

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        node = _find_suitable_baremetal_node(context, instance)

        if not node:
            LOG.info("no suitable baremetal node found")
            raise NoSuitableBareMetalNode()

        _update_baremetal_state(context, node, instance,
                                baremetal_states.BUILDING)

        var = self.baremetal_nodes.define_vars(instance, network_info,
                                               block_device_info)

        # if we have bmpxeinstaller set as a image_meta properties then will 
        # handle the image a bit differently
        pxe_tftp_build = self.check_if_tftp_boot_image(image_meta)
        if pxe_tftp_build:
            LOG.debug("Setting up pxe tftp boot for bare metal")

            self.baremetal_nodes.create_pxe_tftp_boot_image_files(var, node, 
                context, instance, image_meta, admin_password, 
                block_device_info=block_device_info)
            self.baremetal_nodes.setup_node_dnsmasq(node, var, instance)
        else:
	        self._plug_vifs(instance, network_info, context=context)
	
	        self._firewall_driver.setup_basic_filtering(instance, network_info)
	        self._firewall_driver.prepare_instance_filter(instance, network_info)
	
	        self.baremetal_nodes.create_image(var, context, image_meta, node,
	                                          instance,
	                                          injected_files=injected_files,
	                                          admin_password=admin_password)
	        self.baremetal_nodes.activate_bootloader(var, context, node,
	                                                 instance)

        pm = get_power_manager(node)
        if pxe_tftp_build:
            state = pm.activate_tftp_node()
            _update_baremetal_state(context, node, instance, state)
        else:
            state = pm.activate_node()
            _update_baremetal_state(context, node, instance, state)

            self.baremetal_nodes.activate_node(var, context, node, instance)
            self._firewall_driver.apply_instance_filter(instance, network_info)
    
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)
            for vol in block_device_mapping:
                connection_info = vol['connection_info']
                mountpoint = vol['mount_device']
                self.attach_volume(connection_info, instance['name'], mountpoint)

        if node['terminal_port']:
            pm.start_console(node['terminal_port'], node['id'])

    def reboot(self, instance, network_info):
        node = _get_baremetal_node_by_instance_uuid(instance['uuid'])

        if not node:
            raise exception.InstanceNotFound(instance_id=instance['uuid'])

        ctx = nova_context.get_admin_context()
        pm = get_power_manager(node)
        state = pm.reboot_node()
        _update_baremetal_state(ctx, node, instance, state)

    def destroy(self, instance, network_info, block_device_info=None):
        ctx = nova_context.get_admin_context()

        node = _get_baremetal_node_by_instance_uuid(instance['uuid'])
        if not node:
            LOG.warning("Instance:id='%s' not found" % instance['uuid'])
            return

        var = self.baremetal_nodes.define_vars(instance, network_info,
                                               block_device_info)
        
        # if this is a tftp booted node (need image_meta here)
        if os.path.exists(os.path.join(var['image_root'], 'mnt')):
            self.baremetal_nodes.remove_node_dnsmasq(node, var, instance)
            self.baremetal_nodes.deactivate_tftp_node(var, ctx, node, instance)
        else:
            self.baremetal_nodes.deactivate_node(var, ctx, node, instance)

            ## cleanup volumes
            # NOTE(vish): we disconnect from volumes regardless
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)
            for vol in block_device_mapping:
                connection_info = vol['connection_info']
                mountpoint = vol['mount_device']
                self.detach_volume(connection_info, instance['name'], mountpoint)
    
            self.baremetal_nodes.deactivate_bootloader(var, ctx, node, instance)

        self.baremetal_nodes.destroy_images(var, ctx, node, instance)

        pm = get_power_manager(node)

        pm.stop_console(node['id'])

        ## power off the node
        state = pm.deactivate_node()


        # stop firewall
        self._firewall_driver.unfilter_instance(instance,
                                                network_info=network_info)

        self._unplug_vifs(instance, network_info)

        _update_baremetal_state(ctx, node, None, state)

    def get_volume_connector(self, instance):
        return self._volume_driver.get_volume_connector(instance)

    def attach_volume(self, connection_info, instance_name, mountpoint):
        return self._volume_driver.attach_volume(connection_info,
                                                 instance_name, mountpoint)

    @exception.wrap_exception()
    def detach_volume(self, connection_info, instance_name, mountpoint):
        return self._volume_driver.detach_volume(connection_info,
                                                 instance_name, mountpoint)

    def get_info(self, instance):
        node = _get_baremetal_node_by_instance_uuid(instance['uuid'])
        if not node:
            raise exception.InstanceNotFound(instance_id=instance['uuid'])
        pm = get_power_manager(node)
        ps = power_state.SHUTDOWN
        if pm.is_power_on():
            ps = power_state.RUNNING
        return {'state': ps,
                'max_mem': node['memory_mb'],
                'mem': node['memory_mb'],
                'num_cpu': node['cpus'],
                'cpu_time': 0}

    def refresh_security_group_rules(self, security_group_id):
        self._firewall_driver.refresh_security_group_rules(security_group_id)
        return True

    def refresh_security_group_members(self, security_group_id):
        self._firewall_driver.refresh_security_group_members(security_group_id)
        return True

    def refresh_provider_fw_rules(self):
        self._firewall_driver.refresh_provider_fw_rules()

    def _sum_baremetal_resources(self, ctxt):
        vcpus = 0
        vcpus_used = 0
        memory_mb = 0
        memory_mb_used = 0
        local_gb = 0
        local_gb_used = 0
        for node in _get_baremetal_nodes(ctxt):
            if node['registration_status'] != 'done':
                continue
            vcpus += node['cpus']
            memory_mb += node['memory_mb']
            local_gb += node['local_gb']
            if node['instance_uuid']:
                vcpus_used += node['cpus']
                memory_mb_used += node['memory_mb']
                local_gb_used += node['local_gb']

        dic = {'vcpus': vcpus,
               'memory_mb': memory_mb,
               'local_gb': local_gb,
               'vcpus_used': vcpus_used,
               'memory_mb_used': memory_mb_used,
               'local_gb_used': local_gb_used,
               }
        return dic

    def _max_baremetal_resources(self, ctxt):
        max_node = {'cpus': 0,
                    'memory_mb': 0,
                    'local_gb': 0,
                    }

        for node in _get_baremetal_nodes(ctxt):
            if node['registration_status'] != 'done':
                continue
            if node['instance_uuid']:
                continue

            # Put prioirty to memory size.
            # You can use CPU and HDD, if you change the following lines.
            if max_node['memory_mb'] < node['memory_mb']:
                max_node = node
            elif max_node['memory_mb'] == node['memory_mb']:
                if max_node['cpus'] < node['cpus']:
                    max_node = node
                elif max_node['cpus'] == node['cpus']:
                    if max_node['local_gb'] < node['local_gb']:
                        max_node = node

        dic = {'vcpus': max_node['cpus'],
               'memory_mb': max_node['memory_mb'],
               'local_gb': max_node['local_gb'],
               'vcpus_used': 0,
               'memory_mb_used': 0,
               'local_gb_used': 0,
               }
        return dic

    def refresh_instance_security_rules(self, instance):
        self._firewall_driver.refresh_instance_security_rules(instance)

    def update_available_resource(self, ctxt, host):
        """Updates compute manager resource info on ComputeNode table.

        This method is called when nova-coompute launches, and
        whenever admin executes "nova-manage service update_resource".

        :param ctxt: security context
        :param host: hostname that compute manager is currently running

        """

        dic = self._max_baremetal_resources(ctxt)
        #dic = self._sum_baremetal_resources(ctxt)
        dic['hypervisor_type'] = self.get_hypervisor_type()
        dic['hypervisor_version'] = self.get_hypervisor_version()
        dic['cpu_info'] = 'baremetal cpu'

        try:
            service_ref = db.service_get_all_compute_by_host(ctxt, host)[0]
        except exception.NotFound:
            raise exception.ComputeServiceUnavailable(host=host)

        dic['service_id'] = service_ref['id']

        compute_node_ref = service_ref['compute_node']
        if not compute_node_ref:
            LOG.info(_('Compute_service record created for %s ') % host)
            db.compute_node_create(ctxt, dic)
        else:
            LOG.info(_('Compute_service record updated for %s ') % host)
            db.compute_node_update(ctxt, compute_node_ref[0]['id'], dic)

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        self._firewall_driver.setup_basic_filtering(instance_ref, network_info)
        self._firewall_driver.prepare_instance_filter(instance_ref,
                                                      network_info)

    def unfilter_instance(self, instance_ref, network_info):
        self._firewall_driver.unfilter_instance(instance_ref,
                                                network_info=network_info)

    def _get_host_stats(self):
        dic = self._max_baremetal_resources(nova_context.get_admin_context())
        memory_total = dic['memory_mb'] * 1024 * 1024
        memory_free = (dic['memory_mb'] - dic['memory_mb_used']) * 1024 * 1024
        disk_total = dic['local_gb'] * 1024 * 1024 * 1024
        disk_used = dic['local_gb_used'] * 1024 * 1024 * 1024

        return {
          'host_name-description': 'baremetal ' + FLAGS.host,
          'host_hostname': FLAGS.host,
          'host_memory_total': memory_total,
          'host_memory_overhead': 0,
          'host_memory_free': memory_free,
          'host_memory_free_computed': memory_free,
          'host_other_config': {},
          'disk_available': disk_total - disk_used,
          'disk_total': disk_total,
          'disk_used': disk_used,
          'host_name_label': FLAGS.host,
          'cpu_arch': self._extra_specs.get('cpu_arch'),
          'instance_type_extra_specs': self._extra_specs,
          }

    def update_host_status(self):
        return self._get_host_stats()

    def get_host_stats(self, refresh=False):
        return self._get_host_stats()

    def plug_vifs(self, instance, network_info):
        """Plugin VIFs into networks."""
        self._plug_vifs(instance, network_info)

    def _plug_vifs(self, instance, network_info, context=None):
        if not context:
            context = nova_context.get_admin_context()
        node = _get_baremetal_node_by_instance_uuid(instance['uuid'])
        if node:
            pifs = bmdb.bm_interface_get_all_by_bm_node_id(context, node['id'])
            for pif in pifs:
                if pif['vif_uuid']:
                    bmdb.bm_interface_set_vif_uuid(context, pif['id'], None)
        for (network, mapping) in network_info:
            self._vif_driver.plug(instance, (network, mapping))

    def _unplug_vifs(self, instance, network_info):
        for (network, mapping) in network_info:
            self._vif_driver.unplug(instance, (network, mapping))

    def manage_image_cache(self, context):
        """Manage the local cache of images."""
        self._image_cache_manager.verify_base_images(context)

    def get_console_output(self, instance):
        node = _get_baremetal_node_by_instance_uuid(instance['uuid'])
        return self.baremetal_nodes.get_console_output(node, instance)

    def check_if_tftp_boot_image(self, image_meta):
        """
        check to see if a image is a tftp boot image
        """
        tftp_build = False
        if 'properties' in image_meta:
            if 'bmpxetftpinstaller' in image_meta['properties']:
                if image_meta['properties']['bmpxetftpinstaller']:
                    # this is a install image for tftp pxe booting bm nodes
                    # so we are going to handle it differently
                    LOG.debug("bmpxetftpinstaller set")
                    tftp_build = True
            else:
                LOG.debug("bmpxetftpinstaller not in image_meta properties")
        else:
            LOG.debug("properties not in image_meta")
        
        return tftp_build