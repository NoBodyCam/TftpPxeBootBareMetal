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

"""
Class for PXE bare-metal nodes.
"""

import os
import shutil

from nova.compute import instance_types
from nova import exception
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova import utils
from nova.virt.baremetal import bmdb
from nova.virt.baremetal import vlan
from nova.virt.disk import api as disk
from nova.virt.libvirt import utils as libvirt_utils


LOG = logging.getLogger(__name__)

pxe_opts = [
    cfg.BoolOpt('baremetal_use_unsafe_vlan',
                default=False,
                help='use baremetal node\'s vconfig for network isolation'),
    cfg.BoolOpt('baremetal_pxe_vlan_per_host',
                default=False),
    cfg.StrOpt('baremetal_pxe_parent_interface',
               default='eth0'),
    cfg.StrOpt('baremetal_pxelinux_path',
               default='/usr/lib/syslinux/pxelinux.0',
               help='path to pxelinux.0'),
    cfg.StrOpt('baremetal_dnsmasq_pid_dir',
               default='/var/lib/nova/baremetal/dnsmasq',
               help='path to directory stores pidfiles of dnsmasq'),
    cfg.StrOpt('baremetal_dnsmasq_lease_dir',
               default='/var/lib/nova/baremetal/dnsmasq',
               help='path to directory stores leasefiles of dnsmasq'),
    cfg.StrOpt('baremetal_kill_dnsmasq_path',
               default='bm_kill_dnsmasq',
               help='path to bm_kill_dnsmasq'),
    cfg.StrOpt('baremetal_deploy_kernel',
               help='kernel image ID used in deployment phase'),
    cfg.StrOpt('baremetal_deploy_ramdisk',
               help='ramdisk image ID used in deployment phase'),
    cfg.BoolOpt('baremetal_pxe_append_iscsi_portal',
                default=True,
                help='append "bm_iscsi_porttal=<portal_address>" '
                     'to instances\' /proc/cmdline'),
    cfg.StrOpt('baremetal_pxe_append_params',
               help='additional append parameters for baremetal pxe'),
            ]

FLAGS = flags.FLAGS
FLAGS.register_opts(pxe_opts)


def get_baremetal_nodes():
    return PXE()


Template = None


def _late_load_cheetah():
    global Template
    if Template is None:
        t = __import__('Cheetah.Template', globals(), locals(),
                       ['Template'], -1)
        Template = t.Template


def _dnsmasq_pid_path(pxe_interface):
    name = 'dnsmasq-%s.pid' % pxe_interface
    path = os.path.join(FLAGS.baremetal_dnsmasq_pid_dir, name)
    return path


def _dnsmasq_lease_path(pxe_interface):
    name = 'dnsmasq-%s.lease' % pxe_interface
    path = os.path.join(FLAGS.baremetal_dnsmasq_lease_dir, name)
    return path


def _dnsmasq_pid(pxe_interface):
    pidfile = _dnsmasq_pid_path(pxe_interface)
    if os.path.exists(pidfile):
        with open(pidfile, 'r') as f:
            return int(f.read())
    return None


def _unlink_without_raise(path):
    try:
        libvirt_utils.file_delete(path)
    except OSError:
        LOG.exception("failed to unlink %s" % path)


def _random_alnum(count):
    import random
    import string
    chars = string.ascii_uppercase + string.digits
    return "".join([random.choice(chars) for _ in range(count)])


def _start_dnsmasq(interface, tftp_root, client_address, pid_path, lease_path):
    utils.execute('dnsmasq',
             '--conf-file=',
             '--pid-file=%s' % pid_path,
             '--dhcp-leasefile=%s' % lease_path,
             '--port=0',
             '--bind-interfaces',
             '--interface=%s' % interface,
             '--enable-tftp',
             '--tftp-root=%s' % tftp_root,
             '--dhcp-boot=pxelinux.0',
             '--dhcp-range=%s,%s' % (client_address, client_address))


def _cache_image_x(context, target, image_id,
                   user_id, project_id):
    if not os.path.exists(target):
        libvirt_utils.fetch_image(context, target, image_id,
                                  user_id, project_id)


def _build_pxe_config(deployment_id, deployment_key, iscsi_iqn,
                      deploy_aki_path, deploy_ari_path, aki_path, ari_path,
                      iscsi_portal):
    # 'default deploy' will be replaced to 'default boot' by bm_deploy_server
    pxeconf = "default deploy\n"
    pxeconf += "\n"

    pxeconf += "label deploy\n"
    pxeconf += "kernel %s\n" % deploy_aki_path
    pxeconf += "append"
    pxeconf += " initrd=%s" % deploy_ari_path
    pxeconf += " selinux=0"
    pxeconf += " disk=cciss/c0d0,sda,hda"
    pxeconf += " iscsi_target_iqn=%s" % iscsi_iqn
    pxeconf += " deployment_id=%s" % deployment_id
    pxeconf += " deployment_key=%s" % deployment_key
    if FLAGS.baremetal_pxe_append_params:
        pxeconf += " %s" % FLAGS.baremetal_pxe_append_params
    pxeconf += "\n"
    pxeconf += "ipappend 3\n"
    pxeconf += "\n"

    pxeconf += "label boot\n"
    pxeconf += "kernel %s\n" % aki_path
    pxeconf += "append"
    pxeconf += " initrd=%s" % ari_path
    # ${ROOT} will be replaced to UUID=... by bm_deploy_server
    pxeconf += " root=${ROOT} ro"
    if iscsi_portal:
        pxeconf += ' bm_iscsi_portal=%s' % iscsi_portal
    if FLAGS.baremetal_pxe_append_params:
        pxeconf += " %s" % FLAGS.baremetal_pxe_append_params
    pxeconf += "\n"
    pxeconf += "\n"
    return pxeconf


def _start_per_host_pxe_server(tftp_root, vlan_id,
                               server_address, client_address):
    parent_interface = FLAGS.baremetal_pxe_parent_interface

    pxe_interface = vlan.ensure_vlan(vlan_id, parent_interface)

    from nova.network import linux_net

    chain = 'bm-%s' % pxe_interface
    iptables = linux_net.iptables_manager
    f = iptables.ipv4['filter']
    f.add_chain(chain)
    f.add_rule('INPUT', '-i %s -j $%s' % (pxe_interface, chain))
    f.add_rule(chain, '--proto udp --sport=68 --dport=67 -j ACCEPT')
    f.add_rule(chain, '-s %s -j ACCEPT' % client_address)
    f.add_rule(chain, '-j DROP')
    iptables.apply()

    utils.execute('ip', 'address',
            'add', server_address + '/24',
            'dev', pxe_interface,
            run_as_root=True)
    utils.execute('ip', 'route', 'add',
            client_address, 'scope', 'host', 'dev', pxe_interface,
            run_as_root=True)

    shutil.copyfile(FLAGS.baremetal_pxelinux_path,
                    os.path.join(tftp_root, 'pxelinux.0'))
    libvirt_utils.ensure_tree(os.path.join(tftp_root, 'pxelinux.cfg'))

    _start_dnsmasq(interface=pxe_interface,
                   tftp_root=tftp_root,
                   client_address=client_address,
                   pid_path=_dnsmasq_pid_path(pxe_interface),
                   lease_path=_dnsmasq_lease_path(pxe_interface))


def _stop_per_host_pxe_server(tftp_root, vlan_id):
    pxe_interface = 'vlan%d' % vlan_id

    dnsmasq_pid = _dnsmasq_pid(pxe_interface)
    if dnsmasq_pid:
        utils.execute(FLAGS.baremetal_kill_dnsmasq_path,
                      str(dnsmasq_pid),
                      run_as_root=True)
    _unlink_without_raise(_dnsmasq_pid_path(pxe_interface))
    _unlink_without_raise(_dnsmasq_lease_path(pxe_interface))

    vlan.ensure_no_vlan(vlan_id, FLAGS.baremetal_pxe_parent_interface)

    shutil.rmtree(os.path.join(tftp_root, 'pxelinux.cfg'), ignore_errors=True)

    from nova.network import linux_net
    chain = 'bm-%s' % pxe_interface
    iptables = linux_net.iptables_manager
    iptables.ipv4['filter'].remove_chain(chain)
    iptables.apply()


class PXE(object):

    def __init__(self):
        if not FLAGS.baremetal_deploy_kernel:
            raise exception.NovaException(
                    'baremetal_deploy_kernel is not defined')
        if not FLAGS.baremetal_deploy_ramdisk:
            raise exception.NovaException(
                    'baremetal_deploy_ramdisk is not defined')

    def define_vars(self, instance, network_info, block_device_info):
        var = {}
        var['image_root'] = os.path.join(FLAGS.instances_path,
                                         instance['name'])
        if FLAGS.baremetal_pxe_vlan_per_host:
            var['tftp_root'] = os.path.join(FLAGS.baremetal_tftp_root,
                                            str(instance['uuid']))
        else:
            var['tftp_root'] = FLAGS.baremetal_tftp_root
        var['network_info'] = network_info
        var['block_device_info'] = block_device_info
        return var

    def _inject_to_image(self, context, target, node, inst, network_info,
                         injected_files=None, admin_password=None):
        # For now, we assume that if we're not using a kernel, we're using a
        # partitioned disk image where the target partition is the first
        # partition
        target_partition = None
        if not inst['kernel_id']:
            target_partition = "1"

        nics_in_order = []
        pifs = bmdb.bm_interface_get_all_by_bm_node_id(context, node['id'])
        for pif in pifs:
            nics_in_order.append(pif['address'])
        nics_in_order.append(node['prov_mac_address'])

        # rename nics to be in the order in the DB
        LOG.debug("injecting persistent net")
        rules = ""
        i = 0
        for hwaddr in nics_in_order:
            rules += 'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ' \
                     'ATTR{address}=="%s", ATTR{dev_id}=="0x0", ' \
                     'ATTR{type}=="1", KERNEL=="eth*", NAME="eth%d"\n' \
                     % (hwaddr.lower(), i)
            i += 1
        if not injected_files:
            injected_files = []
        injected_files.append(('/etc/udev/rules.d/70-persistent-net.rules',
                               rules))
        bootif_name = "eth%d" % (i - 1)

        if inst['key_data']:
            key = str(inst['key_data'])
        else:
            key = None
        net = ""
        nets = []
        ifc_template = open(FLAGS.baremetal_injected_network_template).read()
        ifc_num = -1
        have_injected_networks = False
        for (network_ref, mapping) in network_info:
            ifc_num += 1
            # always inject
            #if not network_ref['injected']:
            #    continue
            have_injected_networks = True
            address = mapping['ips'][0]['ip']
            netmask = mapping['ips'][0]['netmask']
            address_v6 = None
            gateway_v6 = None
            netmask_v6 = None
            if FLAGS.use_ipv6:
                address_v6 = mapping['ip6s'][0]['ip']
                netmask_v6 = mapping['ip6s'][0]['netmask']
                gateway_v6 = mapping['gateway_v6']
            name = 'eth%d' % ifc_num
            if FLAGS.baremetal_use_unsafe_vlan \
                    and mapping['should_create_vlan'] \
                    and network_ref.get('vlan'):
                name = 'eth%d.%d' % (ifc_num, network_ref.get('vlan'))
            net_info = {'name': name,
                   'address': address,
                   'netmask': netmask,
                   'gateway': mapping['gateway'],
                   'broadcast': mapping['broadcast'],
                   'dns': ' '.join(mapping['dns']),
                   'address_v6': address_v6,
                   'gateway_v6': gateway_v6,
                   'netmask_v6': netmask_v6,
                   'hwaddress': mapping['mac']}
            nets.append(net_info)

        if have_injected_networks:
            _late_load_cheetah()
            net = str(Template(ifc_template,
                               searchList=[{'interfaces': nets,
                                            'use_ipv6': FLAGS.use_ipv6}]))
        net += "\n"
        net += "auto %s\n" % bootif_name
        net += "iface %s inet dhcp\n" % bootif_name

        if not FLAGS.baremetal_inject_password:
            admin_password = None

        metadata = inst.get('metadata')
        if any((key, net, metadata, admin_password)):
            inst_name = inst['name']

            img_id = inst['image_ref']

            for injection in ('metadata', 'key', 'net', 'admin_password'):
                if locals()[injection]:
                    LOG.info(_('instance %(inst_name)s: injecting '
                               '%(injection)s into image %(img_id)s'),
                             locals(), instance=inst)
            try:
                disk.inject_data(target,
                                 key, net, metadata, admin_password,
                                 files=injected_files,
                                 partition=target_partition,
                                 use_cow=False)

            except Exception as e:
                # This could be a windows image, or a vmdk format disk
                LOG.warn(_('instance %(inst_name)s: ignoring error injecting'
                        ' data into image %(img_id)s (%(e)s)') % locals(),
                         instance=inst)

    def create_image(self, var, context, image_meta, node, instance,
                     injected_files=None, admin_password=None):
        image_root = var['image_root']
        network_info = var['network_info']

        ami_id = str(image_meta['id'])
        libvirt_utils.ensure_tree(image_root)
        image_path = os.path.join(image_root, 'disk')
        LOG.debug("fetching image id=%s target=%s", ami_id, image_path)

        _cache_image_x(context=context,
                       target=image_path,
                       image_id=ami_id,
                       user_id=instance['user_id'],
                       project_id=instance['project_id'])

        LOG.debug("injecting to image id=%s target=%s", ami_id, image_path)
        self._inject_to_image(context, image_path, node,
                              instance, network_info,
                              injected_files=injected_files,
                              admin_password=admin_password)
        var['image_path'] = image_path
        LOG.debug("fetching images all done")

    def destroy_images(self, var, context, node, instance):
        image_root = var['image_root']
        shutil.rmtree(image_root, ignore_errors=True)

    def _pxe_cfg_name(self, node):
        name = "01-" + node['prov_mac_address'].replace(":", "-").lower()
        return name

    def activate_bootloader(self, var, context, node, instance):
        tftp_root = var['tftp_root']
        image_path = var['image_path']

        deploy_aki_id = FLAGS.baremetal_deploy_kernel
        deploy_ari_id = FLAGS.baremetal_deploy_ramdisk
        aki_id = str(instance['kernel_id'])
        ari_id = str(instance['ramdisk_id'])

        images = [(deploy_aki_id, 'deploy_kernel'),
                  (deploy_ari_id, 'deploy_ramdisk'),
                  (aki_id, 'kernel'),
                  (ari_id, 'ramdisk'),
                  ]

        libvirt_utils.ensure_tree(tftp_root)
        if FLAGS.baremetal_pxe_vlan_per_host:
            tftp_paths = [i[1] for i in images]
        else:
            tftp_paths = [os.path.join(str(instance['uuid']), i[1])
                    for i in images]
            libvirt_utils.ensure_tree(
                    os.path.join(tftp_root, str(instance['uuid'])))

        LOG.debug("tftp_paths=%s", tftp_paths)

        def _cache_image_b(image_id, target):
            LOG.debug("fetching id=%s target=%s", image_id, target)
            _cache_image_x(context=context,
                           image_id=image_id,
                           target=target,
                           user_id=instance['user_id'],
                           project_id=instance['project_id'])

        for image, path in zip(images, tftp_paths):
            target = os.path.join(tftp_root, path)
            _cache_image_b(image[0], target)

        pxe_config_dir = os.path.join(tftp_root, 'pxelinux.cfg')
        pxe_config_path = os.path.join(pxe_config_dir,
                                       self._pxe_cfg_name(node))

        root_mb = instance['root_gb'] * 1024

        inst_type_id = instance['instance_type_id']
        inst_type = instance_types.get_instance_type(inst_type_id)
        swap_mb = inst_type['swap']
        if swap_mb < 1024:
            swap_mb = 1024

        pxe_ip = None
        if FLAGS.baremetal_pxe_vlan_per_host:
            pxe_ip_id = bmdb.bm_pxe_ip_associate(context, node['id'])
            pxe_ip = bmdb.bm_pxe_ip_get(context, pxe_ip_id)

        deployment_key = _random_alnum(32)
        deployment_id = bmdb.bm_deployment_create(context, deployment_key,
                                                  image_path, pxe_config_path,
                                                  root_mb, swap_mb)
        iscsi_iqn = "iqn-%s" % str(instance['uuid'])
        iscsi_portal = None
        if FLAGS.baremetal_pxe_append_iscsi_portal:
            if pxe_ip:
                iscsi_portal = pxe_ip['server_address']
        pxeconf = _build_pxe_config(deployment_id, deployment_key, iscsi_iqn,
            tftp_paths[0], tftp_paths[1], tftp_paths[2], tftp_paths[3],
            iscsi_portal)

        libvirt_utils.ensure_tree(pxe_config_dir)
        libvirt_utils.write_to_file(pxe_config_path, pxeconf)

        if FLAGS.baremetal_pxe_vlan_per_host:
            vlan_id = node['prov_vlan_id']
            server_address = pxe_ip['server_address']
            client_address = pxe_ip['address']
            _start_per_host_pxe_server(tftp_root, vlan_id,
                                       server_address, client_address)

    def deactivate_bootloader(self, var, context, node, instance):
        tftp_root = var['tftp_root']

        if FLAGS.baremetal_pxe_vlan_per_host:
            _stop_per_host_pxe_server(tftp_root, node['prov_vlan_id'])
            bmdb.bm_pxe_ip_disassociate(context, node['id'])
            tftp_image_dir = tftp_root
        else:
            tftp_image_dir = os.path.join(tftp_root, str(instance['uuid']))
        shutil.rmtree(tftp_image_dir, ignore_errors=True)

        pxe_config_path = os.path.join(tftp_root,
                                       "pxelinux.cfg",
                                       self._pxe_cfg_name(node))
        _unlink_without_raise(pxe_config_path)

    def activate_node(self, var, context, node, instance):
        pass

    def deactivate_node(self, var, context, node, instance):
        pass

    def get_console_output(self, node, instance):
        raise NotImplementedError()
