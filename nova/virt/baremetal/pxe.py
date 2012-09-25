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
import signal
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
                help='use baremetal nodes vconfig for network isolation'),
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
                     'to instances /proc/cmdline'),
    cfg.StrOpt('baremetal_pxe_append_params',
                default=None,
                help='additional append parameters for baremetal pxe'),
    cfg.StrOpt('baremetal_pxe_tftp_boot_kernel_options_file',
                default='install_inc/txt.cfg',
                help='file for pxe boot kernel options'),
    cfg.StrOpt('baremetal_pxe_tftp_base_url',
                default=None,
                help='base url for pxe tftp install'),
    cfg.StrOpt('baremetal_pxe_tftp_node_default_interface',
                default='eth2',
                help='local net dev for pxe tftp node'),
    cfg.StrOpt('baremetal_pxe_tftp_node_gateway_override',
                default='10.10.16.193',
                help='override passed to node to support environment testing'),
    cfg.StrOpt('baremetal_pxe_tftp_node_netmask_override',
                default='255.255.255.192',
                help='override passed to node to support environment testing'),
    cfg.StrOpt('baremetal_pxe_tftp_node_broadcast_override',
                default='10.10.16.255',
                help='override passed to node to support environment testing'),
    cfg.StrOpt('baremetal_pxe_tftp_node_dns_override',
                default='208.67.222.222',
                help='override passed to node to support environment testing'),
    cfg.StrOpt('baremetal_pxe_tftp_node_hwaddress_override',
                default=None,
                help='override passed to node to support environment testing'),
    cfg.StrOpt('baremetal_dnsmasq_dhcp_host_file',
                default='/var/lib/nova/baremetal/dnsmasq/dnsmasq-dhcp.host',
                help='baremetal dnsmasq dhcp lease reservation location'),
    cfg.StrOpt('baremetal_tftp_web_store_path',
                default=None,
                help='web storage path for tftp files'),
           ]

FLAGS = flags.FLAGS
FLAGS.register_opts(pxe_opts)


# support for override values (for limited raq testing)
override_check = {'interface': FLAGS.baremetal_pxe_tftp_node_default_interface,
    'gateway': FLAGS.baremetal_pxe_tftp_node_gateway_override,
    'netmask': FLAGS.baremetal_pxe_tftp_node_netmask_override,
    'broadcast': FLAGS.baremetal_pxe_tftp_node_broadcast_override,
    'dns': FLAGS.baremetal_pxe_tftp_node_dns_override
    }
    

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

def _start_tftp_dnsmasq(interface, tftp_root, host_path, pid_path, lease_path):
    """
    Start dnsmasq
    """
    LOG.debug(_("Start dnsMasq with :"))
    LOG.debug(_("interface: %s ") % interface)
    LOG.debug(_("tftp_root: %s ") % tftp_root)
    LOG.debug(_("host_path: %s ") % host_path)
    LOG.debug(_("pid_path: %s ") % pid_path)
    LOG.debug(_("lease_path: %s ") % lease_path)

    # this can be done better I'm sure 
    if os.path.exists(pid_path):
        # dnsmasq running ... stop it
        LOG.debug("dnsmasq running stopping for restart")
        f = open(pid_path)
        pid_to_stop = f.readline()
        pid_to_stop = pid_to_stop.rstrip('\n')
        f.close()
        try:
            os.kill(int(pid_to_stop), signal.SIGTERM)
        except OSError:
            LOG.debug("Removing stale dnsmasq pid file.")
            os.unlink(pid_path)       
    else:
        LOG.debug(_("dnsmasq not running"))
        
    # we need to set --dhcp-range for each ip listed in host_path
    dhcp_range_options = ''
    tmp_dhcp_mac = ''
    tmp_dhcp_name = ''
    tmp_dhcp_address = ''
    f = open(_("%s" % host_path) , 'r')
    for line in f: 
        tmp_dhcp_mac, tmp_dhcp_name, tmp_dhcp_address = line.split(',')
        tmp_dhcp_address = tmp_dhcp_address.rstrip('\r\n')
        dhcp_range_options += '--dhcp-range=%s,%s ' % (tmp_dhcp_address, 
            tmp_dhcp_address)
    f.close()
    dhcp_range_options.rstrip()

    # now restart dnsmasq
    tmp_cmd_result = utils.execute('sudo', 'dnsmasq',
        '--conf-file=',
        '--pid-file=%s' % pid_path,
        '--dhcp-leasefile=%s' % lease_path,
        '--port=0',
        dhcp_range_options,
        '--interface=%s' % interface,
        '--enable-tftp',
        '--tftp-root=%s' % tftp_root,
        '--tftp-unique-root',
        '--dhcp-boot=pxelinux.0',
        '--dhcp-hostsfile=%s' % host_path )

    LOG.debug(_("Command result: %s") % str(tmp_cmd_result))
    # now because we started with sudo. a quick fix
    if os.path.exists(pid_path):
        LOG.debug(_("Setting ownership on: %s") % str(pid_path))
        utils.execute('sudo', 'chown', 'stack:stack', pid_path)
    if os.path.exists(lease_path):
        LOG.debug(_("Setting ownership on: %s") % str(lease_path))
        utils.execute('sudo', 'chown', 'stack:stack', lease_path)

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
        mount_check = os.path.join(image_root, 'mnt')
        self.unmount_tftp_image(mount_check)
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

    def deactivate_tftp_node(self, var, context, node, instance):
        # remove tftp files
        network_info = var['network_info']
        node_ip = self.get_value_from_net_info(network_info, 'ip')
        node_tftp_path = os.path.join(var['tftp_root'], node_ip)
        node_image_mont_unpac_path = os.path.join(var['image_root'], 'mnt')
        self.remove_tftp_boot_directories(node_tftp_path, 
            node_image_mont_unpac_path, node_ip)
        
    def activate_node(self, var, context, node, instance):
        pass

    def deactivate_node(self, var, context, node, instance):
        pass

    def get_console_output(self, node, instance):
        raise NotImplementedError()

    def create_pxe_tftp_boot_image_files(self, var, node, context, instance, 
        image_meta, admin_password, block_device_info):
        """
        create tftp boot files
        """
        def filename_ext(filename='', ext=''):
            return _("%s.%s") % (filename, ext)

        LOG.debug("create_pxe_tftp_boot_image_files")
        LOG.debug(_("setting up tftp for %s") % instance['name'])
        
        image_id = str(image_meta['id'])
        image_root = var['image_root']
        image_file_name = ''
        image_mnt_unpac_path = os.path.join(image_root, 'mnt')
        image_distro = image_meta['properties']['distro']
        network_info = var['network_info']
        node_host_name = instance['hostname']
        # ensure instance-######## dir exists
        libvirt_utils.ensure_tree(image_root)
        # ensure mount / unpack point exists
        libvirt_utils.ensure_tree(image_mnt_unpac_path)
        
        #build image the file name
        if image_meta['disk_format'] == "iso":
            image_file_name = filename_ext(image_distro, "iso")
        elif image_meta['disk_format'] == "raw":
            image_file_name = filename_ext(image_distro, "tar.gz")
        else:
            raise exception.NovaException(_("unsupported disk type"))
            return            

        image_file_full_path = os.path.join(image_root, image_file_name)


        LOG.debug("fetching image id=%s to=%s as=%s", image_id, image_root, 
            image_file_name)
    
        _cache_image_x(context=context,
              target=image_file_full_path,
              image_id=image_id,
              user_id=instance['user_id'],
              project_id=instance['project_id'])

        LOG.info("Creating image pxe tftp templates")

        self.mount_unpac_tftp_image(image_file_full_path, image_mnt_unpac_path, 
            image_meta['disk_format'])

        self.setup_tftp_boot_directories(instance, network_info, var, 
            image_distro, node_host_name, node, admin_password)

        self.unmount_tftp_image(image_mnt_unpac_path)

    def setup_tftp_boot_directories(self, instance, network_info, var,
        image_distro, node_host_name, node, admin_password):
        """
        Setup the tftp boot directories and files
        Check to see if the directories / files we are about to create
        exist. if they do delete them
        """
        LOG.debug(_("checking for tftp boot directories before setup."))
        node_ip = self.get_value_from_net_info(network_info, 'ip')
        node_image_mont_unpac_path = os.path.join(var['image_root'], 'mnt')
        node_tftp_path = os.path.join(var['tftp_root'], node_ip)

        # this could / should do a check sum thing. maybe later
        if self.check_tftp_boot_directories(node_tftp_path, 
            node_image_mont_unpac_path, node_ip):
            # directories or files found remove them
            self.remove_tftp_boot_directories(node_tftp_path, 
                node_image_mont_unpac_path, node_ip)

        LOG.debug(_("setting up tftp boot (distro: %s / host name: %s )") % 
           (image_distro, node_host_name))
        
        if not os.path.isdir(node_tftp_path):
            # root tftp directory not found. Create it
            LOG.debug(_("Directory %s not found creating") % node_tftp_path)
            os.makedirs(node_tftp_path)
    
        # copy the pxe boot files into place
        master_boot_tree = os.path.join(node_image_mont_unpac_path, 
            image_distro)
        files_to_copy = os.listdir(master_boot_tree)
        for working_file in files_to_copy:
            src = os.path.join(master_boot_tree, working_file)
            dst = os.path.join(node_tftp_path, working_file)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src,dst)
  
        # setup pxe boot kernel options file for tftp
        self.setup_tftp_boot_kernel_options_file(node_tftp_path, node_ip, 
            node_host_name, image_distro)

        web_store_location = os.path.join(FLAGS.baremetal_tftp_web_store_path, 
            node_ip)

        if not os.path.isdir(web_store_location):
            # tftp conf directory not found. Create it
            LOG.debug(_("Directory %s not found creating") % web_store_location)
            os.makedirs(web_store_location)

        # now the preseed and other install files
        self.create_node_tftp_files(node_host_name, var, instance, 
            image_distro, node, admin_password)

    def get_value_from_net_info(self, network_info, look_for=''):
        """
        get first value from network_info and return it
        """
        return_value = ''        
        if look_for:
            if look_for == 'interface':
                # default to eth 0 for most systems
                return_value = 'eth0'
            else:
                LOG.debug(_("Looking for network value: %s") % look_for)
                for tmp_net in network_info:
                    if not return_value and look_for == 'broadcast':
                        return_value = tmp_net[1]['broadcast']
                    elif not return_value and look_for == 'dns':
                        return_value = tmp_net[1]['dns']
                    for tmp_ips in tmp_net[1]['ips']:
                        if not return_value:
                            return_value = tmp_ips[look_for]
        else:
            return_value = "nothing to look up."

        
        # support for override values (for limited raq testing)
        if look_for in override_check:
            if override_check[look_for]:
                LOG.debug("using network override value")
                return_value = override_check[look_for]
        
        LOG.debug(_("Returning : %s") % return_value)
        return return_value

    def check_tftp_boot_directories(self, node_tftp_path, 
        node_image_mont_unpac_path, node_ip):
        """
        check for the pxe boot directories and files needed to boot a node
        """
        anything_found = False
        LOG.debug(_("checking pxe files for at: %s") % node_tftp_path)
        # first check for the tptp boot dir
        
        if os.path.exists(node_tftp_path):
            anything_found = True
            LOG.debug(_("Found: %s") % node_tftp_path)

        # now the pre / post cfg files
        web_store_location = os.path.join(FLAGS.baremetal_tftp_web_store_path, 
            node_ip)

        if os.path.exists(web_store_location):
            anything_found = True
            LOG.debug(_("Found: %s") % web_store_location)

        return anything_found

    def get_pxe_file_name(self, file_name, node_ip):
        """
        returns file name for preseed file
        """
        pxe_file_name = file_name.replace('template', node_ip)
        return pxe_file_name

    def remove_tftp_boot_directories(self, node_tftp_path, 
        node_image_mont_unpac_path, node_ip):
        """
        remove the pxe boot directories and files needed to boot a node
        """
        LOG.debug(_("removing pxe tftp boot files for Ip: %s") % node_ip)
        if os.path.isdir(node_tftp_path):
            shutil.rmtree(node_tftp_path)
            LOG.debug(_("removed %s") % node_tftp_path)
        else:
            LOG.debug(_("%s not found") % node_tftp_path)
            
        # now the cfg files
        LOG.debug(_("removing pxe config files for Ip: %s") % node_ip)
        # now the pre / post cfg files
        web_store_location = os.path.join(FLAGS.baremetal_tftp_web_store_path, 
            node_ip)
        if os.path.isdir(web_store_location):
            shutil.rmtree(web_store_location)
            LOG.debug(_("removed %s") % web_store_location)
        else:
            LOG.debug(_("%s not found") % web_store_location)

    def create_node_tftp_files(self, node_hostname, var, instance, 
        image_distro, node, admin_password):
        """
        Creates a preseed / kickstart file for baremetal node 
        places it a http accessible directory
        """
        LOG.debug(_("Creating pre/post-install files for node : %s") % 
            node_hostname)
        # setup what we need to build our templates
        master_template_path = os.path.join(var['image_root'], 'mnt', 
            'templates')
        master_templates = os.listdir(master_template_path)
        network_info = var['network_info']
        node_ip = self.get_value_from_net_info(network_info, look_for='ip')
        node_web_store_path = os.path.join(FLAGS.baremetal_tftp_web_store_path, 
            node_ip)

        node_net_netmask = self.get_value_from_net_info(network_info, 
            look_for='netmask')
   
        node_net_gateway = self.get_value_from_net_info(network_info, 
            look_for='gateway')

        node_net_broadcast = self.get_value_from_net_info(network_info, 
            look_for='broadcast')

        node_net_dns = self.get_value_from_net_info(network_info, 
            look_for='dns')

        node_net_name = self.get_value_from_net_info(network_info, 
            look_for='interface')
                
        node_net_hwaddress = node['prov_mac_address']

        tmp_root_key_url = _(self.get_node_tftp_conf_base_url(node_ip) +
            image_distro + '.root_key.' + node_ip)
        tmp_interface_url = _(self.get_node_tftp_conf_base_url(node_ip) 
            + image_distro + '.interface.' + node_ip)

        tmp_repo_url = FLAGS.baremetal_pxe_tftp_base_url


        for filename in master_templates:
            file_to_create = self.get_pxe_file_name(filename, node_ip)
            web_store_location = os.path.join(node_web_store_path, 
                file_to_create)

            template_file = os.path.join(master_template_path, filename)

            template_file_text = open(template_file).read()

            template_values = {'root_key_url': tmp_root_key_url, 
                'interface_file_url': tmp_interface_url,
                'name': node_net_name, 
                'address': node_ip, 
                'netmask': node_net_netmask, 
                'broadcast': node_net_broadcast, 
                'gateway': node_net_gateway, 
                'dns': node_net_dns, 
                'hwaddress': node_net_hwaddress,
                'root_key': instance['key_data']
                }
 
            if 'preseed' in filename:
                LOG.debug("Setup preseed file")
            elif 'interface' in filename:
                LOG.debug("Setup interface vars")
            elif 'root_key' in filename:
                LOG.debug("Setup root key vars")
            else:
                LOG.debug("Setup static file")

            # not sure what going on here.. this should work
            #_late_load_cheetah()
            #template_filled_in = str(Template(template_file_text, 
            #    searchList={'template_values': template_values}))
            # because template system just not working
            template_file_text = template_file_text.replace( 
                '${template_values.ssh_key}', instance['key_data'])
            template_file_text = template_file_text.replace(
                '${template_values.name}', node_net_name)
            template_file_text = template_file_text.replace(
                '${template_values.address}', node_ip)
            template_file_text = template_file_text.replace(
                '${template_values.netmask}', node_net_netmask)
            template_file_text = template_file_text.replace(
                '${template_values.broadcast}', node_net_broadcast)
            template_file_text = template_file_text.replace(
                '${template_values.gateway}', node_net_gateway)
            template_file_text = template_file_text.replace(
                '${template_values.dns}', node_net_dns)
            template_file_text = template_file_text.replace(
                '${template_values.hwaddress}', node_net_hwaddress)
            template_file_text = template_file_text.replace(
                '${template_values.root_key_url}', tmp_root_key_url)
            template_file_text = template_file_text.replace(
                '${template_values.interface_file_url}', tmp_interface_url)
            template_file_text = template_file_text.replace(
                '${template_values.address}', node_ip)
            template_file_text = template_file_text.replace(
                '${template_values.netmask}', node_net_netmask)
            template_file_text = template_file_text.replace(
                '${template_values.name}', node_hostname)
            template_file_text = template_file_text.replace(
                '${template_values.interface}', node_net_name)
            template_file_text = template_file_text.replace(
                '${template_values.repo_url}',  tmp_repo_url)
            template_file_text = template_file_text.replace( 
                '${template_values.admin_password}', admin_password)

            template_filled_in = template_file_text

            LOG.debug(_("Saving file: %s") % web_store_location)
            f = open(web_store_location, 'w+')
            f.write(template_filled_in)
            f.close()
            
    def setup_node_dnsmasq(self, node, var, instance):
        """
        Setup dnsmasq for dhcp booting a tftp node
        """
        node_mac_address = node['prov_mac_address']
        network_info = var['network_info']
        node_ip = self.get_value_from_net_info(network_info, look_for='ip')
        node_host_name = instance['hostname']
        dhcp_conf_line_txt = self.get_dhcp_conf_line(node_mac_address, node_ip, 
            node_host_name)
        dhcp_host_file = FLAGS.baremetal_dnsmasq_dhcp_host_file
        self.add_line_to_dhcp(dhcp_conf_line_txt, dhcp_host_file)

        pxe_interface = FLAGS.flat_interface
        dnsmasq_pid_path = _dnsmasq_pid_path(pxe_interface)
        dnsmasq_lease_path = _dnsmasq_lease_path(pxe_interface)
 
        _start_tftp_dnsmasq(interface=pxe_interface,
                       tftp_root=var['tftp_root'],
                       host_path=dhcp_host_file,
                       pid_path=dnsmasq_pid_path,
                       lease_path=dnsmasq_lease_path)

    def get_dhcp_conf_line(self, node_mac_address, domain_ip, domain_name):
        """
        Return a line for dnsmasq's dhcp file
        """
        LOG.debug(_("get_dhcp_conf_line (node_mac_address:%s / ip: %s / name: %s)")
            % (node_mac_address, domain_ip, domain_name))
        return (_("%s,%s,%s") % (node_mac_address, domain_name, domain_ip) )

    def add_line_to_dhcp(self, line_to_add_to_file, file_to_add_line_to):
        """
        add line to dhcp lease file if not there
        """
        LOG.debug(_("Checking for line (%s) in %s") % 
            (line_to_add_to_file, file_to_add_line_to))
        line_to_add_to_file += "\n"
        line_found = 0
        f = open(file_to_add_line_to , 'r+')
        for line in f: 
            if line_to_add_to_file in line:
                LOG.debug(_("Line found."))
                line_found = 1
        f.close()
        if line_found == 0:
            LOG.debug(_("Line not found. Adding"))
            f = open(file_to_add_line_to, 'a+')
            f.write(line_to_add_to_file)
            f.close()

    def del_line_from_dhcp(self, line_to_del_from_file, file_to_del_line_from):
        """
        delete line from dhcp file
        """
        LOG.debug(_("deleting line (%s) in %s") 
            % (line_to_del_from_file, file_to_del_line_from))
        if os.path.exists(file_to_del_line_from):
            f = open(file_to_del_line_from , 'r+')
            current_file_lines = f.readlines()
            f.close()
            f = open(file_to_del_line_from, 'w+')
            for line in current_file_lines: 
                if line_to_del_from_file not in line:
                    f.write(line)
                else:
                    LOG.debug(_("Found Line Removing."))
            f.close()

    def remove_node_dnsmasq(self, node, var, instance):
        """
        remove dnsmasq for dhcp booting a tftp node
        """
        LOG.debug(_("Removing dhcp for node #: %s") % node['id'])
        host_tftp_root = var['tftp_root']
        node_mac_address = node['prov_mac_address']
        dhcp_host_file = FLAGS.baremetal_dnsmasq_dhcp_host_file
        
        pxe_interface = FLAGS.flat_interface
        dnsmasq_pid_path = _dnsmasq_pid_path(pxe_interface)
        dnsmasq_lease_path = _dnsmasq_lease_path(pxe_interface)

        self.del_line_from_dhcp(node_mac_address, dhcp_host_file)
        self.del_line_from_dhcp(node_mac_address, dnsmasq_lease_path) 
        
        _start_tftp_dnsmasq(interface=pxe_interface,
                       tftp_root=host_tftp_root, 
                       host_path=dhcp_host_file, 
                       pid_path=dnsmasq_pid_path, 
                       lease_path=dnsmasq_lease_path)

    def mount_unpac_tftp_image(self, image_file_full_path, 
        image_mnt_unpac_path, image_format):
        """
        mount or untar tftp image
        """
        if image_format == "iso":
            LOG.debug(_("mounting %s to %s") % (image_file_full_path, 
                image_mnt_unpac_path))

            utils.execute('sudo', 'mount', '-o', 'loop', image_file_full_path, 
                image_mnt_unpac_path)

        elif image_format == "raw":
            LOG.debug(_("untaring %s to %s") % (image_file_full_path, 
                image_mnt_unpac_path))
                
            utils.execute('sudo', 'tar', '-xzf', image_file_full_path, '-C', 
                image_mnt_unpac_path)

    def unmount_tftp_image(self, image_mnt_unpac_path):
        """
        Un-mount the tftp iso ... if its mounted
        """
        if os.path.exists(image_mnt_unpac_path):
            if os.path.ismount(image_mnt_unpac_path):
                LOG.debug(_("unmounting master tftp image (%s)") %
                    image_mnt_unpac_path)
                utils.execute('sudo', 'umount', image_mnt_unpac_path)
    
    def setup_tftp_boot_kernel_options_file(self, node_tftp_path, node_ip, 
        node_host_name, image_distro):
        """
        Setup what is needed for the tftp boot loader kernel 
        options.
        
        TODO: make FLAGS.baremetal_pxe_tftp_boot_kernel_options_file
        an option of the tftp image and not a flag
        
        make FLAGS.baremetal_pxe_tftp_node_default_interface a
        option of the node
        """
        kernel_options_file = os.path.join(node_tftp_path, 
        FLAGS.baremetal_pxe_tftp_boot_kernel_options_file)

        LOG.debug(_("configuring kernel options file (%s)") % 
            kernel_options_file)
        
        template_file_text = open(kernel_options_file).read()

        tmp_interface = FLAGS.baremetal_pxe_tftp_node_default_interface
        tmp_hostname = node_host_name
        tmp_preseed_filename = _(image_distro + '.preseed.' + node_ip)
        tmp_preseed_base_url = self.get_node_tftp_conf_base_url(node_ip)
        tmp_preseed_url = _(tmp_preseed_base_url + tmp_preseed_filename)
        template_values = {'interface': tmp_interface, 'hostname': tmp_hostname, 
            'preseed_url': tmp_preseed_url}
        
        # not sure what going on here.. this should work
        #_late_load_cheetah()
        #template_filled_in = str(Template(template_file_text, 
        #    searchList={'template_values': template_values}))

        # because template system just not working
        template_file_text = template_file_text.replace( 
            '${template_values.interface}', tmp_interface)
        template_file_text = template_file_text.replace( 
            '${template_values.hostname}', tmp_hostname)
        template_file_text = template_file_text.replace( 
            '${template_values.preseed_url}', tmp_preseed_url)
        template_filled_in = template_file_text

        # save the kernel options file
        f = open(kernel_options_file, 'w+')
        f.write(template_filled_in)
        f.close()

    def get_node_tftp_conf_base_url(self, node_ip):
        """
        return a nodes base url for preseed / kickstart
        and other config files
        """
        tmp_url = _(FLAGS.baremetal_pxe_tftp_base_url + "/pxe_cfg_files/" + 
            node_ip + '/')

        return tmp_url
        