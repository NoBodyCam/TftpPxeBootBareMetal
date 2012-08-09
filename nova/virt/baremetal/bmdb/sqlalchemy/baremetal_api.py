# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC.
# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Implementation of SQLAlchemy backend."""

from nova import exception
from nova import flags
from nova.openstack.common import log as logging
from nova.openstack.common import timeutils
from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_models
from nova.virt.baremetal.bmdb.sqlalchemy.baremetal_session import get_session
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import joinedload_all
from sqlalchemy.sql.expression import asc
from sqlalchemy.sql.expression import desc
from sqlalchemy.sql.expression import literal_column
from sqlalchemy.sql import func

from nova.db.sqlalchemy.api import is_user_context
from nova.db.sqlalchemy.api import require_admin_context

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


def model_query(context, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id.
    """
    session = kwargs.get('session') or get_session()
    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only')

    query = session.query(*args)

    if read_deleted == 'no':
        query = query.filter_by(deleted=False)
    elif read_deleted == 'yes':
        pass  # omit the filter to include deleted and active
    elif read_deleted == 'only':
        query = query.filter_by(deleted=True)
    else:
        raise Exception(
                _("Unrecognized read_deleted value '%s'") % read_deleted)

    if project_only and is_user_context(context):
        query = query.filter_by(project_id=context.project_id)

    return query


@require_admin_context
def bm_node_get_all(context, service_host=None, session=None):
    query = model_query(context, baremetal_models.BareMetalNode,
                        read_deleted="no", session=session)
    if service_host:
        query = query.filter_by(service_host=service_host)
    return query.all()


@require_admin_context
def bm_node_get(context, bm_node_id, session=None):
    result = model_query(context, baremetal_models.BareMetalNode,
                         read_deleted="no", session=session).\
                     filter_by(id=bm_node_id).\
                     first()
    return result


@require_admin_context
def bm_node_get_by_instance_uuid(context, instance_uuid, session=None):
    result = model_query(context, baremetal_models.BareMetalNode,
                         read_deleted="no", session=session).\
                     filter_by(instance_uuid=instance_uuid).\
                     first()
    return result


@require_admin_context
def bm_node_create(context, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        bm_node_ref = baremetal_models.BareMetalNode()
        bm_node_ref.update(values)
        bm_node_ref.save(session=session)
        return bm_node_ref


@require_admin_context
def bm_node_update(context, bm_node_id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        bm_node_ref = bm_node_get(context, bm_node_id, session=session)
        bm_node_ref.update(values)
        bm_node_ref.save(session=session)


@require_admin_context
def bm_node_destroy(context, bm_node_id, session=None):
    model_query(context, baremetal_models.BareMetalNode, session=session).\
                filter_by(id=bm_node_id).\
                update({'deleted': True,
                        'deleted_at': timeutils.utcnow(),
                        'updated_at': literal_column('updated_at')})


@require_admin_context
def bm_pxe_ip_get_all(context, session=None):
    query = model_query(context, baremetal_models.BareMetalPxeIp,
                        read_deleted="no", session=session)
    return query.all()


@require_admin_context
def bm_pxe_ip_create(context, address, server_address, session=None):
    if not session:
        session = get_session()
    ref = model_query(context, baremetal_models.BareMetalPxeIp,
                      read_deleted="no", session=session).\
                     filter_by(address=address).\
                     first()
    if not ref:
        ref = baremetal_models.BareMetalPxeIp()
        ref.address = address
        ref.server_address = server_address
        ref.save(session=session)
    else:
        if ref.server_address != server_address:
            raise exception.NovaException(
                    'address exists, but server_address is not same')
    return ref.id


@require_admin_context
def bm_pxe_ip_create_direct(context, bm_pxe_ip, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = baremetal_models.BareMetalPxeIp()
        ref.update(bm_pxe_ip)
        ref.save(session=session)
        return ref


@require_admin_context
def bm_pxe_ip_get(context, ip_id, session=None):
    ref = model_query(context, baremetal_models.BareMetalPxeIp,
                      read_deleted="no", session=session).\
                     filter_by(id=ip_id).\
                     first()
    return ref


@require_admin_context
def bm_pxe_ip_get_by_bm_node_id(context, bm_node_id, session=None):
    ref = model_query(context, baremetal_models.BareMetalPxeIp,
                      read_deleted="no", session=session).\
                     filter_by(bm_node_id=bm_node_id).\
                     first()
    return ref


@require_admin_context
def bm_pxe_ip_associate(context, bm_node_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        node_ref = bm_node_get(context, bm_node_id, session=session)
        if not node_ref:
            raise exception.NovaException("bm_node %s not found" % bm_node_id)
        ip_ref = model_query(context, baremetal_models.BareMetalPxeIp,
                             read_deleted="no", session=session).\
                         filter_by(bm_node_id=node_ref.id).\
                         first()
        if ip_ref:
            return ip_ref.id
        ip_ref = model_query(context, baremetal_models.BareMetalPxeIp,
                             read_deleted="no", session=session).\
                         filter_by(bm_node_id=None).\
                         with_lockmode('update').\
                         first()
        if not ip_ref:
            raise exception.NovaException("free bm_pxe_ip not found")
        ip_ref.bm_node_id = bm_node_id
        session.add(ip_ref)
        return ip_ref.id


@require_admin_context
def bm_pxe_ip_disassociate(context, bm_node_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ip = bm_pxe_ip_get_by_bm_node_id(context, bm_node_id, session=session)
        if ip:
            ip.bm_node_id = None
            ip.save(session=session)


@require_admin_context
def bm_interface_get(context, if_id, session=None):
    result = model_query(context, baremetal_models.BareMetalInterface,
                         read_deleted="no", session=session).\
                     filter_by(id=if_id).\
                     first()
    return result


def bm_interface_get_all(context, session=None):
    query = model_query(context, baremetal_models.BareMetalInterface,
                        read_deleted="no", session=session)
    return query.all()


@require_admin_context
def bm_interface_destroy(context, if_id, session=None):
    model_query(context, baremetal_models.BareMetalInterface,
                read_deleted="no", session=session).\
                filter_by(id=if_id).\
                update({'deleted': True,
                        'deleted_at': timeutils.utcnow(),
                        'updated_at': literal_column('updated_at')})


@require_admin_context
def bm_interface_create(context, bm_node_id, address, datapath_id, port_no,
                        session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = baremetal_models.BareMetalInterface()
        ref.bm_node_id = bm_node_id
        ref.address = address
        ref.datapath_id = datapath_id
        ref.port_no = port_no
        ref.save(session=session)
        return ref.id


@require_admin_context
def bm_interface_set_vif_uuid(context, if_id, vif_uuid, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = model_query(context, baremetal_models.BareMetalInterface,
                          read_deleted="no", session=session).\
                         filter_by(id=if_id).\
                         with_lockmode('update').\
                         first()
        if not ref:
            raise exception.NovaException()
        ref.vif_uuid = vif_uuid
        session.add(ref)


@require_admin_context
def bm_interface_get_by_vif_uuid(context, vif_uuid, session=None):
    result = model_query(context, baremetal_models.BareMetalInterface,
                         read_deleted="no", session=session).\
                filter_by(vif_uuid=vif_uuid).\
                first()
    return result


@require_admin_context
def bm_interface_get_all_by_bm_node_id(context, bm_node_id, session=None):
    result = model_query(context, baremetal_models.BareMetalInterface,
                         read_deleted="no", session=session).\
                 filter_by(bm_node_id=bm_node_id).\
                 all()
    return result


@require_admin_context
def bm_deployment_create(context, key, image_path, pxe_config_path, root_mb,
                         swap_mb, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = baremetal_models.BareMetalDeployment()
        ref.key = key
        ref.image_path = image_path
        ref.pxe_config_path = pxe_config_path
        ref.root_mb = root_mb
        ref.swap_mb = swap_mb
        ref.save(session=session)
        return ref.id


@require_admin_context
def bm_deployment_get(context, dep_id, session=None):
    result = model_query(context, baremetal_models.BareMetalDeployment,
                         read_deleted="no", session=session).\
                     filter_by(id=dep_id).\
                     first()
    return result


@require_admin_context
def bm_deployment_destroy(context, dep_id, session=None):
    model_query(context, baremetal_models.BareMetalDeployment,
                session=session).\
                filter_by(id=dep_id).\
                update({'deleted': True,
                        'deleted_at': timeutils.utcnow(),
                        'updated_at': literal_column('updated_at')})
