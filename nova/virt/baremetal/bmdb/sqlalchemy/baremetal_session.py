# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC.
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

"""Session Handling for SQLAlchemy backend."""

import time

import sqlalchemy
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool, StaticPool

import nova.exception
import nova.flags as flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging

from nova.db.sqlalchemy.session import get_maker
from nova.db.sqlalchemy.session import is_db_connection_error
from nova.db.sqlalchemy.session import ping_listener
from nova.db.sqlalchemy.session import synchronous_switch_listener

opts = [
    cfg.StrOpt('baremetal_sql_connection',
               default='sqlite:///$state_path/baremetal_$sqlite_db',
               help='The SQLAlchemy connection string used to connect to the '
                    'bare-metal database'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(opts)

LOG = logging.getLogger(__name__)

_ENGINE = None
_MAKER = None


def get_session(autocommit=True, expire_on_commit=False):
    """Return a SQLAlchemy session."""
    global _MAKER
    if _MAKER is None:
        engine = get_engine()
        _MAKER = get_maker(engine, autocommit, expire_on_commit)

    session = _MAKER()
    session.query = nova.exception.wrap_db_error(session.query)
    session.flush = nova.exception.wrap_db_error(session.flush)
    return session


def get_engine():
    """Return a SQLAlchemy engine."""
    global _ENGINE
    if _ENGINE is None:
        connection_dict = sqlalchemy.engine.url.make_url(
                FLAGS.baremetal_sql_connection)

        engine_args = {
            "pool_recycle": FLAGS.sql_idle_timeout,
            "echo": False,
            'convert_unicode': True,
        }

        # Map our SQL debug level to SQLAlchemy's options
        if FLAGS.sql_connection_debug >= 100:
            engine_args['echo'] = 'debug'
        elif FLAGS.sql_connection_debug >= 50:
            engine_args['echo'] = True

        if "sqlite" in connection_dict.drivername:
            engine_args["poolclass"] = NullPool

            if FLAGS.sql_connection == "sqlite://":
                engine_args["poolclass"] = StaticPool
                engine_args["connect_args"] = {'check_same_thread': False}

        _ENGINE = sqlalchemy.create_engine(FLAGS.baremetal_sql_connection,
                                           **engine_args)

        if 'mysql' in connection_dict.drivername:
            sqlalchemy.event.listen(_ENGINE, 'checkout', ping_listener)
        elif "sqlite" in connection_dict.drivername:
            if not FLAGS.sqlite_synchronous:
                sqlalchemy.event.listen(_ENGINE, 'connect',
                                        synchronous_switch_listener)

        try:
            _ENGINE.connect()
        except OperationalError, e:
            if not is_db_connection_error(e.args[0]):
                raise

            remaining = FLAGS.sql_max_retries
            if remaining == -1:
                remaining = 'infinite'
            while True:
                msg = _('SQL connection failed. %s attempts left.')
                LOG.warn(msg % remaining)
                if remaining != 'infinite':
                    remaining -= 1
                time.sleep(FLAGS.sql_retry_interval)
                try:
                    _ENGINE.connect()
                    break
                except OperationalError, e:
                    if (remaining != 'infinite' and remaining == 0) or \
                       not is_db_connection_error(e.args[0]):
                        raise
    return _ENGINE
