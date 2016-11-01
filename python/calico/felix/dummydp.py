# Copyright (c) 2016 Tigera, Inc. All rights reserved.
import logging
import os

from calico import common
from calico.felix.config import Config
from calico.felix.protocol import *

_log = logging.getLogger(__name__)

def main():
    common.default_logging(gevent_in_use=False)

    # The parent process sends us communication pipes as FD 3 and 4. Open
    # those as files.  Wrap the resulting files in a FileObject to make
    # them cooperate with gevent.
    pipe_from_parent = os.fdopen(3, 'rb', -1)
    pipe_to_parent = os.fdopen(4, 'wb', -1)

    reader = MessageReader(pipe_from_parent)
    writer = MessageWriter(pipe_to_parent)

    config = Config()

    while True:
        for msg_type, msg, seq_no in reader.new_messages():
            _log.info("New %s message (#%s)", msg_type, seq_no)
            if msg_type == MSG_TYPE_CONFIG_UPDATE:
                config.update_from(msg.config)
            elif msg_type == MSG_TYPE_IPSET_DELTA:
                _log.info("IP set delta message: %s", msg)
            elif msg_type == MSG_TYPE_IPSET_REMOVED:
                _log.info("IP set removed message: %s", msg)
            elif msg_type == MSG_TYPE_IPSET_UPDATE:
                _log.info("IP set added message: %s", msg)
            elif msg_type == MSG_TYPE_WL_EP_UPDATE:
                _log.info("Workload endpoint update message: %s", msg)
            elif msg_type == MSG_TYPE_WL_EP_REMOVE:
                _log.info("Workload endpoint remove message: %s", msg)
            elif msg_type == MSG_TYPE_HOST_EP_UPDATE:
                _log.info("Host endpoint update message: %s", msg)
            elif msg_type == MSG_TYPE_HOST_EP_REMOVE:
                _log.info("Host endpoint update remove: %s", msg)
            elif msg_type == MSG_TYPE_HOST_METADATA_UPDATE:
                _log.info("Host endpoint update message: %s", msg)
            elif msg_type == MSG_TYPE_HOST_METADATA_REMOVE:
                _log.info("Host endpoint remove message: %s", msg)
            elif msg_type == MSG_TYPE_IPAM_POOL_UPDATE:
                _log.info("IPAM pool update messages:%s", msg)
            elif msg_type == MSG_TYPE_IPAM_POOL_REMOVE:
                _log.info("IPAM pool remove message: %s", msg)
            elif msg_type == MSG_TYPE_POLICY_UPDATE:
                _log.info("Policy update message: %s", msg)
            elif msg_type == MSG_TYPE_POLICY_REMOVED:
                _log.info("Policy update message: %s", msg)
            elif msg_type == MSG_TYPE_PROFILE_UPDATE:
                _log.info("Profile update message: %s", msg)
            elif msg_type == MSG_TYPE_PROFILE_REMOVED:
                _log.info("Profile update message: %s", msg)
            elif msg_type == MSG_TYPE_IN_SYNC:
                _log.info("In sync message: %s", msg)
            else:
                _log.error("Unexpected message %r %s", msg_type, msg)
