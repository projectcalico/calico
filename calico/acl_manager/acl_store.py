# Copyright (c) 2014 Metaswitch Networks
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

import logging
from threading import Thread
from Queue import Queue

log = logging.getLogger(__name__)


class ACLStore(object):

    def __init__(self):
        """
        Create a new ACL Store.
        
        An ACL Store stores a set of ACL rules, and publishes those rules when
        they change or it is queried.
        """
        log.debug("Creating ACL Store object")
        self.queue = Queue()
        self.endpoint_acls = {}

    def start(self, acl_publisher):
        """Start the ACL Store."""
        self.worker_thread = Thread(target = self.worker_thread_loop)
        self.acl_publisher = acl_publisher
        self.worker_thread.start()
        
    def stop(self):
        """Stop the ACL Store.  start() must have been called previously."""
        self.queue.put(("terminate",))
        self.worker_thread.join()
        
    def query_endpoint_rules(self, endpoint_uuid):
        """
        Notify the ACL Store that a query has been received for an endpoint.
        
        The ACL Store will respond asynchronously by publishing an update for
        that endpoint.  This method is thread-safe.
        """
        log.debug("Query received for endpoint UUID %s" % endpoint_uuid)
        self.queue.put(("query_endpoint", endpoint_uuid))
        
    def update_endpoint_rules(self, endpoint_uuid, rules):
        """
        Pass updated rules information to the ACL Store.
        
        The ACL Store will update its stored state for that endpoint, and
        publish an update for it.  This method is thread-safe.
        """
        # At present there is no way to remove a deleted endpoint.
        self.queue.put(("update_endpoint", endpoint_uuid, rules))
        
    def worker_thread_loop(self):
        continue_working = True
        while continue_working:
            work_params = self.queue.get()
            work_type = work_params[0]
            log.debug("ACL Store worker thread received work item type %s" %
                      work_type)
            if work_type == "terminate":
                continue_working = False
            elif work_type == "query_endpoint":
                self.worker_publish_update(work_params[1])
            elif work_type == "update_endpoint":
                self.worker_update_endpoint(work_params[1], work_params[2])
            else:
                log.error("Exception: invalid ACLStore work type %s" %
                          work_type)
                raise Exception("Invalid ACLStore work type",
                                work_type,
                                params)
            
            self.queue.task_done()
            
    def worker_publish_update(self, endpoint_uuid):
        log.debug("ACL Store work: publish ACLs for endpoint %s" %
                  endpoint_uuid)
        if endpoint_uuid in self.endpoint_acls:
            log.info("Publishing ACLs for endpoint %s" % endpoint_uuid)
            self.acl_publisher.publish_endpoint_acls(
                endpoint_uuid,
                self.endpoint_acls[endpoint_uuid]
            )
        else:
            log.warning("ACL Manager queried for unknown endpoint %s" %
                        endpoint_uuid)

    def worker_update_endpoint(self, endpoint_uuid, rules):
        log.debug("ACL Store work: update rules for endpoint %s" %
                  endpoint_uuid)

        self.endpoint_acls[endpoint_uuid] = rules
        
        self.worker_publish_update(endpoint_uuid)