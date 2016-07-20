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

from oslo_config import cfg


SHARED_ETCD_OPTS = [
    # etcd connection information.
    cfg.StrOpt('etcd_host', default='127.0.0.1',
               help="The hostname or IP of the etcd node/proxy"),
    cfg.IntOpt('etcd_port', default=4001,
               help="The port to use for the etcd node/proxy"),
    cfg.StrOpt('etcd_scheme', default='http',
               help='The protocol scheme to be used for connections to etcd'),
    # etcd TLS-related options.
    cfg.StrOpt('etcd_key_file', default=None,
               help="The path to the TLS key file to use with etcd."),
    cfg.StrOpt('etcd_cert_file', default=None,
               help="The path to the TLS client certificate file to use with "
                    "etcd."),
    cfg.StrOpt('etcd_ca_cert_file', default=None,
               help="The path to the TLS CA certificate file to use with "
                    "etcd."),
]


def register_options(conf, additional_options=None):
    options_to_register = (
        SHARED_ETCD_OPTS if additional_options is None
        else SHARED_ETCD_OPTS + additional_options)
    conf.register_opts(options_to_register, 'calico')
