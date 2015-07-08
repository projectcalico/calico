# Logging
All components log to directories under `/var/log/calico` inside the calico-node container. By default this is mapped to the `/var/log/calico` directory on the host but can be changed when using `calicoctl` by passing in the `--log-dir` parameter.

By default, each component (below) logs to its own directory. Files are automatically rotated, and by default 10 files of 1MB each are kept. The current log file is called `current` and rotated files have @ followed by a timestamp detailing when the files was rotated in [tai64n](http://cr.yp.to/libtai/tai64.html#tai64n) format.

All logging is done using [svlogd](http://smarden.org/runit/svlogd.8.html). Each component can be configured by dropping a file named `config` into that component's logging directory.
e.g. to configure bird to only log 4 files of 10KB each
```
#/var/log/calico/bird/config
s10000
n4
```

svlogd can also be configured to forward logs to syslog, to prefix each line and to filter logs. See the [documentation](http://smarden.org/runit/svlogd.8.html) for further details.

## Bird/Bird6
Bird and Bird6 are used for distributing IPv4 and IPv6 routes between Calico enabled hosts.

Directory | Default level
--- | ---
`bird` and `bird6` | `debug`

To change the level, edit the config file at `node_filesystem/templates/bird.cfg.template` by following the [documentation](http://bird.network.cz/?get_doc&f=bird-3.html). This will require a rebuild of the calico-node image.

## Felix
Felix is the primary Calico agent that runs on each machine that hosts endpoints.

Directory | Default level
--- | ---
`felix` | `DEBUG`

Log can be changed by writing to etcd using the following key `/calico/v1/config/LogSeverityScreen`
Valid values are detailed in the [documentation](http://docs.projectcalico.org/en/latest/configuration.html)


## confd
confd generates configuration files for Felix and Bird.

Directory | Default level
--- | ---
`confd` | `DEBUG`

To change the log level, edit the node_filesystem/etc/service/confd/run and rebuild the calico-node image.

For more information on the allowed levels, see the [documentation](https://github.com/kelseyhightower/confd/blob/master/docs/configuration-guide.md)


## Docker Driver
The Docker driver receives requests from the Docker daemon for configuring networks.

It's implemented using [flask](http://flask.pocoo.org/) and [gunicorn](http://gunicorn.org/). Gunicorn error and access logs are combined with the Flask application logs in a single file.

Directory | Default level
--- | ---
`dockerdriver` | `INFO`

To change the gunicorn log level, edit the node_filesystem/etc/service/calico-driver/run and rebuild the calico-node image. See the gunicorn [documentation](http://gunicorn-docs.readthedocs.org/en/latest/settings.html#loglevel) for more details.
To configure the logging for the driver itself, edit the Python code in calico_containers/docker_plugin.py. For more information see the flask [documentation](http://flask.pocoo.org/docs/0.10/errorhandling/) Again, this requires a rebuild of the calico-node image.
