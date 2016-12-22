The following is a summary of the templates defined in this directory:

### bird.toml.template / bird6.toml.tempate

Referenced by bird.toml.toml and bird6.toml.toml.

These templates write out a TOML file (bird.toml and bird6.toml) that is used 
to tell confd which set of the main BIRD templates to use.

Based off the node_mesh parameter, the TOML file generated either points to the
full-mesh config files, or the no-mesh config files.

Once confd writes out the appropriate TOML file, confd is restarted to pick up
the change to the bird.toml and bird6.toml files.  Since there are two sets
of changes, a change to the node_mesh parameter will result in a double
restart of confd.

In short, this is used by confd to generate its own configuration.


### bird_ipam.cfg.template / bird6_ipam.cfg.template

Referenced by bird_ipam.toml and bird6_ipam.toml.

These templates write out the route filters based on IPAM configuration.  This
is inherited by the main BIRD configuration file.

It is separated out from the main BIRD configuration file because it watches a
different sub-tree in etcd.  This allows confd to watch a smaller portion of 
the tree to reduce churn.


### bird.cfg.mesh.template / bird6.cfg.mesh.template

Referenced by the confd-generated bird.toml and bird6.toml files.

These templates write out the main BIRD configuration when the full 
node-to-node mesh is enabled.


### bird.cfg.no-mesh.template / bird6.cfg.no-mesh.template

Referenced by the confd-generated bird.toml and bird6.toml files.

These templates write out the main BIRD configuration when the full 
node-to-node mesh is disabled.
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calicoctl/calico_node/filesystem/templates/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
