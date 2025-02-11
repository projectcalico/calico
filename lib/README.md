This folder contains importable, self-contained, library modules. These are usable within this project and exportable
to others.

There is an emphasis on restricting the dependencies for these modules, and adding more dependencies should be done
with careful consideration. This statement isn't to completely dissuade any developer from adding dependencies as needed
to a module, but instead to ensure that proper thought is given to whether or not the functionality being added to a module
belongs in that module when new dependencies are required.

As an example, there is a `httpmachinery` module to provide tooling for creating http servers / apis. If k8s or grpc
dependencies were imported for a feature that would be sign that maybe the feature doesn't belong in this module. Either
k8s or grpc modules should be created, or a more generic rethought of the feature being added to the `httpmachinery`
module needs to be done.