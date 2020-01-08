require "optparse"
require "yaml"
require_relative "../_plugins/lib"
require_relative "../_plugins/values"

usage = "ruby hack/gen_values_yaml.rb <version> [arguments...]

It's recommended to run this from the root of the Calico repository,
as the default paths assume as much.

<version> should be the major.minor version (e.g. v3.6) or master.

--config    Path to the jekyll config. [default: _config.yml]
--versions  Path to the versions.yml. [default: _data/versions.yml]
--registry  The registry prefix. [default: quay.io]
"

OptionParser.new do |parser|
    parser.on("-c", "--config=CONFIG") do |config|
        @path_to_config = config
    end

    parser.on("-v", "--versions=VERSIONS") do |versions|
        @path_to_versions = versions
    end

    parser.on("-r", "--registry=REGISTRY") do |registry|
        @image_registry = registry
    end
end.parse!

@version = ARGV.pop
if !@version
    print usage
    exit
end

@path_to_config ||= "_config.yml"
@path_to_versions ||= "_data/versions.yml"
@image_registry ||= "quay.io/"

# In order to preserve backwards compatibility with the existing template system,
# we process config.yml for imageNames and _versions.yml for tags,
# then write them in a more standard helm format.
config = YAML::load_file(@path_to_config)
imageNames = config["imageNames"]

versions_yml = YAML::load_file(@path_to_versions)
versions = parse_versions(versions_yml, @version)

print gen_values(versions, imageNames, @image_registry)
