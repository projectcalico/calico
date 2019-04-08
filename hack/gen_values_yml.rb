require "optparse"
require "yaml"
require_relative "../_plugins/lib"

usage = "ruby hack/gen_values_yaml.rb <version> [arguments...]

It's recommended to run this from the root of the Calico repository,
as the default paths assume as much.

<version> should be the major.minor version (e.g. v3.6) or master.

--config    Path to the jekyll config. [default: _config.yml]
--versions  Path to the versions.yml. [default: _data/versions.yml]
--registry  The registry prefix. [default: quay.io]
"

# Extend the Hash class with deep_merge since the builtin 'merge' function does not merge duplicate keys in a Hash.
# Source: https://stackoverflow.com/a/30225093
class ::Hash
    def deep_merge(second)
        merger = proc { |key, v1, v2| Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : Array === v1 && Array === v2 ? v1 | v2 : [:undefined, nil, :nil].include?(v2) ? v1 : v2 }
        self.merge(second.to_h, &merger)
    end
end

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
@path_to_base_values = "_includes/#{@version}/charts/calico/base_values.yaml"

# In order to preserve backwards compatibility with the existing template system,
# we process config.yml for imageNames and _versions.yml for tags,
# then write them in a more standard helm format.
config = YAML::load_file(@path_to_config)
imageNames = config["imageNames"]

versions_yml = YAML::load_file(@path_to_versions)
versions = parse_versions(versions_yml, @version)
values = YAML::load(gen_values(versions, imageNames, @image_registry))

base_values = YAML::load_file(@path_to_base_values)

print base_values.deep_merge(values).to_yaml
