# Takes versions_yml which is structured as follows:
#
# {"v3.6"=>
#     ["components"=>
#        {"calico/node"=>{"version"=>"v3.6.0"},
#         "typha"=>{"version"=>"v3.6.0"}}]
#
# And for a given version, return a Hash of each components' version by component name e.g:
#
# {"calico/node"=>"v3.6.0",
#   "typha"=>"v3.6.0"}
#
def parse_versions(versions_yml, version)
  if not versions_yml.key?(version)
    raise IndexError.new "requested version '#{version}' not present in versions.yml"
  end

  components = versions_yml[version][0]["components"].clone
  return components.each { |key,val| components[key] = val["version"] }
end


def gen_values(version, vs, imageNames, imageRegistry)
  # Use the gen_values function for this version
  begin
    require_relative "#{version}/values"
  rescue LoadError
    raise "tried to load base values for #{version} but _plugins/#{version}/values.rb does not exist"
  end
  gen_func_name = "gen_values_#{version.tr(".", "_")}"
  return send(gen_func_name, vs, imageNames, imageRegistry)
end
