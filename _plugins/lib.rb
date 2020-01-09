# Takes versions_yml which is structured as follows:
#
#   ["components"=>
#      {"calico/node"=>{"version"=>"v3.6.0"},
#       "typha"=>{"version"=>"v3.6.0"}}]
#
# And for a given version, return a Hash of each components' version by component name e.g:
#
# {"calico/node"=>"v3.6.0",
#   "typha"=>"v3.6.0"}
def parse_versions(versions_yml)
  components = versions_yml[0]["components"].clone
  return components.each { |key,val| components[key] = val["version"] }
end
