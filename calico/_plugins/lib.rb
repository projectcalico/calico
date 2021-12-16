Component = Struct.new(:image, :version, :registry) do
end

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
  versionsYml = components.each { |key,val| components[key] = val["version"] }

  unless versions_yml[0]["tigera-operator"].nil?
          operator = versions_yml[0]["tigera-operator"]
          versionsYml["tigera-operator"] = Component.new(operator["image"], operator["version"], operator["registry"])
  end

  return versionsYml
end
