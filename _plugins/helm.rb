require "jekyll"
require "tempfile"
require "yaml"

# This plugin enables jekyll to render helm charts.
# Traditionally, Jekyll will render files which make use of the Liquid templating language.
# This plugin adds a new 'tag' that when specified will pass the input to the Helm binary.
# example use:
#
# {% helm %}
# datastore: kubernetes
# networking: calico
# {% endhelm %}
module Jekyll
  class RenderHelmTagBlock < Liquid::Block
    def render(context)
      text = super

      # Because helm hasn't merged stdin support, write the passed-in values.yaml
      # to a tempfile on disk.
      t = Tempfile.new("jhelm")
      t.write(text)
      t.close

      version = context.registers[:page]["version"]
      imageRegistry = context.registers[:page]["registry"]

      # Load the versions.yml file so it can be rewritten in a standard helm format.
      versionFile = YAML::load_file('_data/versions.yml')
      components = versionFile[version][0]["components"]

      # Write the yaml values to a temp file for reading.
      tv = Tempfile.new("temp_versions.yml")
      tv.write(components.to_yaml)
      tv.close

      # Here we execute helm. In order to preserve backwards compatibility with the existing template system,
      # we pass the entire versions.yml and config.yml. Our chart templates use the passed in "version" to parse
      # out the correct image tags accordingly.
      out = `helm template _includes/#{version}/charts/calico \
        --set page.version=#{version} \
        --set imageRegistry=#{imageRegistry} \
        -f _config.yml \
        -f #{tv.path} \
        -f #{t.path}`
      
      t.unlink
      tv.unlink
      return out
    end
  end
end

Liquid::Template.register_tag('helm', Jekyll::RenderHelmTagBlock)
