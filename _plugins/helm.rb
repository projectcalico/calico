require "jekyll"
require "tempfile"
require_relative "./lib"

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
    def initialize(tag_name, extra_args, liquid_options)
      super
      if not extra_args.empty?
        @extra_args = extra_args
      end
    end
    def render(context)
      text = super

      # Because helm hasn't merged stdin support, write the passed-in values.yaml
      # to a tempfile on disk.
      t = Tempfile.new("jhelm")
      t.write(text)
      t.close

      version = context.registers[:page]["version"]
      imageRegistry = context.registers[:page]["registry"]
      imageNames = context.registers[:site].config["imageNames"]
      versions = context.registers[:site].data["versions"]

      # Load the versions.yml file so it can be rewritten in a standard helm format.
      if not versions.key?(version)
        puts "skipping because #{version} not present in _versions.yml"
        t.unlink
        return
      end

      versionsYml = gen_values(versions, imageNames, version, imageRegistry)

      tv = Tempfile.new("temp_versions.yml")
      tv.write(versionsYml)
      tv.close

      # Execute helm.
      # Set the default etcd endpoint placeholder for rendering in the docs.
      cmd = """helm template _includes/#{version}/charts/calico \
        -f #{tv.path} \
        -f #{t.path}
        --set etcd.endpoints=http://<ETCD_IP>:<ETCD_PORT>"""

      if @extra_args
        cmd += " " + @extra_args
      end

      out = `#{cmd}`

      t.unlink
      tv.unlink
      return out
    end
  end
end

Liquid::Template.register_tag('helm', Jekyll::RenderHelmTagBlock)
