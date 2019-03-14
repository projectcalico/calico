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
      prodname = context.registers[:site].config["prodname"]
      nodecontainer = context.registers[:site].config["nodecontainer"]

      # Load the versions.yml file so it can be rewritten in a standard helm format.
      if not versions.key?(version)
        puts "skipping because #{version} not present in _versions.yml"
        t.unlink
        return
      end

      components = versions[version][0]["components"]

      # In order to preserve backwards compatibility with the existing template system,
      # we process config.yml for imageNames and _versions.yml for tags,
      # then write them in a more standard helm format.
      versionsYml = <<~EOF
        node:
          image: #{imageNames["node"]}
          tag: #{components["calico/node"]["version"]}
        calicoctl:
          image: #{imageNames["calicoctl"]}
          tag: #{components["calicoctl"]["version"]}
        typha:
          image: #{imageNames["typha"]}
          tag: #{components["typha"]["version"]}
        cni:
          image: #{imageNames["cni"]}
          tag: #{components["calico/cni"]["version"]}
        kubeControllers:
          image: #{imageNames["kubeControllers"]}
          tag: #{components["calico/kube-controllers"]["version"]}
        flannel:
          image: #{imageNames["flannel"]}
          tag: #{components["flannel"]["version"]}
        dikastes:
          image: #{imageNames["dikastes"]}
          tag: #{components["calico/dikastes"]["version"]}
        flexvol:
          image: #{imageNames["flexvol"]}
          tag: #{components["flexvol"]["version"]}
        EOF

      tv = Tempfile.new("temp_versions.yml")
      tv.write(versionsYml)
      tv.close

      # execute helm.
      cmd = """helm template _includes/#{version}/charts/calico \
        --set imageRegistry=#{imageRegistry} \
        --set prodname=#{prodname} \
        --set nodecontainer=#{nodecontainer} \
        -f #{tv.path} \
        -f #{t.path}"""

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
