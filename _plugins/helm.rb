require "jekyll"
require "tempfile"

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
      out = `helm template _includes/#{version}/charts/calico -f #{t.path}`
      
      t.unlink
      return out
    end
  end
end

Liquid::Template.register_tag('helm', Jekyll::RenderHelmTagBlock)
