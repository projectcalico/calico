require "jekyll"
require "tempfile"
require "open3"

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

      @chart = "calico"
      if extra_args.start_with?("tigera-operator")
        @chart = "tigera-operator"
        extra_args.slice! "tigera-operator"
      end

      # helm doesn't natively have an --execute-dir flag but it sure would be useful if it did.
      # here we replace instances of "--execute-dir $dir" with individual calls to "--execute $file" by
      # iterating over files in that directory.
      extra_args.gsub!(/--execute-dir (\S*)/) do |_|
        e = []
        all_files = Dir.entries "_includes/charts/#{@chart}/#{$1}"
        all_files.sort.each do |file|
            fpath = File.join($1, file)
            next if File.directory?("_includes/charts/#{@chart}/#{fpath}")

            # for helm v3, when templating crd files, you must specify them relative
            # to the crd directory. so trim the 'crds' from the name.
            # we don't need to worry about the helm v2 case because crds are stored in templates/
            # and can't be --executed from the crds/ directory.
            if fpath.start_with? "crds" then
              fpath = Pathname.new(fpath).relative_path_from(Pathname.new("crds"))
            end

            e << "--execute #{fpath}"
        end
        e.join(" ")
      end

      # substitute --execute with --show-only for helm v3 compatibility.
      if @chart == "tigera-operator" then
        extra_args.gsub!(/--execute (\S*)/) do |f|
          # operator CRDs have moved to root
          if $1.start_with? "templates/crds/" then f.sub('--execute templates/crds/', '--show-only ')
          # all other requests need to use --show-only instead of --execute for helm v3
          else f.sub('--execute', '--show-only')
          end
        end
      end

      @extra_args = extra_args
    end
    def render(context)
      text = super

      # Because helm hasn't merged stdin support, write the passed-in values.yaml
      # to a tempfile on disk.
      t = Tempfile.new("jhelm")
      t.write(text)
      t.close

      imageRegistry = context.registers[:page]["registry"]
      imageNames = context.registers[:site].config["imageNames"]
      versions = context.registers[:site].data["versions"]

      vs = parse_versions(versions)

      versionsYml = gen_values(vs, imageNames, imageRegistry, @chart)

      tv = Tempfile.new("temp_versions.yml")
      tv.write(versionsYml)
      tv.close

      # Execute helm.
      # Set the default etcd endpoint placeholder for rendering in the docs.
      if @chart == "tigera-operator" then
        cmd = """bin/helm3 --namespace tigera-operator template --include-crds _includes/charts/#{@chart} \
          -f #{tv.path} \
          -f #{t.path}"""
      else
        cmd = """bin/helm template _includes/charts/#{@chart} \
        -f #{tv.path} \
        -f #{t.path} \
        --set etcd.endpoints='http://<ETCD_IP>:<ETCD_PORT>'"""
      end

      cmd += " " + @extra_args.to_s

      out, stderr, status = Open3.capture3(cmd)
      if status != 0
        raise "failed to execute helm for '#{context.registers[:page]["path"]}': #{stderr}"
      end

      t.unlink
      tv.unlink
      return out
    end
  end
end

Liquid::Template.register_tag('helm', Jekyll::RenderHelmTagBlock)
