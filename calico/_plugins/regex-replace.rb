require 'liquid'

module Jekyll
  module RegexReplace
    def regex_replace(str, regex, value_replace)
      return str.gsub(Regexp.new(regex), value_replace, )
    end
  end
end

Liquid::Template.register_filter(Jekyll::RegexReplace)