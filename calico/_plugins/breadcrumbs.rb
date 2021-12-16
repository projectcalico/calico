require_relative 'drops/breadcrumb_item.rb'


module Jekyll
  module Breadcrumbs
    def self.load(navbars)
      @navbars = navbars
    end

    def self.build(side, payload)
      payload["breadcrumbs"] = self.get_drops(side.url, @navbars)
    end

    # get_drops recursively searches navbars to find an item whose path matches the url
    def self.get_drops(url, navbars)
      navbars.each do |val|
        if val["path"] == url
          return [Jekyll::Drops::BreadcrumbItem.new(val["title"], val["path"])]
        end

        if val["section"]
          drops = self.get_drops(url, val["section"])
          if drops
            return drops.prepend(Jekyll::Drops::BreadcrumbItem.new(val["title"], val["path"]))
          end
        end
      end

      return nil
    end
  end
end

# register for post_read hook so that we can store off the navbar data
# which otherwise isn't available in the main hook
Jekyll::Hooks.register [:site], :post_read do |site, payload|
  Jekyll::Breadcrumbs::load(site.data["navbars"].values)
end


Jekyll::Hooks.register [:pages, :documents], :pre_render do |side, payload|
  Jekyll::Breadcrumbs::build(side, payload)
end
