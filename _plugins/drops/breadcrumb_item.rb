module Jekyll::Drops
  class BreadcrumbItem < Liquid::Drop
    extend Forwardable

    def_delegator :@page, :data
    def_delegator :@page, :url

    def initialize(title, url)
      @title = title
      @url = url
    end

    def title
      @title
    end

    def url
      @url
    end

    def namespace
      @page.data["namespace"]
    end

  end
end
