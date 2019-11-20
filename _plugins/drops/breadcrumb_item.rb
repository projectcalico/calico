module Drops
  class BreadcrumbItem < Liquid::Drop
    extend Forwardable

    def_delegator :@page, :data
    def_delegator :@page, :url

    def initialize(page, payload)
      @payload = payload
      @page = page
    end

    def title
      @page.data["breadcrumb"] != nil ? @page.data["breadcrumb"] : @page.data["title"]
    end

    def namespace
      @page.data["namespace"]
    end

  end
end
