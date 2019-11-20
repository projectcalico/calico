require_relative 'drops/breadcrumb_item.rb'

Jekyll::Hooks.register [:pages, :documents], :pre_render do |side, payload|  # documents are collections, and collections include also posts
  drop = Drops::BreadcrumbItem

  if side.url == "/"
    then payload["breadcrumbs"] = [
      drop.new(side, payload)
    ]
  else
    payload["breadcrumbs"] = []
    path = side.url.split("/")

    0.upto(path.size - 1) do |int|
      joined_path = path[0..int].join("/")
      sides = [].concat(side.site.pages).concat(side.site.documents)
      item = sides.find { |side_| joined_path == "" && side_.url == "/" || side_.url.chomp("/") == joined_path }
      payload["breadcrumbs"] << drop.new(item, payload) if item
    end
  end
end
