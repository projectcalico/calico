# NullConverter implements the Jekyll Markdown Converter but doesn't actually make any modifications
# to the markdown when it converts it. This is useful in development if you want to see what the rendered markdown looks like
# after "include" statements are processed but before it's converted into a full html page. Specifically, this makes it trivial
# to diff rendered markdown changes made to include statements. 
# To activate, set "markdown: NullConverter" in config.yml.
module Jekyll
    class Converters::Markdown::NullConverter
        def initialize(config)
        end

        def convert(content)
            content
        end
    end

    # This after_init register sets layout=null for all pages if the NullConverter is in use.
    Hooks.register :site, :after_init do |site|
        if site.config["markdown"] == "NullConverter"
            site.config["defaults"].each do |defaults|
                defaults["values"]["layout"] = nil
            end
        end
    end
end
