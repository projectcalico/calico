class Jekyll::Converters::Markdown::NullConverter
    def initialize(config)
    end

    def convert(content)
        content
    end
end
