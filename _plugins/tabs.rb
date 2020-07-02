#
# This plugin generates bootstrap by providing a predefined block in Jekyll
###
# You can generate tabs by using {% tabs id:test-tab,type:pills%}
# @input id required, html id
# @input type optional, pill|tabs
# To create individual tab use <id:operator,active:true>
# @input id required, tab HTML id
# @input active optional, adds active class to tab
# @input name optional, tab visual name
# After each tab you must provide tab contents by using <% Content %>
module Jekyll
    class RenderTabs < Liquid::Block

        # regexp pattern to generate key values out of user input
        InputPattern = /(.*?):([A-Za-z0-9\- ]+)(?:,|$| )/m
        IdPattern = /(.*?):([A-Za-z0-9\-]+)(?:,|$| )/m

        def initialize(tag_name, text, tokens)
            super

            @header = createHash(text)
            checkMandatories(@header)
            # by default we will fall back to `tabs` https://getbootstrap.com/docs/4.0/components/navs/#tabs
            if @header.key?("type") == false || @header["type"].match(/tabs|pills/) == false
                @header["type"] = "tabs"
            end
        end

        # function checks mandatory items that are needed to implement tabs
        def checkMandatories(items)
            # exception handeling if user not gave any id
            if items.key?("id") == false || items["id"].match(IdPattern) == false
                raise "id is required and can only contain Numbers,- and Alphabet."
            end
        end

        # convert input parameters to hash
        def createHash(items)
            hash = {} 
            items.scan(InputPattern) do |key, value|
                hash[key] = value
            end
            return hash
        end

        def render(context)
            text = super

            # tab global header
            result = "<ul class=\"nav nav-#{@header["type"]} flex-column general-tab-header\" "
            result += "aria-orientation=\"vertical\" id=\"#{@header['id']}\" role=\"tablist\">"

            # user input should follow this format
            # tabs : <key:value>
            # content: <% content %>
            tmpdata = text.scan(/<(.*?)>(?:.*?)<\%(.*?)\%>/m)            

            # headers and contents are two temporary variables used to generate last result
            headers = ""
            contents = "</ul><div class=\"tab-content\" id=\"#{@header['id']}Content\">"

            for item in tmpdata
                # temporary dictionary to gather header key,values
                dict = createHash(item[0])
                checkMandatories(dict)
                # monkey patch to fix visual bug if user provided multiple active panes.
                if headers.scan(/(active)">/m).length() > 1
                    dict["active"] = false
                    print("\t** WARN: Detected multiple active tabs. **\n")
                end
                # To perevent empty tabs if name was not provided use id as tab name.
                if dict.key?("name") == false
                    dict["name"] = dict["id"]
                end
                headers += "<li class=\"nav-item#{dict["active"]? " active" : ""}\">"
                headers += "<a class=\"nav-link \" id=\"#{dict["id"]}-tab\" data-toggle=\"tab\" "
                headers += "href=\"#tab-#{dict["id"]}\" role=\"tab\" aria-controls=\"tab-#{dict["id"]}\" "
                headers += "aria-selected=\"#{dict["active"]}\">#{dict["name"]}</a></li>"

                contents += "<div class=\"tab-pane#{dict["active"]? " active" : ""}\" "
                contents += "id=\"tab-#{dict["id"]}\" role=\"tabpanel\" "
                contents += "aria-labelledby=\"#{dict["id"]}-tab\" markdown=\"1\">#{item[1]}</div>"

            end
            # final result is ready
            result += headers + contents + "</div>"
            
            return result

        end
    end
end
# register tag into jekyll
Liquid::Template.register_tag('tabs', Jekyll::RenderTabs)
