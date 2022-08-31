#
# Authour : Reza R <54559947+frozenprocess@users.noreply.github.com>
# This plugin adds bootstrap predefined tab block in Jekyll
<<-EXAMPLE
tabs can be generated using
{% tabs %}
**Note: tabs are linked to a predefined group named `default`, using `tab-group`
you can define multiple linked tab groups.**
@input tab-group optional, string
@input type optional, pill|tabs

Create individual pane in your tab using
<label:Mytab,active:true>
@input active optional, adds active class to tab
@input label optional, tab visual label

Pane contents should come after each corresponding pane.
<% My pane content %>
<label:anotherpane>
<%Awesome content for second pane!%>
use end block when you are finished with your tab
{% endtabs %}
EXAMPLE
###
# Global scope variable in order to eliminate chance of accidental tab id
if !defined?($idInc)
    $idInc = 1
end

module Jekyll
    class RenderTabs < Liquid::Block
        # regexp pattern to generate key values out of user input
        InputPattern = /(.*?):([A-Za-z0-9\- \.]+)(?:,|$| )/m
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
            # exception handling if user not gave any id
            if items.key?("id") == false || items["id"].match(IdPattern) == false
                items["id"] = "tabplugin-#{$idInc}"
                $idInc += 1
            end
        end

        # convert input parameters to hash
        def createHash(items)
            hash = {}
            items.scan(InputPattern) do |key, value|
                hash[key] = value.strip
            end
            return hash
        end

        def render(context)
            text = super

            # tab global header
            result = "<ul class=\"nav nav-#{@header["type"]} flex-column general-tab-header\" "
            result += "aria-orientation=\"vertical\" id=\"#{@header['id']}\" "
            result += "tab-group=\"#{@header["tab-group"] ? @header["tab-group"] : "default"}\" role=\"tablist\">"
            # user input should follow this format
            # tabs : <key:value>
            # content: <% content %>
            tmpdata = text.scan(/<(.*?)>(?:.*?)<\%(.*?)\%>/m)

            # registering tab_group flag used in `_layouts/docwithnav.html` to decide
            # when to include js/tabs.js in a page.
            context.registers[:page]["tab_group"] = true

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

                headers += "<li class=\"nav-item#{dict["active"]? " active" : ""}\">"
                headers += "<a class=\"nav-link \" id=\"#{dict["id"]}-tab\" data-toggle=\"tab\" "
                headers += "href=\"#tab-#{dict["id"]}\" role=\"tab\" aria-controls=\"tab-#{dict["id"]}\" "
                headers += "aria-selected=\"#{dict["active"]}\">#{dict["label"]}</a></li>"

                contents += "<div class=\"tab-pane#{dict["active"]? " active" : ""}\" "
                contents += "id=\"tab-#{dict["id"]}\" role=\"tabpanel\" "
                # If user decides to create a one line content can cause a bug, \n after
                # item variable resolves this issue.
                contents += "aria-labelledby=\"#{dict["id"]}-tab\" markdown=\"1\" >#{item[1]}\n</div>"

            end
            # final result is ready
            result += headers + contents + "</div>"

            return result

        end
    end
end
# register tag into jekyll
Liquid::Template.register_tag('tabs', Jekyll::RenderTabs)
