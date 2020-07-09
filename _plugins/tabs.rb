#
# Authour : Reza R <54559947+frozenprocess@users.noreply.github.com>
# This plugin adds bootstrap predefined tab block in Jekyll
<<-EXAMPLE
You can generate tabs by using {% tabs type:pills %}
@input id optional, html id
You can link pane by their index position if you provide an integer for `tab-group` or 
link panes using identical pane names
@input tab-group optional, int|"name"
@input type optional, pill|tabs
To create individual tab use <name:Mytab,active:true>
@input id optional, tab HTML id
@input active optional, adds active class to tab
@input name optional, tab visual name
```
   Normal tab                  |    Linked "Numerical index"            |   Linked tab "Identical names"                    
------------------------------ |:--------------------------------------:|-----------------------------------------:
   {% tabs %}                  |    {% tabs tab-group:1 %}              |   {% tabs tab-group:name %}                             
   <name:Mytab,active:true>    |    <name:Non unique name,active:true>  |   <name:unique tab y,active:true>  
   <% Content %>               |    <% Content for tab1 %>              |   <% Content for tab y %>                          
   <name:Mytab>                |    <name:Non unique name>              |   <name:unique tab x>             
   <% Content %>               |    <% Content for tab2 %>              |   <% Content for tab x %>                          
   <>                          |    <>                                  |   {% endtabs %}                          
   <% Tab with random name  %> |    <% Tab with random name  %>         |   {% tabs tab-group:name %}                             
   {% endtabs %}               |    {% endtabs %}                       |   <name:unique tab x>
                               |    {% tabs tab-group:1 %}              |   <% Content for tab x %>                          
                               |    <name:Non unique name,active:true>  |   <name:unique tab y> 
                               |    <% Content for tab1 %>              |   <% Content for tab y %>                                        
                               |    <name:Non unique name>              |   {% endtabs %}                                        
                               |    <% Content for tab2 %>              |                                          
                               |    <>                                  |                                          
                               |    <% Tab with random name  %>         |                                          
                               |    {% endtabs %}                       |          
```                               
EXAMPLE
###
# Gloabl scope variable in order to eliminate chance of accidental tab id
if !defined?($idInc)
    $idInc = 1
end

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
            result += "aria-orientation=\"vertical\" id=\"#{@header['id']}\""
            result += "#{@header["tab-group"] ? " tab-group=\"#{@header["tab-group"]}\" " : ""} role=\"tablist\">"
            # user input should follow this format
            # tabs : <key:value>
            # content: <% content %>
            tmpdata = text.scan(/<(.*?)>(?:.*?)<\%(.*?)\%>/m)            

            if @header["tab-group"]
                # registering tab_group flag used in `_layouts/docwithnav.html` to decied
                # when to include js/tabs.js in a page.
                context.registers[:page]["tab_group"] = true
            end

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
                # there is a bug if user decides to create a one line content \n at the end of variable
                # address this bug
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
