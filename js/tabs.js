$(document).ready(function () {
    $("ul[tab-group] > li.nav-item > a").click(function(){
        var selected_tab = $(this).parent('li').parent('ul').attr("tab-group");
        if(selected_tab == "name"){
            var selected_pane = this.text;
        }else{
            var selected_pane = $(this).parent('li').index();
        }
        $("ul[tab-group='" + selected_tab + "']").each(function(e,s) {
            if(selected_tab == "name"){
                $(s).find("a").each((j,k) => {
                    if($(k).text() == selected_pane){
                        $(k).tab("show");
                    }
                });
            }else{
                $(s).find("a:eq(" + selected_pane + ")").tab("show");
            }
        });
    });
});
