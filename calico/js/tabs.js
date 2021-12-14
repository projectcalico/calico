$(document).ready(function () {
    $("ul[tab-group] > li.nav-item > a").click(function(){
        var selected_tab = $(this).parent('li').parent('ul').attr("tab-group");
        var selected_pane = this.text;
        $("ul[tab-group='" + selected_tab + "']").each(function(e,s) {
            $(s).find("a").each((j,k) => {
                if($(k).text() == selected_pane){
                    $(k).tab("show");
                }
            });
        });
    });
});
