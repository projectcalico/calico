$(document).ready(function(){
  var pathname = location.href.split('#')[0]; // remove anchor hash from page url if present

  $('#sidebar a').each(function () {
    if (pathname === this.href) {
      $(this).parents('div.collapse').each(function(){
        // Toggling will show animation on pageload. instead, just add CSS class
        $(this).addClass("in");
        $(this).prev().prev().removeClass('glyphicon-chevron-right').addClass('glyphicon-chevron-down');
      });
      $(this).parent().addClass('current-page');
      this.onclick = function(e){e.preventDefault();};
    }

  });

  $('#sidebar').on('show.bs.collapse', function(event) {
    $(event.target).prev().prev().removeClass('glyphicon-chevron-right').addClass('glyphicon-chevron-down');
  });
  $('#sidebar').on('hide.bs.collapse', function(event) {
    $(event.target).prev().prev().removeClass('glyphicon-chevron-down').addClass('glyphicon-chevron-right');
  })
});
