$(document).ready(function(){
  // remove anchor hash from page url if present
  var pathname = location.href.split('#')[0];

  // Open any collapses that should be opened when the page loads
  $('#sidebar a').each(function () {
    if (pathname === this.href) {
      $(this).parents('div.collapse').each(function(){
        // Toggling will show animation on pageload. instead, just add CSS class
        $(this).addClass("in");
        $(this).parent().prev().find('span.glyphicon').removeClass('glyphicon-chevron-right').addClass('glyphicon-chevron-down');
      });
      $(this).parent().addClass('current-page');
      this.onclick = function(e){e.preventDefault();};
    }

  });

  // Make arrows switch direction on collapse.
  $('#sidebar').on('show.bs.collapse', function(event) {
    $(event.target).parent().prev().find('span.glyphicon').removeClass('glyphicon-chevron-right').addClass('glyphicon-chevron-down');
  });
  $('#sidebar').on('hide.bs.collapse', function(event) {
    $(event.target).parent().prev().find('span.glyphicon').removeClass('glyphicon-chevron-down').addClass('glyphicon-chevron-right');
  })

  // Enable the sidebar collapse
  $('[data-toggle="offcanvas"]').click(function () {
    $('.row-offcanvas').toggleClass('active')
  });
});
