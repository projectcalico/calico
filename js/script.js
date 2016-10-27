$(document).ready(function(){
  function setYAH() {
    var pathname = location.href.split('#')[0]; // on page load, make sure the page is YAH even if there's a hash
    var currentLinks = [];

    $('#sidebar a').each(function () {
      if (pathname === this.href) currentLinks.push(this);
    });

    currentLinks.forEach(function (yahLink) {
      $(yahLink).parents('div.collapse').each(function(){
        $(this).collapse('show');
      });

      $(yahLink).addClass('current-page');
      yahLink.onclick = function(e){e.preventDefault();};
    });
  }
  setYAH();
  $('#sidebar').on('show.bs.collapse', function(event) {
    $(event.target).prev().prev().removeClass('glyphicon-chevron-right').addClass('glyphicon-chevron-down');
  });
  $('#sidebar').on('hide.bs.collapse', function(event) {
    $(event.target).prev().prev().removeClass('glyphicon-chevron-down').addClass('glyphicon-chevron-right');
  })
});
