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

      $(yahLink).addClass('yah');
      yahLink.onclick = function(e){e.preventDefault();};
    });
  }
  setYAH();
});
