$(document).ready(function() {
   $('pre.highlight').each(function(i) {
      if (!$(this).parents().hasClass('no-select-button')) {

        // create an id for the current code section
        var currentId = "codeblock" + (i + 1);

        // find the code section and add the id to it
        var codeSection = $(this).find('code');
        codeSection.attr('id', currentId);

        $(function () {
          $('[data-toggle="tooltip"]').tooltip();
        });

        // now create the button, setting the clipboard target to the id
        var btn = document.createElement('a');
        btn.setAttribute('type', 'btn');
        btn.setAttribute('class', 'btn-copy-code');
        btn.setAttribute('data-clipboard-target', '#' + currentId);
        btn.innerHTML = '<i class="glyphicon glyphicon-copy" data-toggle="tooltip" data-placement="bottom" title="Copy"></i>';
        this.insertBefore(btn, this.firstChild);
      }
    });

    var clipboard = new ClipboardJS('.btn-copy-code');

    clipboard.on('success', function(e) {
      e.clearSelection();
    });

  });
