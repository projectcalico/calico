$(document).ready(function() {
  var codeToolbarClass = 'code-toolbar';
  var copyButtonClass = `${codeToolbarClass}__copy-button`;
  var downloadButtonClass = `${codeToolbarClass}__download-button`;

  $('pre.highlight').each(function(i) {
    if (!$(this).parents().hasClass('no-select-button')) {
      var codeSectionContainer = $(this).closest('div.highlighter-rouge')[0];
      var currentCodeSectionId = "codeblock-" + (i + 1);
      var codeSection = $(this).find('code');
      var code = codeSection[0].innerText;
      codeSection.attr('id', currentCodeSectionId);

      $(function () {
        $('[data-toggle="tooltip"]').tooltip();
      });

      var copyButton = document.createElement('a');
      copyButton.setAttribute('type', 'btn');
      copyButton.setAttribute('class', copyButtonClass);
      copyButton.setAttribute('data-clipboard-target', '#' + currentCodeSectionId);
      copyButton.innerHTML = '<i class="glyphicon glyphicon-copy" data-toggle="tooltip" data-placement="bottom" title="Copy"></i>';

      var downloadButton = document.createElement('a');
      downloadButton.setAttribute('type', 'btn');
      downloadButton.setAttribute('class', downloadButtonClass);
      downloadButton.innerHTML = '<i class="glyphicon glyphicon-download-alt" data-toggle="tooltip" data-placement="bottom" title="Download"></i>';
      downloadButton.onclick = function() {
        var language = "";

        for (var c of codeSectionContainer.classList) {
          if (!c) {
            continue;
          }

          if (c.startsWith("language-")) {
            language = c.substr(9);
            break;
          }
        }

        if (language === "shell") {
          language = "sh";
        } else if (language === "") {
          language = "txt";
        }

        var downloadas = `${document.title}.${language}`;
        saveFile(downloadas, code);
      }

      var toolbarDiv = document.createElement('div');
      toolbarDiv.setAttribute('class', codeToolbarClass);
      toolbarDiv.appendChild(downloadButton);
      toolbarDiv.appendChild(copyButton);
      this.insertBefore(toolbarDiv, this.firstChild);
    }
  });

  var clipboard = new ClipboardJS(`.${copyButtonClass}`);
  clipboard.on('success', function(e) {
    e.clearSelection();
  });
});

function saveFile(filename, text) {
  var element = document.createElement("a");
  element.setAttribute("href", "data:text/plain;charset=utf-8," + encodeURIComponent(text));
  element.setAttribute("download", filename);
  element.style.display = "none";
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}
