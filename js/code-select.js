$(document).ready(function() {
  var codeSnippetClass = 'code-snippet';
  var codeToolbarClass = `code-snippet-toolbar`;
  var copyButtonClass = `${codeToolbarClass}__copy-button`;
  var downloadButtonClass = `${codeToolbarClass}__download-button`;
  var codeToolbarVisibleClass = `${codeToolbarClass}--visible`;

  $('pre.highlight').each(function(i) {
    if (!$(this).parents().hasClass('no-select-button')) {
      $(this).addClass(codeSnippetClass);
      var codeSectionContainer = $(this).closest('div.highlighter-rouge')[0];
      var currentCodeSectionId = "codeblock-" + (i + 1);
      var codeSection = $(this).find('code');
      codeSection.attr('id', currentCodeSectionId);
      var codeSectionContent = codeSection[0];
      var code = codeSectionContent.innerText;
      var codeHtml = codeSectionContent.innerHTML;

      var language;
      for (var c of codeSectionContainer.classList) {
        if (!c) {
          continue;
        }

        if (c.startsWith("language-")) {
          language = c.substr(9);
          break;
        }
      }

      if (language === "bash") {
        var isEofStarted = false;
        var isMultilineCommandStarted = false;
        var codeLines = code.split('\n');
        var codeLinesHtml = codeHtml.split('\n');

        for (var i = 0; i < codeLines.length; i++) {
          var trimmedCodeLine = codeLines[i].trim();

          var isPartOfEof = isEofStarted && trimmedCodeLine !== "EOF";
          var isEndOfEof = isEofStarted && trimmedCodeLine === "EOF";
          if (!isPartOfEof) {
            isEofStarted = !isEofStarted && trimmedCodeLine.includes("<<EOF");
          }

          var codeLineEndsWithMultilineSeparator = trimmedCodeLine.endsWith(" \\");
          var isPartOfMultilineCommand = isMultilineCommandStarted && codeLineEndsWithMultilineSeparator;
          var isEndOfMultilineCommand = isMultilineCommandStarted && !codeLineEndsWithMultilineSeparator;
          if (!isPartOfMultilineCommand) {
            isMultilineCommandStarted = !isMultilineCommandStarted && codeLineEndsWithMultilineSeparator;
          }

          var codeLineIsCommand = !isPartOfMultilineCommand && !isEndOfMultilineCommand && !isPartOfEof && !isEndOfEof;
          if (!!trimmedCodeLine && codeLineIsCommand) {
            codeLinesHtml[i] = `<span class='code-snippet__command-prefix'>$ </span>${codeLinesHtml[i]}`;
          }
        }

        codeSectionContent.innerHTML = codeLinesHtml.join('\n');
      }

      $(function () {
        $('[data-toggle="tooltip"]').tooltip();
      });

      var copyButton = document.createElement('a');
      copyButton.setAttribute('type', 'btn');
      copyButton.setAttribute('class', copyButtonClass);
      copyButton.setAttribute('data-clipboard-target', '#' + currentCodeSectionId);
      copyButton.innerHTML = '<i class="glyphicon glyphicon-duplicate" data-toggle="tooltip" data-placement="bottom" title="Copy"></i>';

      var downloadButton = document.createElement('a');
      downloadButton.setAttribute('type', 'btn');
      downloadButton.setAttribute('class', downloadButtonClass);
      downloadButton.innerHTML = '<i class="glyphicon glyphicon-download-alt" data-toggle="tooltip" data-placement="bottom" title="Download"></i>';
      downloadButton.onclick = function() {
        var fileExtension = language || "txt";
        var fileName = `${document.title}.${fileExtension}`;

        saveFile(fileName, code);
      }

      var toolbarDiv = document.createElement('div');
      toolbarDiv.setAttribute('class', `${codeSnippetClass}__toolbar ${codeToolbarClass}`);
      toolbarDiv.appendChild(downloadButton);
      toolbarDiv.appendChild(copyButton);
      this.insertBefore(toolbarDiv, this.firstChild);
      this.onmouseover = function() {
        toolbarDiv.classList.add(codeToolbarVisibleClass);
      }
      this.onmouseout = function() {
        toolbarDiv.classList.remove(codeToolbarVisibleClass);
      }
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
