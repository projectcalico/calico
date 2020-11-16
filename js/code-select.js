$(document).ready(function() {
  var codeSnippetClass = 'code-snippet';
  var codeToolbarClass = `code-snippet-toolbar`;
  var toolBarButtonClass = `${codeToolbarClass}__button`;
  var copyButtonClass = `${codeToolbarClass}__copy-button`;
  var downloadButtonClass = `${codeToolbarClass}__download-button ${codeToolbarClass}__button`;
  var codeToolbarVisibleClass = `${codeToolbarClass}--visible`;

  var bashPrompt = "$";
  var bashNewlineEscape = " \\";
  var powershellPrompt = "PS C:\>";
  var powershellNewlineEscape = " `";

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

      if (language === "bash" || language == "powershell") {
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

          var codeLineEndsWithMultilineSeparator;
          var promptString;
          if (language == "bash") {
            codeLineEndsWithMultilineSeparator = trimmedCodeLine.endsWith(bashNewlineEscape);
            promptString = bashPrompt
          } else {
            codeLineEndsWithMultilineSeparator = trimmedCodeLine.endsWith(powershellNewlineEscape);
            promptString = powershellPrompt
          }

          var isPartOfMultilineCommand = isMultilineCommandStarted && codeLineEndsWithMultilineSeparator;
          var isEndOfMultilineCommand = isMultilineCommandStarted && !codeLineEndsWithMultilineSeparator;
          if (!isPartOfMultilineCommand) {
            isMultilineCommandStarted = !isMultilineCommandStarted && codeLineEndsWithMultilineSeparator;
          }

          var codeLineIsCommand = !isPartOfMultilineCommand && !isEndOfMultilineCommand && !isPartOfEof && !isEndOfEof;
          if (!!trimmedCodeLine && codeLineIsCommand) {
            codeLinesHtml[i] = `<span class='code-snippet__command-prefix'>${promptString} </span>${codeLinesHtml[i]}`;
          }
        }

        codeSectionContent.innerHTML = codeLinesHtml.join('\n');
      }

      $(function () {
        $('[data-toggle="tooltip"]').tooltip();
      });

      var copyButton = document.createElement('a');
      copyButton.setAttribute('type', 'btn');
      copyButton.setAttribute('class', `${copyButtonClass} ${toolBarButtonClass}`);
      copyButton.setAttribute('data-clipboard-target', '#' + currentCodeSectionId);
      copyButton.innerHTML = '<i class="glyphicon glyphicon-duplicate" data-toggle="tooltip" data-placement="bottom" title="Copy"></i>';

      var downloadButton = document.createElement('a');
      downloadButton.setAttribute('type', 'btn');
      downloadButton.setAttribute('class', `${downloadButtonClass} ${toolBarButtonClass}`);
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
      this.appendChild(toolbarDiv);
      this.onmouseover = function() {
        toolbarDiv.classList.add(codeToolbarVisibleClass);
      }
      this.onmouseout = function() {
        toolbarDiv.classList.remove(codeToolbarVisibleClass);
      }
    }
  });

  var clipboard = new ClipboardJS(`.${copyButtonClass}`,
    {
      text: trigger => {
        const codeSnippetId = trigger.getAttribute('data-clipboard-target').replace('#', '');

        const codeSnippet = document.getElementById(codeSnippetId);

        const normalizedText = codeSnippet.innerText
          .split('\n')
          .map(str => {
            if (str.startsWith(bashPrompt)) {
              return str.slice(bashPrompt.length , str.length).trimLeft();
            } else if (str.startsWith(powershellPrompt)) {
              return str.slice(powershellPrompt.length, str.length).trimLeft();
            }

            return str;
          })
          .join('\n');

        return normalizedText;
      },
    },
  );

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
