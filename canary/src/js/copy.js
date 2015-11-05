// Copy to clipboard
var copyButton = document.getElementById('copy-button');
var copyStatus = document.getElementById('copy-status');
var ciphertext = document.getElementById('ciphertext')

// copyButton is disabled by default. It's enabled if the user allows JavaScript.
copyButton.disabled = false;

document.addEventListener('copy', function(e) {
  e.clipboardData.setData('text/plain', ciphertext.innerText);
  e.preventDefault();
});

// Trigger copy event with copyButton (keyboard works too, of course)
copyButton.addEventListener('click', function(e) {
  e.preventDefault();
  try {
    document.execCommand('copy');
    copyStatus.innerText = "Copied!";
  } catch (e) {
      copyStatus.innerText = "Copy failed"
  }
});

