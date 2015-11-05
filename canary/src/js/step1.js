// Add aria-invalid=true to every invalid input
// Customize validation feedback
inputs = document.querySelectorAll("input[type=number], input[type=text], textarea");
for (var i = 0; i < inputs.length; i++) { 
  el = inputs[i];
  el.addEventListener('invalid', function(e) {
    setCustomInValidMsg(e.target);
    e.target.setAttribute('aria-invalid', 'true');
  });
  el.addEventListener('change', function(e) {
    e.target.removeAttribute('aria-invalid');
    setCustomValidMsg(e.target);
  });
}

function setCustomInValidMsg(node) {
  switch (node.name) {
  	case "signedMessage":
  		node.setCustomValidity("Paste a PGP-signed message.");
      break;
    case "frequencyNum":
      if (document.querySelector("input[name=frequency]:checked") != null) {
        freq = document.querySelector("input[name=frequency]:checked");
        node.setCustomValidity("How many " + freq.value + "s?");
      }
      break;
    case "decrypted":
      node.setCustomValidity("Decrypt the message above to post your canary!");
      break;
  }
}

function setCustomValidMsg(node) {
  switch (node.name) {
    case "frequencyNum":
    case "signedMessage":
      node.setCustomValidity("");
      break;
  }
}

