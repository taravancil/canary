// Customized form validation
var form = document.forms.step2;
form.decrypted.oninvalid = function() {
  form.decrypted.setCustomValidity("Decrypt the secret to post your canary.");
};
form.decrypted.oninput = function() {
  form.decrypted.setCustomValidity("");
};

