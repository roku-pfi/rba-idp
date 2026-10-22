// ADR-0037: enroll a passkey with an operator-issued code plus the password.
(() => {
  const { publicKeyFromJson, credentialToJson } = window.RbaPasskey;
  const error = document.getElementById("activate-error");

  function setError(message) {
    error.hidden = !message;
    error.textContent = message || "";
  }

  document.getElementById("form-activate").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("");
    if (!window.PublicKeyCredential) {
      setError("This browser cannot create a passkey.");
      return;
    }
    const submit = document.getElementById("activate-submit");
    submit.disabled = true;
    const code = document.getElementById("code").value;
    try {
      const optionsResp = await fetch("/activate/options", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code, password: document.getElementById("password").value }),
      });
      if (optionsResp.status !== 200) {
        setError("The code or the password is not right, or the code has expired.");
        return;
      }
      const options = await optionsResp.json();
      const cred = await navigator.credentials.create({
        publicKey: publicKeyFromJson(options.public_key),
      });
      const resp = await fetch("/activate/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code, credential: credentialToJson(cred) }),
      });
      if (resp.status !== 204) {
        setError("Couldn't save the passkey. Ask support for a new code.");
        return;
      }
      document.getElementById("panel-form").hidden = true;
      document.getElementById("panel-done").hidden = false;
    } catch (err) {
      setError(
        err && err.name === "NotAllowedError"
          ? "Cancelled. You can try again with the same code."
          : "Couldn't save the passkey. Ask support for a new code."
      );
    } finally {
      submit.disabled = false;
    }
  });
})();
