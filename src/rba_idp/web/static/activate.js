// ADR-0037: enroll a passkey with an operator-issued code plus the password.
//
// Two taps on purpose. Mobile browsers (iOS Safari above all) only open the
// passkey prompt when navigator.credentials.create() runs straight from a
// tap; awaiting a network request first cancels it ("NotAllowedError"). So
// the first tap checks the code and fetches the options, and the second tap
// goes directly to create().
(() => {
  const { publicKeyFromJson, credentialToJson, waiting, warnInApp } = window.RbaPasskey;
  const wait = document.getElementById("create-wait");
  let code = "";
  let publicKey = null;

  function setError(id, message) {
    const el = document.getElementById(id);
    el.hidden = !message;
    el.textContent = message || "";
  }

  function show(id) {
    for (const panel of ["panel-form", "panel-create", "panel-done"]) {
      document.getElementById(panel).hidden = panel !== id;
    }
  }

  document.getElementById("form-activate").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("activate-error", "");
    if (!window.PublicKeyCredential) {
      setError("activate-error", "This browser cannot create a passkey.");
      return;
    }
    const submit = document.getElementById("activate-submit");
    submit.disabled = true;
    code = document.getElementById("code").value;
    try {
      const resp = await fetch("/activate/options", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code, password: document.getElementById("password").value }),
      });
      if (resp.status !== 200) {
        setError("activate-error", "The code or the password is not right, or the code has expired.");
        return;
      }
      publicKey = publicKeyFromJson((await resp.json()).public_key);
      setError("create-error", "");
      show("panel-create");
      warnInApp(document.getElementById("create-inapp"));
    } catch {
      setError("activate-error", "Couldn't reach the server. Try again.");
    } finally {
      submit.disabled = false;
    }
  });

  document.getElementById("create-submit").addEventListener("click", async () => {
    if (!publicKey) return;
    const button = document.getElementById("create-submit");
    button.disabled = true;
    setError("create-error", "");
    try {
      // First thing in the tap handler: nothing awaited before it.
      const pending = navigator.credentials.create({ publicKey });
      waiting(wait, true);
      const cred = await pending;
      waiting(wait, false);
      const resp = await fetch("/activate/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code, credential: credentialToJson(cred) }),
      });
      if (resp.status !== 204) {
        setError("create-error", "Couldn't save the passkey. Ask support for a new code.");
        return;
      }
      show("panel-done");
    } catch (err) {
      waiting(wait, false);
      const name = err && err.name ? err.name : "Error";
      setError(
        "create-error",
        name === "NotAllowedError"
          ? "The device did not create the passkey (cancelled or not allowed). Tap again to retry."
          : `Couldn't create the passkey (${name}). Ask support for a new code.`
      );
    } finally {
      button.disabled = false;
    }
  });
})();
