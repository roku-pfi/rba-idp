// WebAuthn JSON <-> browser buffers. Shared by the login and activation pages.
(() => {
  function b64urlToBuf(value) {
    const pad = "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function publicKeyFromJson(options) {
    const pk = { ...options, challenge: b64urlToBuf(options.challenge) };
    if (options.user) {
      pk.user = { ...options.user, id: b64urlToBuf(options.user.id) };
    }
    if (options.excludeCredentials) {
      pk.excludeCredentials = options.excludeCredentials.map((item) => ({
        ...item,
        id: b64urlToBuf(item.id),
      }));
    }
    if (options.allowCredentials) {
      pk.allowCredentials = options.allowCredentials.map((item) => ({
        ...item,
        id: b64urlToBuf(item.id),
      }));
    }
    return pk;
  }

  function credentialToJson(cred) {
    const response = cred.response;
    const payload = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(response.clientDataJSON),
      },
    };
    if (cred.authenticatorAttachment) {
      payload.authenticatorAttachment = cred.authenticatorAttachment;
    }
    if (response.attestationObject) {
      payload.response.attestationObject = bufToB64url(response.attestationObject);
      if (typeof response.getTransports === "function") {
        payload.response.transports = response.getTransports();
      }
    }
    if (response.authenticatorData) {
      payload.response.authenticatorData = bufToB64url(response.authenticatorData);
      payload.response.signature = bufToB64url(response.signature);
      if (response.userHandle) {
        payload.response.userHandle = bufToB64url(response.userHandle);
      }
    }
    return payload;
  }

  // In-app browsers (a link opened from WhatsApp, Instagram, Gmail…) often
  // accept the WebAuthn call and then never show the passkey prompt.
  function inAppBrowser(ua = navigator.userAgent || "") {
    return /FBAN|FBAV|Instagram|WhatsApp|Telegram|Line\/|GSA\/|; wv\)|LinkedInApp|Twitter/i.test(ua);
  }

  const HINT =
    "If no prompt appears, open this page in Safari or Chrome directly — not inside another app — and check that passkeys are on in your phone's password settings.";

  // While the browser's prompt is (or should be) on screen. Without it, a
  // prompt that never appears looks like a dead button.
  function waiting(el, on) {
    if (!el) return;
    el.hidden = !on;
    el.textContent = on ? `Waiting for your device… ${HINT}` : "";
  }

  // Shown before the tap when the page can tell it is in an in-app browser.
  function warnInApp(el) {
    if (!el || !inAppBrowser()) return;
    el.hidden = false;
    el.textContent = `This looks like an in-app browser, where passkeys often do not work. ${HINT}`;
  }

  window.RbaPasskey = {
    b64urlToBuf,
    bufToB64url,
    publicKeyFromJson,
    credentialToJson,
    inAppBrowser,
    waiting,
    warnInApp,
  };
})();
