(() => {
  const boot = JSON.parse(document.getElementById("boot").textContent);
  const SESSION_KEY = "rba.idp.session";

  const panels = {
    unknown: document.getElementById("panel-unknown"),
    credentials: document.getElementById("panel-credentials"),
    challenge: document.getElementById("panel-challenge"),
    blocked: document.getElementById("panel-blocked"),
    denied: document.getElementById("panel-denied"),
    session: document.getElementById("panel-session"),
    unavailable: document.getElementById("panel-unavailable"),
  };

  function show(name) {
    Object.entries(panels).forEach(([key, el]) => {
      el.hidden = key !== name;
    });
  }

  function deviceHints(ua) {
    const u = ua.toLowerCase();
    const hints = { user_agent: ua };
    if (/iphone|ipad|android|mobile/.test(u)) hints.device_type = "mobile";
    else if (ua) hints.device_type = "desktop";
    if (u.includes("android")) hints.os = "Android";
    else if (/iphone|ipad|ipod/.test(u)) hints.os = "iOS";
    else if (u.includes("mac os")) hints.os = "macOS";
    else if (u.includes("windows")) hints.os = "Windows";
    else if (u.includes("linux")) hints.os = "Linux";
    if (u.includes("edg/")) hints.browser = "Edge";
    else if (u.includes("chrome") && !u.includes("edg/")) hints.browser = "Chrome";
    else if (u.includes("firefox")) hints.browser = "Firefox";
    else if (u.includes("safari")) hints.browser = "Safari";
    return hints;
  }

  function setError(id, message) {
    const el = document.getElementById(id);
    if (!message) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    el.hidden = false;
    el.textContent = message;
  }

  function storeSession(token) {
    sessionStorage.setItem(SESSION_KEY, token);
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  function authHeader() {
    const token = sessionStorage.getItem(SESSION_KEY);
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  async function parseJson(resp) {
    const text = await resp.text();
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch {
      return {};
    }
  }

  function applyOutcome(body, status) {
    if (status === 503) {
      show("unavailable");
      return;
    }
    const outcome = body.outcome;
    if (outcome === "INVALID_CREDENTIALS") {
      show("credentials");
      setError("login-error", "Email or password is not right.");
      return;
    }
    if (outcome === "ACCESS_DENIED") {
      show("denied");
      return;
    }
    if (outcome === "BLOCKED") {
      show("blocked");
      return;
    }
    if (outcome === "MFA_REQUIRED" || outcome === "REAUTH_REQUIRED") {
      document.getElementById("challenge-title").textContent = "Confirm it’s you";
      document.getElementById("challenge-lede").textContent =
        "Use this device to confirm the sign-in.";
      document.getElementById("mfa-submit").dataset.challengeId = body.challenge_id;
      setError("mfa-error", "");
      show("challenge");
      return;
    }
    if (outcome === "AUTHENTICATED" && body.session?.token) {
      storeSession(body.session.token);
      if (body.redirect_to) {
        window.location.assign(body.redirect_to);
        return;
      }
      if (boot.next && boot.next.startsWith("/admin")) {
        window.location.assign(boot.next);
        return;
      }
      showSignedIn(body);
      return;
    }
    setError("login-error", body.detail || "Unexpected response from the IdP.");
    show("credentials");
  }

  function showSignedIn(body, session) {
    const email = session?.user?.email || "";
    const userId = body?.user_id || session?.user?.user_id || "";
    document.getElementById("session-lede").textContent = email
      ? `You are signed in as ${email}.`
      : "You have an active IdP session.";
    const facts = document.getElementById("session-facts");
    facts.replaceChildren();
    const rows = [
      ["User", email || userId],
      ["Expires", session?.expires_at ? new Date(session.expires_at).toLocaleString() : ""],
    ];
    rows.forEach(([k, v]) => {
      if (!v) return;
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = v;
      facts.append(dt, dd);
    });
    show("session");
  }

  async function restoreSession() {
    if (boot.redirect_uri) return false;
    const token = sessionStorage.getItem(SESSION_KEY);
    if (!token) return false;
    const resp = await fetch("/session", { headers: authHeader() });
    if (resp.status !== 200) {
      clearSession();
      return false;
    }
    const session = await parseJson(resp);
    showSignedIn({}, session);
    return true;
  }

  function restart(event) {
    event.preventDefault();
    setError("login-error", "");
    setError("mfa-error", "");
    delete document.getElementById("mfa-submit").dataset.challengeId;
    show("credentials");
  }

  document.getElementById("challenge-restart").addEventListener("click", restart);
  document.getElementById("blocked-restart").addEventListener("click", restart);
  document.getElementById("denied-restart").addEventListener("click", restart);
  document.getElementById("unavailable-restart").addEventListener("click", restart);

  if (boot.unknown_application) {
    show("unknown");
    return;
  }

  const appName = boot.application_name || boot.application_id;
  document.getElementById("credentials-title").textContent = `Sign in to ${appName}`;
  document.getElementById("credentials-lede").textContent =
    "This page is hosted by the IdP. The application never sees your password.";

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

  document.getElementById("form-login").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("login-error", "");
    const submit = document.getElementById("login-submit");
    submit.disabled = true;
    try {
      const payload = {
        email: document.getElementById("email").value,
        password: document.getElementById("password").value,
        application_id: boot.application_id,
        ip_address: boot.ip_address,
        country: boot.country,
        asn: boot.asn,
        ...deviceHints(navigator.userAgent || ""),
      };
      if (boot.redirect_uri) payload.redirect_uri = boot.redirect_uri;
      const resp = await fetch("/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await parseJson(resp);
      if (resp.status === 400) {
        setError("login-error", body.detail || "Unknown application.");
        return;
      }
      applyOutcome(body, resp.status);
    } catch {
      show("unavailable");
    } finally {
      submit.disabled = false;
    }
  });

  document.getElementById("mfa-submit").addEventListener("click", async () => {
    setError("mfa-error", "");
    const submit = document.getElementById("mfa-submit");
    const challengeId = submit.dataset.challengeId;
    if (!challengeId) return;
    if (!window.PublicKeyCredential) {
      setError("mfa-error", "This browser cannot confirm this device.");
      return;
    }
    submit.disabled = true;
    try {
      const optionsResp = await fetch("/mfa/webauthn/options", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ challenge_id: challengeId }),
      });
      const optionsBody = await parseJson(optionsResp);
      if (optionsResp.status === 400) {
        setError("mfa-error", "This challenge is unknown or expired.");
        return;
      }
      const publicKey = publicKeyFromJson(optionsBody.public_key);
      const cred =
        optionsBody.mode === "create"
          ? await navigator.credentials.create({ publicKey })
          : await navigator.credentials.get({ publicKey });
      if (!cred) {
        setError("mfa-error", "Confirmation was cancelled.");
        return;
      }
      const payload = {
        challenge_id: challengeId,
        credential: credentialToJson(cred),
      };
      if (boot.redirect_uri) payload.redirect_uri = boot.redirect_uri;
      const resp = await fetch("/mfa/webauthn/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await parseJson(resp);
      if (resp.status === 400) {
        setError("mfa-error", "This challenge is unknown or expired.");
        return;
      }
      if (body.outcome === "INVALID_CREDENTIALS") {
        setError("mfa-error", "Couldn't confirm this device.");
        return;
      }
      applyOutcome(body, resp.status);
    } catch (err) {
      if (err && err.name === "NotAllowedError") {
        setError("mfa-error", "Confirmation was cancelled.");
      } else {
        setError("mfa-error", "Couldn't confirm this device.");
      }
    } finally {
      submit.disabled = false;
    }
  });

  document.getElementById("form-logout").addEventListener("submit", async (event) => {
    event.preventDefault();
    await fetch("/logout", { method: "POST", headers: authHeader() });
    clearSession();
    document.getElementById("form-login").reset();
    show("credentials");
  });

  restoreSession();
})();
