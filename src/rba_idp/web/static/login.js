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
    nofactor: document.getElementById("panel-nofactor"),
    offer: document.getElementById("panel-offer"),
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
    if (outcome === "SECOND_FACTOR_MISSING") {
      // ADR-0037: a step-up never becomes an enrollment.
      show("nofactor");
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
      if (body.passkey_offer && window.PublicKeyCredential) {
        // A usual-context login of a user with no passkey: the one moment
        // (besides an activation code) a passkey may be added.
        pendingLogin = body;
        setError("offer-error", "");
        show("offer");
        return;
      }
      continueAfterLogin(body);
      return;
    }
    setError("login-error", body.detail || "Unexpected response from the IdP.");
    show("credentials");
  }

  let pendingLogin = null;

  function continueAfterLogin(body) {
    if (body.redirect_to) {
      window.location.assign(body.redirect_to);
      return;
    }
    if (boot.next && boot.next.startsWith("/admin")) {
      window.location.assign(boot.next);
      return;
    }
    showSignedIn(body);
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
  document.getElementById("nofactor-restart").addEventListener("click", restart);

  document.getElementById("offer-skip").addEventListener("click", (event) => {
    event.preventDefault();
    if (pendingLogin) continueAfterLogin(pendingLogin);
  });

  document.getElementById("offer-add").addEventListener("click", async () => {
    const button = document.getElementById("offer-add");
    button.disabled = true;
    setError("offer-error", "");
    try {
      const optionsResp = await fetch("/passkeys/options", {
        method: "POST",
        headers: authHeader(),
      });
      if (optionsResp.status !== 200) {
        // The window closed or a passkey exists now; nothing to add.
        continueAfterLogin(pendingLogin);
        return;
      }
      const options = await parseJson(optionsResp);
      const cred = await navigator.credentials.create({
        publicKey: publicKeyFromJson(options.public_key),
      });
      const resp = await fetch("/passkeys/verify", {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeader() },
        body: JSON.stringify({ credential: credentialToJson(cred) }),
      });
      if (resp.status !== 204) {
        setError("offer-error", "Couldn't save the passkey. You can continue without it.");
        return;
      }
      continueAfterLogin(pendingLogin);
    } catch (err) {
      setError(
        "offer-error",
        err && err.name === "NotAllowedError"
          ? "Cancelled. You can try again or continue without it."
          : "Couldn't save the passkey. You can continue without it."
      );
    } finally {
      button.disabled = false;
    }
  });

  if (boot.unknown_application) {
    show("unknown");
    return;
  }

  const appName = boot.tenant_name && boot.tenant_name !== boot.application_name
    ? `${boot.application_name} · ${boot.tenant_name}`
    : boot.application_name || boot.application_id;
  document.getElementById("credentials-title").textContent = `Sign in to ${appName}`;
  document.getElementById("credentials-lede").textContent =
    "This page is hosted by the IdP. The application never sees your password.";

  const { publicKeyFromJson, credentialToJson } = window.RbaPasskey;

  document.getElementById("form-login").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("login-error", "");
    const submit = document.getElementById("login-submit");
    submit.disabled = true;
    try {
      const payload = {
        email: document.getElementById("email").value,
        password: document.getElementById("password").value,
        ip_address: boot.ip_address,
        country: boot.country,
        asn: boot.asn,
        ...deviceHints(navigator.userAgent || ""),
      };
      // The console login names no application: the server finds the
      // operator's tenant from the email's domain (ADR-0033).
      if (!boot.console) payload.application_id = boot.application_id;
      if (boot.redirect_uri) payload.redirect_uri = boot.redirect_uri;
      const resp = await fetch(boot.console ? "/console/login" : "/login", {
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
      const cred = await navigator.credentials.get({ publicKey });
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
