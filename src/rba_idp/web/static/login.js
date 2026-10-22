(() => {
  const boot = JSON.parse(document.getElementById("boot").textContent);
  const SESSION_KEY = "rba.idp.session";

  const panels = {
    unknown: document.getElementById("panel-unknown"),
    credentials: document.getElementById("panel-credentials"),
    checking: document.getElementById("panel-checking"),
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
      setError("login-error", "El email o la contraseña no son correctos.");
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
      document.getElementById("challenge-title").textContent = "Confirmá que sos vos";
      document.getElementById("challenge-lede").textContent = "Con la passkey de este dispositivo.";
      document.getElementById("mfa-submit").dataset.challengeId = body.challenge_id;
      setError("mfa-error", "");
      show("challenge");
      warnInApp(document.getElementById("mfa-inapp"));
      prepareStepUp(body.challenge_id);
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
        warnInApp(document.getElementById("offer-inapp"));
        prepareOffer();
        return;
      }
      continueAfterLogin(body);
      return;
    }
    setError("login-error", "Algo salió mal. Probá de nuevo.");
    show("credentials");
  }

  let pendingLogin = null;

  // Mobile browsers (iOS Safari above all) open the passkey prompt only when
  // navigator.credentials.get()/create() runs straight from a tap; awaiting a
  // request first cancels it (NotAllowedError, shown as "cancelled"). So the
  // options are fetched as soon as the panel appears, and the button goes
  // directly to the prompt.
  let stepUpKey = null;
  let offerKey = null;

  async function prepareStepUp(challengeId) {
    const button = document.getElementById("mfa-submit");
    stepUpKey = null;
    button.disabled = true;
    button.style.display = "";
    document.getElementById("form-otp").hidden = true;
    try {
      const resp = await fetch("/mfa/webauthn/options", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ challenge_id: challengeId }),
      });
      if (resp.status !== 200) {
        if (boot.mock_otp) {
          // No passkey to use; locally the test code stands in for one.
          button.style.display = "none";
          document.getElementById("form-otp").hidden = false;
          document.getElementById("form-otp").dataset.challengeId = challengeId;
          document.getElementById("otp").focus();
          return;
        }
        setError("mfa-error", "El pedido venció. Empezá de nuevo.");
        return;
      }
      stepUpKey = publicKeyFromJson((await parseJson(resp)).public_key);
    } catch {
      setError("mfa-error", "Sin conexión con el servidor. Empezá de nuevo.");
    } finally {
      button.disabled = stepUpKey === null;
    }
  }

  async function prepareOffer() {
    const button = document.getElementById("offer-add");
    offerKey = null;
    button.disabled = true;
    try {
      const resp = await fetch("/passkeys/options", { method: "POST", headers: authHeader() });
      if (resp.status !== 200) {
        // The window closed or a passkey exists now; nothing to add.
        continueAfterLogin(pendingLogin);
        return;
      }
      offerKey = publicKeyFromJson((await parseJson(resp)).public_key);
    } catch {
      continueAfterLogin(pendingLogin);
    } finally {
      button.disabled = offerKey === null;
    }
  }

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
      ? email
      : "";
    const facts = document.getElementById("session-facts");
    facts.replaceChildren();
    const rows = [
      ["Usuario", email || userId],
      ["Vence", session?.expires_at ? new Date(session.expires_at).toLocaleString("es-AR", { dateStyle: "short", timeStyle: "short" }) : ""],
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
      if (!offerKey) return;
      // First thing in the tap handler: nothing awaited before it.
      const pending = navigator.credentials.create({ publicKey: offerKey });
      waiting(document.getElementById("offer-wait"), true);
      const cred = await pending;
      waiting(document.getElementById("offer-wait"), false);
      const resp = await fetch("/passkeys/verify", {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeader() },
        body: JSON.stringify({ credential: credentialToJson(cred) }),
      });
      if (resp.status !== 204) {
        setError("offer-error", "No se pudo guardar la passkey. Podés seguir sin ella.");
        return;
      }
      continueAfterLogin(pendingLogin);
    } catch (err) {
      waiting(document.getElementById("offer-wait"), false);
      setError(
        "offer-error",
        err && err.name === "NotAllowedError"
          ? "Cancelado. Podés reintentar o seguir sin ella."
          : "No se pudo guardar la passkey. Podés seguir sin ella."
      );
    } finally {
      button.disabled = false;
    }
  });

  if (boot.unknown_application) {
    show("unknown");
    return;
  }

  // RokuSec's page says where you are going; the tenant's page is already its
  // own, so it needs no subtitle.
  const appName = boot.application_name || boot.application_id;
  document.getElementById("credentials-lede").textContent =
    boot.look === "tenant" ? "" : boot.console ? "Consola de RokuSec" : `Continuá a ${appName}`;

  const { publicKeyFromJson, credentialToJson, waiting, warnInApp } = window.RbaPasskey;

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
      if (boot.simulation_ticket && !boot.console) payload.simulation_ticket = boot.simulation_ticket;
      // The scanning ring stays up long enough to be read as a step, not a flicker.
      show("checking");
      const [resp] = await Promise.all([
        fetch(boot.console ? "/console/login" : "/login", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        }),
        new Promise((resolve) => setTimeout(resolve, 700)),
      ]);
      const body = await parseJson(resp);
      if (resp.status === 400) {
        show("credentials");
        setError("login-error", "Aplicación desconocida.");
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
      setError("mfa-error", "Este navegador no admite passkeys.");
      return;
    }
    if (!stepUpKey) return;
    submit.disabled = true;
    try {
      // First thing in the tap handler: nothing awaited before it. The same
      // options serve a retry: the challenge stays open until it succeeds.
      const pending = navigator.credentials.get({ publicKey: stepUpKey });
      waiting(document.getElementById("mfa-wait"), true);
      const cred = await pending;
      waiting(document.getElementById("mfa-wait"), false);
      if (!cred) {
        setError("mfa-error", "Cancelado. Podés reintentar.");
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
        setError("mfa-error", "El pedido venció. Empezá de nuevo.");
        return;
      }
      if (body.outcome === "INVALID_CREDENTIALS") {
        setError("mfa-error", "No se pudo confirmar con este dispositivo.");
        return;
      }
      applyOutcome(body, resp.status);
    } catch (err) {
      waiting(document.getElementById("mfa-wait"), false);
      if (err && err.name === "NotAllowedError") {
        setError("mfa-error", "Cancelado. Podés reintentar.");
      } else {
        setError("mfa-error", "No se pudo confirmar con este dispositivo.");
      }
    } finally {
      submit.disabled = false;
    }
  });

  document.getElementById("form-otp").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("mfa-error", "");
    const form = event.currentTarget;
    const payload = { challenge_id: form.dataset.challengeId, code: document.getElementById("otp").value.trim() };
    if (boot.redirect_uri) payload.redirect_uri = boot.redirect_uri;
    const resp = await fetch("/mfa/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await parseJson(resp);
    if (resp.status !== 200 || body.outcome === "INVALID_CREDENTIALS") {
      setError("mfa-error", "Código incorrecto.");
      return;
    }
    applyOutcome(body, resp.status);
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
