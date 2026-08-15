(() => {
  const boot = JSON.parse(document.getElementById("boot").textContent);
  const SESSION_KEY = "rba.idp.session";

  const panels = {
    unknown: document.getElementById("panel-unknown"),
    credentials: document.getElementById("panel-credentials"),
    challenge: document.getElementById("panel-challenge"),
    blocked: document.getElementById("panel-blocked"),
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

  function renderDecision(container, body) {
    container.replaceChildren();
    if (!body || (!body.action && !body.reasons?.length)) return;

    const heading = document.createElement("h2");
    heading.textContent = "Why this decision";
    container.append(heading);

    const meta = document.createElement("p");
    if (body.risk_level) {
      const badge = document.createElement("span");
      badge.className = `badge ${body.risk_level}`;
      badge.textContent = body.risk_level;
      meta.append(badge);
    }
    const bits = [];
    if (body.action) bits.push(body.action);
    if (typeof body.risk_score === "number") {
      bits.push(`score ${body.risk_score.toFixed(2)}`);
    }
    meta.append(document.createTextNode(bits.join(" · ")));
    container.append(meta);

    if (body.reasons?.length) {
      const list = document.createElement("ul");
      list.className = "reasons";
      body.reasons.forEach((reason) => {
        const item = document.createElement("li");
        const detail = reason.detail || reason.code;
        item.append(document.createTextNode(detail));
        if (reason.signal) {
          const sig = document.createElement("div");
          sig.className = "signal";
          sig.textContent = reason.signal;
          item.append(sig);
        }
        list.append(item);
      });
      container.append(list);
    }
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
    if (outcome === "BLOCKED") {
      renderDecision(document.getElementById("blocked-decision"), body);
      show("blocked");
      return;
    }
    if (outcome === "MFA_REQUIRED" || outcome === "REAUTH_REQUIRED") {
      const title = document.getElementById("challenge-title");
      const lede = document.getElementById("challenge-lede");
      if (outcome === "REAUTH_REQUIRED") {
        title.textContent = "Confirm it’s you";
        lede.textContent = "Risk is high enough that this IdP wants a re-authentication step.";
      } else {
        title.textContent = "Verify it’s you";
        lede.textContent = "The PDP asked for MFA before issuing a session.";
      }
      document.getElementById("form-mfa").dataset.challengeId = body.challenge_id;
      renderDecision(document.getElementById("challenge-decision"), body);
      setError("mfa-error", "");
      show("challenge");
      document.getElementById("otp").focus();
      return;
    }
    if (outcome === "AUTHENTICATED" && body.session?.token) {
      storeSession(body.session.token);
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
    renderDecision(document.getElementById("session-decision"), body);
    show("session");
  }

  async function restoreSession() {
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
    document.getElementById("form-mfa").reset();
    document.getElementById("otp").value = "";
    show("credentials");
  }

  document.getElementById("challenge-restart").addEventListener("click", restart);
  document.getElementById("blocked-restart").addEventListener("click", restart);
  document.getElementById("unavailable-restart").addEventListener("click", restart);

  if (boot.unknown_application) {
    show("unknown");
    return;
  }

  const appName = boot.application_name || boot.application_id;
  document.getElementById("credentials-title").textContent = `Sign in to ${appName}`;
  document.getElementById("credentials-lede").textContent =
    "This page is hosted by the IdP. The application never sees your password.";

  document.getElementById("form-login").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("login-error", "");
    const submit = document.getElementById("login-submit");
    submit.disabled = true;
    try {
      const resp = await fetch("/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: document.getElementById("email").value,
          password: document.getElementById("password").value,
          application_id: boot.application_id,
          ip_address: boot.ip_address,
          ...deviceHints(navigator.userAgent || ""),
        }),
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

  document.getElementById("form-mfa").addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("mfa-error", "");
    const submit = document.getElementById("mfa-submit");
    submit.disabled = true;
    try {
      const resp = await fetch("/mfa/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          challenge_id: event.currentTarget.dataset.challengeId,
          code: document.getElementById("otp").value,
        }),
      });
      const body = await parseJson(resp);
      if (resp.status === 400) {
        setError("mfa-error", "This challenge is unknown or expired.");
        return;
      }
      if (body.outcome === "INVALID_CREDENTIALS") {
        setError("mfa-error", "That code is not right.");
        return;
      }
      applyOutcome(body, resp.status);
    } catch {
      show("unavailable");
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
