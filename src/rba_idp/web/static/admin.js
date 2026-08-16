(() => {
  const SESSION_KEY = "rba.idp.session";
  const ADMIN_APP = "idp-admin-console";
  const root = document.getElementById("root");

  const state = {
    user: null,
    tab: "decisions",
    users: [],
    apps: [],
    groups: [],
    selectedGroup: null,
    decisions: [],
    policyText: "",
    error: "",
    notice: "",
  };

  function token() {
    return sessionStorage.getItem(SESSION_KEY);
  }

  function authHeader() {
    const value = token();
    return value ? { Authorization: `Bearer ${value}` } : {};
  }

  async function parseJson(resp) {
    const text = await resp.text();
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch {
      return { detail: text };
    }
  }

  function detailOf(body) {
    if (!body) return "Request failed.";
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return "Invalid request.";
    return body.detail ? JSON.stringify(body.detail) : "Request failed.";
  }

  async function api(path, options = {}) {
    const resp = await fetch(path, {
      ...options,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        ...authHeader(),
        ...(options.headers || {}),
      },
    });
    const body = await parseJson(resp);
    if (resp.status === 401) {
      sessionStorage.removeItem(SESSION_KEY);
      window.location.assign(`/login?application_id=${ADMIN_APP}&next=/admin`);
      throw new Error("unauthorized");
    }
    if (!resp.ok) {
      throw new Error(detailOf(body));
    }
    return body;
  }

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (key === "class") node.className = value;
      else if (key === "onClick") node.addEventListener("click", value);
      else if (key === "onSubmit") node.addEventListener("submit", value);
      else if (key === "html") node.innerHTML = value;
      else if (value === false || value === null || value === undefined) return;
      else if (key === "checked") node.checked = Boolean(value);
      else node.setAttribute(key, value);
    });
    children.flat().forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    });
    return node;
  }

  function setTab(tab) {
    state.tab = tab;
    state.error = "";
    state.notice = "";
    loadTab();
  }

  async function loadTab() {
    try {
      if (state.tab === "users") state.users = await api("/admin/api/users");
      if (state.tab === "apps") state.apps = await api("/admin/api/applications");
      if (state.tab === "groups") {
        const [listed, directory, registered] = await Promise.all([
          api("/admin/api/groups"),
          api("/admin/api/users"),
          api("/admin/api/applications"),
        ]);
        state.groups = listed;
        state.users = directory;
        state.apps = registered;
        if (state.selectedGroup) {
          state.selectedGroup = await api(`/admin/api/groups/${state.selectedGroup.group_id}`);
        }
      }
      if (state.tab === "decisions") {
        const body = await api("/admin/api/decisions");
        state.decisions = body.items || [];
      }
      if (state.tab === "policy") {
        const policy = await api("/admin/api/policy");
        state.policyText = JSON.stringify(policy, null, 2);
      }
    } catch (err) {
      state.error = err.message || String(err);
    }
    render();
  }

  function banner() {
    if (state.error) return el("p", { class: "form-error" }, state.error);
    if (state.notice) return el("p", { class: "ok-msg" }, state.notice);
    return null;
  }

  function usersPanel() {
    const rows = state.users.map((user) =>
      el("tr", {},
        el("td", { class: "mono" }, user.user_id),
        el("td", {}, user.email),
        el("td", {}, user.is_admin ? "admin" : "user"),
        el("td", {}, user.enabled ? "enabled" : "disabled"),
        el("td", {},
          el("button", {
            class: "secondary",
            onClick: async () => {
              try {
                await api(`/admin/api/users/${user.user_id}`, {
                  method: "PATCH",
                  body: JSON.stringify({ enabled: !user.enabled }),
                });
                await loadTab();
              } catch (err) {
                state.error = err.message;
                render();
              }
            },
          }, user.enabled ? "Disable" : "Enable"),
        ),
      ),
    );
    return el("section", { class: "panel" },
      el("h1", {}, "Users"),
      el("p", { class: "lede" }, "Directory of this IdP. Passwords are never listed."),
      banner(),
      el("form", {
        class: "form-row",
        onSubmit: async (event) => {
          event.preventDefault();
          const form = event.currentTarget;
          try {
            await api("/admin/api/users", {
              method: "POST",
              body: JSON.stringify({
                email: form.email.value,
                password: form.password.value,
                is_admin: form.is_admin.checked,
              }),
            });
            form.reset();
            state.notice = "User created.";
            await loadTab();
          } catch (err) {
            state.error = err.message;
            render();
          }
        },
      },
        el("label", {}, "Email", el("input", { name: "email", type: "email", required: true })),
        el("label", {}, "Password", el("input", { name: "password", type: "password", required: true })),
        el("label", { class: "check" }, el("input", { name: "is_admin", type: "checkbox" }), "Admin"),
        el("button", { type: "submit" }, "Create user"),
      ),
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "User id"), el("th", {}, "Email"), el("th", {}, "Role"),
          el("th", {}, "Status"), el("th", {}, ""),
        )),
        el("tbody", {}, ...rows),
      ),
    );
  }

  function appsPanel() {
    const rows = state.apps.map((app) =>
      el("tr", {},
        el("td", { class: "mono" }, app.application_id),
        el("td", {}, app.name),
        el("td", {}, app.enabled ? "enabled" : "disabled"),
        el("td", {},
          el("button", {
            class: "secondary",
            onClick: async () => {
              try {
                await api(`/admin/api/applications/${app.application_id}`, {
                  method: "PATCH",
                  body: JSON.stringify({ enabled: !app.enabled }),
                });
                await loadTab();
              } catch (err) {
                state.error = err.message;
                render();
              }
            },
          }, app.enabled ? "Disable" : "Enable"),
        ),
      ),
    );
    return el("section", { class: "panel" },
      el("h1", {}, "Applications"),
      el("p", { class: "lede" }, "Registered clients. Hosted login requires a known application_id."),
      banner(),
      el("form", {
        class: "form-row",
        onSubmit: async (event) => {
          event.preventDefault();
          const form = event.currentTarget;
          try {
            await api("/admin/api/applications", {
              method: "POST",
              body: JSON.stringify({
                application_id: form.application_id.value,
                name: form.name.value,
              }),
            });
            form.reset();
            state.notice = "Application registered.";
            await loadTab();
          } catch (err) {
            state.error = err.message;
            render();
          }
        },
      },
        el("label", {}, "Application id", el("input", { name: "application_id", required: true })),
        el("label", {}, "Name", el("input", { name: "name", required: true })),
        el("button", { type: "submit" }, "Register app"),
      ),
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Id"), el("th", {}, "Name"), el("th", {}, "Status"), el("th", {}, ""),
        )),
        el("tbody", {}, ...rows),
      ),
    );
  }

  async function refreshGroup(groupId) {
    state.selectedGroup = await api(`/admin/api/groups/${groupId}`);
    state.groups = await api("/admin/api/groups");
    render();
  }

  function groupsPanel() {
    const rows = state.groups.map((row) =>
      el("tr", { class: state.selectedGroup?.group_id === row.group_id ? "selected" : "" },
        el("td", {},
          el("button", {
            class: "linkish",
            type: "button",
            onClick: async () => {
              try {
                state.selectedGroup = await api(`/admin/api/groups/${row.group_id}`);
                render();
              } catch (err) {
                state.error = err.message;
                render();
              }
            },
          }, row.name),
          el("div", { class: "muted mono" }, row.group_id),
        ),
        el("td", {}, String(row.member_count)),
      ),
    );
    const detail = state.selectedGroup
      ? el("div", {},
          el("h2", {}, state.selectedGroup.name),
          el("p", { class: "muted" }, state.selectedGroup.description || "No description"),
          el("button", {
            class: "secondary",
            type: "button",
            onClick: async () => {
              try {
                await api(`/admin/api/groups/${state.selectedGroup.group_id}`, { method: "DELETE" });
                state.selectedGroup = null;
                state.notice = "Group deleted.";
                await loadTab();
              } catch (err) {
                state.error = err.message;
                render();
              }
            },
          }, "Delete group"),
          el("h3", {}, "Members"),
          el("form", {
            class: "form-row",
            onSubmit: async (event) => {
              event.preventDefault();
              try {
                await api(`/admin/api/groups/${state.selectedGroup.group_id}/members`, {
                  method: "POST",
                  body: JSON.stringify({ user_id: event.currentTarget.user_id.value }),
                });
                await refreshGroup(state.selectedGroup.group_id);
              } catch (err) {
                state.error = err.message;
                render();
              }
            },
          },
            el("label", {}, "User",
              el("select", { name: "user_id", required: true },
                ...state.users
                  .filter((user) => !(state.selectedGroup.members || []).some((m) => m.user_id === user.user_id))
                  .map((user) => el("option", { value: user.user_id }, user.email)),
              ),
            ),
            el("button", { type: "submit" }, "Add member"),
          ),
          el("ul", { class: "plain" },
            ...(state.selectedGroup.members || []).map((member) =>
              el("li", {},
                member.email,
                el("button", {
                  class: "secondary",
                  type: "button",
                  onClick: async () => {
                    try {
                      await api(
                        `/admin/api/groups/${state.selectedGroup.group_id}/members/${member.user_id}`,
                        { method: "DELETE" },
                      );
                      await refreshGroup(state.selectedGroup.group_id);
                    } catch (err) {
                      state.error = err.message;
                      render();
                    }
                  },
                }, "Remove"),
              ),
            ),
          ),
          el("h3", {}, "App grants"),
          el("form", {
            class: "form-row",
            onSubmit: async (event) => {
              event.preventDefault();
              try {
                await api(`/admin/api/groups/${state.selectedGroup.group_id}/grants`, {
                  method: "POST",
                  body: JSON.stringify({ application_id: event.currentTarget.application_id.value }),
                });
                await refreshGroup(state.selectedGroup.group_id);
              } catch (err) {
                state.error = err.message;
                render();
              }
            },
          },
            el("label", {}, "Application",
              el("select", { name: "application_id", required: true },
                ...state.apps
                  .filter((app) => !(state.selectedGroup.grants || []).some((g) => g.application_id === app.application_id))
                  .map((app) => el("option", { value: app.application_id }, app.name)),
              ),
            ),
            el("button", { type: "submit" }, "Grant access"),
          ),
          el("ul", { class: "plain" },
            ...(state.selectedGroup.grants || []).map((grant) =>
              el("li", {},
                el("span", { class: "mono" }, grant.application_id),
                ` ${grant.permission}`,
                el("button", {
                  class: "secondary",
                  type: "button",
                  onClick: async () => {
                    try {
                      await api(
                        `/admin/api/groups/${state.selectedGroup.group_id}/grants/${grant.application_id}`,
                        { method: "DELETE" },
                      );
                      await refreshGroup(state.selectedGroup.group_id);
                    } catch (err) {
                      state.error = err.message;
                      render();
                    }
                  },
                }, "Revoke"),
              ),
            ),
          ),
        )
      : el("p", { class: "muted" }, "Select a group to manage members and app grants.");
    return el("section", { class: "panel" },
      el("h1", {}, "Groups"),
      el("p", { class: "lede" }, "App-scoped access. A user may sign in to an application only if one of their groups grants access."),
      banner(),
      el("form", {
        class: "form-row",
        onSubmit: async (event) => {
          event.preventDefault();
          const form = event.currentTarget;
          try {
            state.selectedGroup = await api("/admin/api/groups", {
              method: "POST",
              body: JSON.stringify({
                name: form.name.value,
                description: form.description.value || "",
              }),
            });
            form.reset();
            state.notice = "Group created.";
            await loadTab();
          } catch (err) {
            state.error = err.message;
            render();
          }
        },
      },
        el("label", {}, "Name", el("input", { name: "name", required: true })),
        el("label", {}, "Description", el("input", { name: "description" })),
        el("button", { type: "submit" }, "Create group"),
      ),
      el("div", { class: "split" },
        el("table", {},
          el("thead", {}, el("tr", {}, el("th", {}, "Group"), el("th", {}, "Members"))),
          el("tbody", {}, ...rows),
        ),
        detail,
      ),
    );
  }

  function decisionsPanel() {
    const rows = state.decisions.map((item) => {
      const reasons = (item.reasons || []).map((reason) =>
        el("li", {},
          reason.detail || reason.code,
          reason.signal ? el("div", { class: "signal" }, reason.signal) : null,
        ),
      );
      return el("tr", {},
        el("td", {},
          el("div", { class: "mono" }, item.event_id),
          el("div", { class: "muted" }, new Date(item.occurred_at).toLocaleString()),
        ),
        el("td", {},
          el("div", {}, item.user_id),
          el("div", { class: "muted" }, item.application_id),
        ),
        el("td", {},
          el("span", { class: `badge ${item.risk_level}` }, item.risk_level),
          el("span", { class: `badge ${item.action}` }, item.action),
          el("div", { class: "muted" }, `score ${Number(item.risk_score).toFixed(2)} · policy ${item.policy_version}`),
        ),
        el("td", {},
          reasons.length ? el("ul", { class: "reasons" }, ...reasons) : el("span", { class: "muted" }, "No reasons"),
        ),
      );
    });
    return el("section", { class: "panel" },
      el("h1", {}, "Decisions"),
      el("p", { class: "lede" }, "Every scored login with the PDP action and per-signal reasons. This is the thesis core, browsable."),
      banner(),
      state.decisions.length === 0
        ? el("p", { class: "muted" }, "No scored logins yet. Sign in once (demo or admin) so the PDP persists a decision.")
        : el("table", {},
            el("thead", {}, el("tr", {},
              el("th", {}, "Event"), el("th", {}, "Who"), el("th", {}, "Decision"), el("th", {}, "Reasons"),
            )),
            el("tbody", {}, ...rows),
          ),
    );
  }

  function policyPanel() {
    return el("section", { class: "panel" },
      el("h1", {}, "Policy"),
      el("p", { class: "lede" }, "Score bands and level→action map. Saving hot-reloads the PDP; the next login uses the new thresholds."),
      banner(),
      el("form", {
        onSubmit: async (event) => {
          event.preventDefault();
          try {
            const parsed = JSON.parse(state.policyText);
            const saved = await api("/admin/api/policy", {
              method: "PUT",
              body: JSON.stringify(parsed),
            });
            state.policyText = JSON.stringify(saved, null, 2);
            state.notice = `Policy ${saved.policy_version} is active.`;
            state.error = "";
            render();
          } catch (err) {
            state.error = err.message;
            render();
          }
        },
      },
        el("textarea", {
          id: "policy-json",
        }),
        el("button", { type: "submit", style: "margin-top:0.9rem" }, "Save policy"),
      ),
    );
  }

  function render() {
    if (!state.user) return;
    const tabs = [
      ["decisions", "Decisions"],
      ["policy", "Policy"],
      ["users", "Users"],
      ["apps", "Applications"],
      ["groups", "Groups"],
    ];
    const panel = {
      users: usersPanel,
      apps: appsPanel,
      groups: groupsPanel,
      decisions: decisionsPanel,
      policy: policyPanel,
    }[state.tab]();

    root.replaceChildren(
      el("div", { class: "admin-shell" },
        el("header", { class: "admin-top" },
          el("div", {},
            el("p", { class: "brand-mark" }, "RBA Identity"),
            el("p", { class: "brand-sub" }, "Admin console"),
          ),
          el("div", { class: "who" },
            state.user.email,
            el("button", {
              class: "secondary",
              onClick: async () => {
                await fetch("/logout", { method: "POST", headers: authHeader() });
                sessionStorage.removeItem(SESSION_KEY);
                window.location.assign(`/login?application_id=${ADMIN_APP}&next=/admin`);
              },
            }, "Sign out"),
          ),
        ),
        el("nav", { class: "tabs" },
          ...tabs.map(([id, label]) =>
            el("button", {
              class: state.tab === id ? "active" : "",
              type: "button",
              onClick: () => setTab(id),
            }, label),
          ),
        ),
        panel,
      ),
    );

    if (state.tab === "policy") {
      const area = document.getElementById("policy-json");
      if (area) {
        area.value = state.policyText;
        area.addEventListener("input", () => {
          state.policyText = area.value;
        });
      }
    }
  }

  async function boot() {
    if (!token()) {
      window.location.assign(`/login?application_id=${ADMIN_APP}&next=/admin`);
      return;
    }
    try {
      const session = await api("/session");
      if (!session.user?.is_admin) {
        root.replaceChildren(
          el("div", { class: "admin-shell" },
            el("section", { class: "panel" },
              el("h1", {}, "Admin required"),
              el("p", { class: "lede" }, "This session is not an operator. Sign in as the seeded admin user."),
            ),
          ),
        );
        return;
      }
      state.user = session.user;
      await loadTab();
    } catch (err) {
      if (err.message === "unauthorized") return;
      root.replaceChildren(
        el("div", { class: "admin-shell" },
          el("section", { class: "panel" },
            el("h1", {}, "Admin unavailable"),
            el("p", { class: "lede" }, err.message || "Could not load the console."),
          ),
        ),
      );
    }
  }

  boot();
})();
