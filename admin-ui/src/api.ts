const SESSION_KEY = "rba.idp.session";
// ADR-0033: the tenant a platform operator switched to. Sent on every admin
// call; the server ignores nothing — a tenant operator naming another tenant
// gets 403, so this is a preference, never an authorization.
const TENANT_KEY = "rba.console.tenant";
const TENANT_HEADER = "X-RokuSec-Tenant";


export type SessionUser = {
  tenant_id: string;
  user_id: string;
  email: string;
  is_admin?: boolean;
};

export type Tenant = {
  tenant_id: string;
  name: string;
  operator_domains: string[];
  is_platform: boolean;
  branding: { display_name: string; login_style: string };
};

export type AdminUser = {
  user_id: string;
  email: string;
  enabled: boolean;
  is_admin: boolean;
  created_at: string;
  groups: { group_id: string; name: string }[];
  /** 0 means a step-up cannot succeed (ADR-0037). */
  passkeys: number;
  last_login_at: string | null;
};

export type Application = {
  application_id: string;
  name: string;
  enabled: boolean;
  created_at: string;
};

export type Group = {
  group_id: string;
  name: string;
  description: string;
  member_count: number;
  created_at: string;
};

export type GroupDetail = Group & {
  members: { user_id: string; email: string }[];
  roles: { role_id: string; application_id: string; name: string }[];
};

/** ADR-0029: user -> group -> role -> permission, every role scoped to one app. */
export type Permission = {
  permission_id: string;
  application_id: string;
  resource: string;
  operation: string;
  description: string;
  scope: string;
};

export type Role = {
  role_id: string;
  application_id: string;
  name: string;
  description: string;
  permission_count: number;
  created_at: string;
};

export type RoleDetail = Role & {
  permissions: Permission[];
};

export type Reason = {
  code: string;
  signal: string;
  contribution?: number | null;
  detail?: string | null;
};

export type Decision = {
  event_id: string;
  occurred_at: string;
  application_id: string;
  user_id: string;
  risk_score: number;
  risk_level: string;
  /** The engine's verdict. */
  action: string;
  /** What was applied (ADR-0034); differs from `action` while monitoring. */
  enforced_action: string;
  engine_mode: "OFF" | "MONITOR" | "ACTIVE";
  simulated?: boolean;
  reasons: Reason[];
  policy_version: string;
  fallback: boolean;
};

function token(): string | null {
  return sessionStorage.getItem(SESSION_KEY);
}

function authHeader(): Record<string, string> {
  const value = token();
  return value ? { Authorization: `Bearer ${value}` } : {};
}

export function actingTenant(): string | null {
  return sessionStorage.getItem(TENANT_KEY);
}

export function switchTenant(tenantId: string | null): void {
  if (tenantId) sessionStorage.setItem(TENANT_KEY, tenantId);
  else sessionStorage.removeItem(TENANT_KEY);
}

function tenantHeader(): Record<string, string> {
  const value = actingTenant();
  return value ? { [TENANT_HEADER]: value } : {};
}

function detailOf(body: unknown): string {
  if (!body || typeof body !== "object") return "Request failed.";
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  return "Request failed.";
}

export function redirectToLogin(): void {
  // Email + password only; the server finds the tenant from the domain.
  window.location.assign("/console/login?next=/admin");
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const resp = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...authHeader(),
      ...(path.startsWith("/admin/api/") ? tenantHeader() : {}),
      ...(options.headers || {}),
    },
  });
  const text = await resp.text();
  let body: unknown = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }
  if (resp.status === 401) {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(TENANT_KEY);
    redirectToLogin();
    throw new Error("unauthorized");
  }
  if (!resp.ok) throw new Error(detailOf(body));
  return body as T;
}

export function currentToken(): string | null {
  return token();
}

export async function logout(): Promise<void> {
  await fetch("/logout", { method: "POST", headers: authHeader() });
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(TENANT_KEY);
  redirectToLogin();
}
