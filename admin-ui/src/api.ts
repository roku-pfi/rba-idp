const SESSION_KEY = "rba.idp.session";
const ADMIN_APP = "idp-admin-console";

export type Tab = "decisions" | "policy" | "users" | "apps" | "groups";

export type SessionUser = {
  user_id: string;
  email: string;
  is_admin?: boolean;
};

export type AdminUser = {
  user_id: string;
  email: string;
  enabled: boolean;
  is_admin: boolean;
  created_at: string;
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
  grants: { application_id: string; permission: string }[];
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
  action: string;
  reasons: Reason[];
  policy_version: string;
  fallback: boolean;
};

function token(): string | null {
  return sessionStorage.getItem(SESSION_KEY);
}

function authHeader(): HeadersInit {
  const value = token();
  return value ? { Authorization: `Bearer ${value}` } : {};
}

function detailOf(body: unknown): string {
  if (!body || typeof body !== "object") return "Request failed.";
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  return "Request failed.";
}

export function redirectToLogin(): void {
  window.location.assign(`/login?application_id=${ADMIN_APP}&next=/admin`);
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const resp = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...authHeader(),
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
  redirectToLogin();
}
