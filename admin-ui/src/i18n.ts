/* What a person reads is Spanish (es-AR); what the API sends stays English
   (ADR-0036). This file is the one place the two meet: enum and reason-code
   labels, and date and number formatting. The raw code stays on hover. */

import type { Reason } from "./api";

const LOCALE = "es-AR";

const dateTime = new Intl.DateTimeFormat(LOCALE, { dateStyle: "short", timeStyle: "short" });
const time = new Intl.DateTimeFormat(LOCALE, { timeStyle: "short" });
const decimal = new Intl.NumberFormat(LOCALE, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const integer = new Intl.NumberFormat(LOCALE);

const relative = new Intl.RelativeTimeFormat(LOCALE, { numeric: "auto" });
const STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["second", 60],
  ["minute", 60],
  ["hour", 24],
  ["day", 30],
  ["month", 12],
  ["year", Infinity],
];

/** "hace 5 minutos", "ayer", "hace 3 meses". */
function ago(iso: string): string {
  let value = (new Date(iso).getTime() - Date.now()) / 1000;
  for (const [unit, size] of STEPS) {
    if (Math.abs(value) < size) return relative.format(Math.round(value), unit);
    value /= size;
  }
  return relative.format(Math.round(value), "year");
}

export const fmt = {
  ago,
  dateTime: (iso: string) => dateTime.format(new Date(iso)),
  time: (iso: string) => time.format(new Date(iso)),
  score: (value: number) => decimal.format(value),
  count: (value: number) => integer.format(value),
};

export const ACTION_LABEL: Record<string, string> = {
  ALLOW: "Permitir",
  REQUIRE_MFA: "Pedir passkey",
  REAUTHENTICATE: "Reautenticar",
  BLOCK: "Bloquear",
};

/** What happened to the login, as an operator reads it in a list. */
export const OUTCOME_LABEL: Record<string, string> = {
  ALLOW: "Permitido",
  REQUIRE_MFA: "Pidió passkey",
  REAUTHENTICATE: "Reautenticación",
  BLOCK: "Bloqueado",
};

const regions = new Intl.DisplayNames([LOCALE], { type: "region" });
/** "JP" → "Japón"; unknown or missing codes come back as given. */
export function countryName(code?: string | null): string {
  if (!code) return "País desconocido";
  try {
    return regions.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

export const DEVICE_LABEL: Record<string, string> = {
  desktop: "Computadora",
  mobile: "Celular",
  tablet: "Tablet",
};

export const LEVEL_LABEL: Record<string, string> = {
  LOW: "Bajo",
  MEDIUM: "Medio",
  HIGH: "Alto",
  CRITICAL: "Crítico",
};

export const MODE_LABEL: Record<string, string> = {
  OFF: "Apagado",
  MONITOR: "Monitoreo",
  ACTIVE: "Activo",
};

/** What a login signal is, in words. Keys are the PDP's `signal` names. */
const SIGNAL_LABEL: Record<string, string> = {
  ip_address: "Dirección IP",
  asn: "Red (ASN)",
  country: "País",
  device_type: "Tipo de dispositivo",
  os: "Sistema operativo",
  browser: "Navegador",
  hour: "Hora del día",
  // freeman-0.4.0 (ADR-0043): one signal per hierarchy.
  network: "Red y ubicación",
  agent: "Dispositivo y navegador",
  failed_logins_last_24h: "Intentos fallidos (24 h)",
  user_login_count: "Historial del usuario",
  system: "Sistema",
};

/** What the engine concluded about it. Keys are the PDP's reason `code`s. */
const CODE_LABEL: Record<string, string> = {
  signal_novel: "nuevo para este usuario",
  signal_familiar: "habitual para este usuario",
  signal_neutral: "sin peso en la decisión",
  failed_login_burst: "contraseñas incorrectas desde lugares desconocidos",
  failed_login_lockout: "intentos fallidos sostenidos: cuenta bloqueada",
  source_blocked: "IP bloqueada por intentos fallidos",
  account_cooldown: "cuenta en pausa por contraseñas incorrectas propias",
  supervised_second_opinion: "el modelo supervisado lo marcó como ataque",
  low_history: "pocos inicios previos, el perfil todavía aprende",
  vpn_or_hosting: "VPN o red de hosting; no se evalúa el viaje",
  impossible_travel: "viaje imposible desde el último inicio",
  pdp_unavailable: "el motor de riesgo no respondió",
  fallback: "decisión de respaldo",
};

/** freeman-0.4.0's detail: how far the user's history reaches into the login. */
const DEPTH_LABEL: Record<string, string> = {
  "new country": "país nuevo",
  "new network in a familiar country": "red nueva en un país habitual",
  "new IP address in a familiar network": "IP nueva en una red habitual",
  "familiar IP address": "IP habitual",
  "new device type": "tipo de dispositivo nuevo",
  "new operating system on a familiar device type": "sistema nuevo en un dispositivo habitual",
  "new browser on a familiar device and system": "navegador nuevo en un dispositivo habitual",
  "familiar device, system and browser": "dispositivo, sistema y navegador habituales",
  "no history yet": "sin historial todavía",
};

export const label = (table: Record<string, string>, key: string) => table[key] ?? key;

export function signalLabel(signal: string): string {
  return label(SIGNAL_LABEL, signal);
}

/** One reason as a sentence, plus the raw identifiers for the tooltip. */
export function reasonText(reason: Reason): { text: string; title: string } {
  const what = CODE_LABEL[reason.code];
  const title = `${reason.code} · ${reason.signal}${reason.detail ? ` — ${reason.detail}` : ""}`;
  if (!what) return { text: reason.detail || reason.code, title };
  // The model's per-signal reasons read "País: nuevo para este usuario"; rule
  // reasons already say what they are about.
  const perSignal = reason.code.startsWith("signal_");
  const depth = reason.detail ? DEPTH_LABEL[reason.detail] : undefined;
  const text = perSignal
    ? `${signalLabel(reason.signal)}: ${depth ?? what}`
    : what[0].toUpperCase() + what.slice(1);
  return { text, title };
}

const n = (text: string) => integer.format(Number(text));

/** The engine writes rule details in English (they are also log lines); the
 *  console says them in Spanish. Unknown shapes are left out (raw on hover). */
export function reasonDetail(code: string, detail?: string | null): string | null {
  if (!detail) return null;
  let m: RegExpMatchArray | null;
  if (code === "impossible_travel" && (m = detail.match(/from (\S+) to (\S+) \((\d+) km at ~(\d+) km\/h; threshold (\d+)/))) {
    return `De ${countryName(m[1])} a ${countryName(m[2])}: ${n(m[3])} km a unos ${n(m[4])} km/h (el máximo creíble es ${n(m[5])} km/h).`;
  }
  if (code === "impossible_travel" && (m = detail.match(/from (\S+) to (\S+)/))) {
    return `De ${countryName(m[1])} a ${countryName(m[2])}, más rápido de lo posible.`;
  }
  if (code === "vpn_or_hosting" && (m = detail.match(/ASN (\S+)/))) {
    return `La red AS${m[1].replace(/^AS/, "")} es de VPN o hosting; por eso no se evalúa el viaje.`;
  }
  if (code === "source_blocked" && (m = detail.match(/passed (\d+) failed logins in (\d+) min; blocked for (\d+) min/))) {
    return `Esta IP superó ${n(m[1])} intentos fallidos en ${n(m[2])} min: queda bloqueada ${n(m[3])} min, aun con la contraseña correcta.`;
  }
  if (code === "account_cooldown" && (m = detail.match(/^(\d+) wrong passwords.*paused for (\d+) min/))) {
    return `${n(m[1])} contraseñas incorrectas desde una red habitual del usuario: la cuenta queda en pausa ${n(m[2])} min.`;
  }
  if (code === "failed_login_burst" && (m = detail.match(/^(\d+) failed.*unfamiliar contexts \(threshold (\d+)/))) {
    return `${n(m[1])} contraseñas incorrectas en 24 h desde lugares que el usuario no usa (el umbral es ${n(m[2])}).`;
  }
  if ((code === "failed_login_burst" || code === "failed_login_lockout") && (m = detail.match(/^(\d+) failed.*threshold (\d+)/))) {
    return `${n(m[1])} contraseñas incorrectas en 24 h (el umbral es ${n(m[2])}).`;
  }
  if (code === "low_history" && (m = detail.match(/only (\d+) prior/))) {
    return `Solo ${n(m[1])} inicios previos: el perfil todavía tiene poco para comparar.`;
  }
  if (code === "pdp_unavailable") return "El motor no respondió; se aplicó la decisión de respaldo.";
  return null;
}
