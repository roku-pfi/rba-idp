/* What a person reads is Spanish (es-AR); what the API sends stays English
   (ADR-0036). This file is the one place the two meet: enum and reason-code
   labels, and date and number formatting. The raw code stays on hover. */

import type { Reason } from "./api";

const LOCALE = "es-AR";

const dateTime = new Intl.DateTimeFormat(LOCALE, { dateStyle: "short", timeStyle: "medium" });
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
  failed_logins_last_24h: "Intentos fallidos (24 h)",
  user_login_count: "Historial del usuario",
  system: "Sistema",
};

/** What the engine concluded about it. Keys are the PDP's reason `code`s. */
const CODE_LABEL: Record<string, string> = {
  signal_novel: "nuevo para este usuario",
  signal_familiar: "habitual para este usuario",
  signal_neutral: "sin peso en la decisión",
  failed_login_burst: "ráfaga de contraseñas incorrectas",
  failed_login_lockout: "intentos fallidos sostenidos: cuenta bloqueada",
  supervised_second_opinion: "el modelo supervisado lo marcó como ataque",
  low_history: "pocos inicios previos, el perfil todavía aprende",
  vpn_or_hosting: "VPN o red de hosting; no se evalúa el viaje",
  impossible_travel: "viaje imposible desde el último inicio",
  pdp_unavailable: "el motor de riesgo no respondió",
  fallback: "decisión de respaldo",
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
  const text = perSignal ? `${signalLabel(reason.signal)}: ${what}` : what[0].toUpperCase() + what.slice(1);
  return { text, title };
}
