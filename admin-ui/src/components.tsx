/* Small pieces several pages draw the same way. */

// A person and a group keep their colour across pages and sessions.
const AVATAR_COLORS = ["#1466e5", "#007d79", "#8a3ffc", "#d02670", "#198038", "#0072c3"];
export const TAG_TYPES = ["blue", "teal", "purple", "magenta", "green", "cyan"] as const;
export const hash = (text: string) => [...text].reduce((sum, ch) => (sum * 31 + ch.charCodeAt(0)) >>> 0, 7);

export function Avatar({ email }: { email: string }) {
  return (
    <span className="rk-avatar" style={{ background: AVATAR_COLORS[hash(email) % AVATAR_COLORS.length] }} aria-hidden="true">
      {email[0].toUpperCase()}
    </span>
  );
}

/** What it is, then the detail that tells it apart. */
export function TwoLines({ primary, secondary, mono }: { primary: React.ReactNode; secondary?: React.ReactNode; mono?: boolean }) {
  return (
    <span className="rk-cell-text">
      <span className={`rk-primary${mono ? " rk-mono" : ""}`}>{primary}</span>
      {secondary ? <span className="rk-secondary">{secondary}</span> : null}
    </span>
  );
}
