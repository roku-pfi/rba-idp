/* Small pieces several pages draw the same way. */

import { DefinitionTooltip, Tooltip } from "@carbon/react";
import { Information } from "@carbon/icons-react";

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

/** A term with its meaning on hover and focus (dotted underline). */
export function Hint({ text, children }: { text: React.ReactNode; children: React.ReactNode }) {
  return (
    <DefinitionTooltip definition={text} openOnHover align="bottom-left">
      {children}
    </DefinitionTooltip>
  );
}

/** Page title, an ⓘ that says what the page is for on hover, and its actions. */
export function PageHead({
  title,
  info,
  sub,
  lead,
  children,
}: {
  title: React.ReactNode;
  info?: React.ReactNode;
  sub?: React.ReactNode;
  lead?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="rk-page-head">
      <div className="rk-cell">
        {lead}
        <div>
          <h1 className="rk-title">
            {title}
            {info && (
              <Tooltip label={info} align="bottom-left" className="rk-info-tip">
                <button type="button" className="rk-info" aria-label="Qué es esta página">
                  <Information size={16} />
                </button>
              </Tooltip>
            )}
          </h1>
          {sub ? <p>{sub}</p> : null}
        </div>
      </div>
      {children}
    </div>
  );
}
