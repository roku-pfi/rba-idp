/* What every page needs from the shell: who is signed in, what they may do,
   which tenant the console is scoped to, and a way to say something. */

import { ToastNotification } from "@carbon/react";
import { createContext, ReactNode, useCallback, useContext, useRef, useState } from "react";
import type { SessionUser, Tenant } from "./api";

type Toast = { id: number; kind: "ok" | "error"; text: string };

export type Console = {
  user: SessionUser;
  tenant: Tenant | null;
  /** The tenant id every admin call is scoped to; pages reload when it changes. */
  scope: string;
  /** ADR-0029: the console is gated by permissions, not by the is_admin flag. */
  can: (permission: string) => boolean;
  permissions: string[];
  expiresAt: string | null;
  ok: (text: string) => void;
  fail: (err: unknown) => void;
};

const ConsoleContext = createContext<Console | null>(null);

export function useConsole(): Console {
  const value = useContext(ConsoleContext);
  if (!value) throw new Error("useConsole outside the console shell");
  return value;
}

export function ConsoleProvider({
  value,
  children,
}: {
  value: Omit<Console, "ok" | "fail">;
  children: ReactNode;
}) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(0);

  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = ++next.current;
    setToasts((list) => [...list, { id, kind, text }]);
    // Errors stay until dismissed: an operator should not miss why a save failed.
    if (kind === "ok") setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), 6000);
  }, []);
  const ok = useCallback((text: string) => push("ok", text), [push]);
  const fail = useCallback(
    (err: unknown) => {
      const text = err instanceof Error ? err.message : String(err);
      if (text !== "unauthorized") push("error", text);
    },
    [push],
  );

  return (
    <ConsoleContext.Provider value={{ ...value, ok, fail }}>
      {children}
      <div className="rk-toasts" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <ToastNotification
            key={toast.id}
            kind={toast.kind === "ok" ? "success" : "error"}
            title={toast.kind === "ok" ? "Listo" : "No se pudo completar"}
            subtitle={toast.text}
            lowContrast
            ariaLabel="Cerrar aviso"
            statusIconDescription={toast.kind === "ok" ? "Éxito" : "Error"}
            onClose={() => {
              setToasts((list) => list.filter((t) => t.id !== toast.id));
              return false;
            }}
          />
        ))}
      </div>
    </ConsoleContext.Provider>
  );
}
