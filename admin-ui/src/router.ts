/* Pages are real URLs under /admin/ (the IdP serves the SPA for every path
   there), so a page can be bookmarked, reloaded and opened in a new tab. Slugs
   are Spanish: the address bar is something a person reads. */

import { useEffect, useState } from "react";

export type Page = "home" | "events" | "effectiveness" | "policy" | "users" | "apps" | "groups" | "roles" | "orgs" | "account";

/** The side navigation's sections, grouped by what the operator is doing. */
export type Section = "activity" | "directory" | "access" | "platform";

export const SECTIONS: { id: Section; label: string }[] = [
  { id: "activity", label: "Actividad" },
  { id: "directory", label: "Directorio" },
  { id: "access", label: "Acceso" },
  // Shown only to the platform operator (ADR-0033).
  { id: "platform", label: "Plataforma" },
];

// `section: null` pages are reached from elsewhere (the account menu), not the nav.
export const PAGES: { id: Page; slug: string; label: string; section: Section | null }[] = [
  { id: "home", slug: "resumen", label: "Resumen", section: "activity" },
  { id: "events", slug: "eventos", label: "Eventos", section: "activity" },
  { id: "effectiveness", slug: "efectividad", label: "Efectividad", section: "activity" },
  { id: "users", slug: "usuarios", label: "Usuarios", section: "directory" },
  { id: "groups", slug: "grupos", label: "Grupos", section: "directory" },
  { id: "roles", slug: "roles", label: "Roles", section: "directory" },
  { id: "apps", slug: "aplicaciones", label: "Aplicaciones", section: "access" },
  { id: "policy", slug: "politica", label: "Política", section: "access" },
  { id: "orgs", slug: "organizaciones", label: "Organizaciones", section: "platform" },
  { id: "account", slug: "cuenta", label: "Mi cuenta", section: null },
];

const BASE = "/admin/";
const HOME: Page = "home";

type Route = { page: Page; id: string | null };

/** /admin/<slug>[/<id>]: a page, and optionally one item on it. */
function routeFromPath(pathname: string): Route {
  const [slug = "", id = ""] = pathname.startsWith(BASE) ? pathname.slice(BASE.length).split("/") : [];
  const page = PAGES.find((item) => item.slug === slug)?.id;
  return page ? { page, id: id ? decodeURIComponent(id) : null } : { page: HOME, id: null };
}

export function hrefOf(page: Page, id?: string): string {
  const base = BASE + PAGES.find((item) => item.id === page)!.slug;
  return id ? `${base}/${encodeURIComponent(id)}` : base;
}

export function navigate(page: Page, id?: string): void {
  const href = hrefOf(page, id);
  if (window.location.pathname !== href) window.history.pushState(null, "", href);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => routeFromPath(window.location.pathname));
  useEffect(() => {
    // An unknown or bare /admin path settles on the home page's URL.
    const current = routeFromPath(window.location.pathname);
    const canonical = hrefOf(current.page, current.id ?? undefined);
    if (window.location.pathname !== canonical) window.history.replaceState(null, "", canonical);
    const sync = () => setRoute(routeFromPath(window.location.pathname));
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);
  return route;
}
