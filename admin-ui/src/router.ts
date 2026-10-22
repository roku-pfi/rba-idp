/* Pages are real URLs under /admin/ (the IdP serves the SPA for every path
   there), so a page can be bookmarked, reloaded and opened in a new tab. Slugs
   are Spanish: the address bar is something a person reads. */

import { useEffect, useState } from "react";

export type Page = "decisions" | "policy" | "users" | "apps" | "groups" | "roles";

export const PAGES: { id: Page; slug: string; label: string }[] = [
  { id: "decisions", slug: "decisiones", label: "Decisiones" },
  { id: "policy", slug: "politica", label: "Política" },
  { id: "users", slug: "usuarios", label: "Usuarios" },
  { id: "groups", slug: "grupos", label: "Grupos" },
  { id: "roles", slug: "roles", label: "Roles" },
  { id: "apps", slug: "aplicaciones", label: "Aplicaciones" },
];

const BASE = "/admin/";
const HOME: Page = "decisions";

function pageFromPath(pathname: string): Page {
  const slug = pathname.startsWith(BASE) ? pathname.slice(BASE.length).split("/")[0] : "";
  return PAGES.find((page) => page.slug === slug)?.id ?? HOME;
}

export function hrefOf(page: Page): string {
  return BASE + PAGES.find((item) => item.id === page)!.slug;
}

export function navigate(page: Page): void {
  const href = hrefOf(page);
  if (window.location.pathname !== href) window.history.pushState(null, "", href);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function usePage(): Page {
  const [page, setPage] = useState<Page>(() => pageFromPath(window.location.pathname));
  useEffect(() => {
    // An unknown or bare /admin path settles on the home page's URL.
    const canonical = hrefOf(pageFromPath(window.location.pathname));
    if (window.location.pathname !== canonical) window.history.replaceState(null, "", canonical);
    const sync = () => setPage(pageFromPath(window.location.pathname));
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);
  return page;
}
