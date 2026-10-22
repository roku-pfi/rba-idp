import { useCallback, useEffect, useState } from "react";
import { useConsole } from "../console";

/** Fetch on mount and whenever the console's tenant changes; `reload` after a write. */
export function useLoad<T>(fetcher: () => Promise<T>, initial: T): [T, () => Promise<void>, boolean] {
  const { scope, fail } = useConsole();
  const [data, setData] = useState<T>(initial);
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(() => fetcher().then(setData).catch(fail), [scope]);
  useEffect(() => {
    setLoading(true);
    reload().finally(() => setLoading(false));
  }, [reload]);
  return [data, reload, loading];
}
