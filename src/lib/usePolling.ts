// Minimal polling hook — the plugin has no react-query, and backend scan
// state (pending→running→completed) changes over seconds, so the Overview
// re-fetches on an interval. `refetch` lets callers refresh immediately after
// a launch/delete so the UI updates without waiting for the next tick.
import { useCallback, useEffect, useRef, useState } from 'react';

export function usePolling<T>(
  fn: () => Promise<T>,
  intervalMs: number
): { data: T | null; error: unknown; loading: boolean; refetch: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const load = useCallback(async () => {
    try {
      const d = await fnRef.current();
      setData(d);
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let alive = true;
    const tick = () => {
      if (alive) load();
    };
    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [load, intervalMs]);

  return { data, error, loading, refetch: load };
}
