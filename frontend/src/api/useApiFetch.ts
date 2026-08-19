import { useEffect, useState } from "react";
import { ApiError } from "./client";

export type FetchState<T> =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "success"; data: T };

/**
 * Runs `fetcher` once on mount (and whenever `deps` changes), tracking
 * loading/error/success state explicitly rather than leaving callers to
 * juggle `data`, `loading`, and `error` as three separately-nullable
 * variables that can drift out of sync with each other.
 */
export function useApiFetch<T>(fetcher: () => Promise<T>, deps: unknown[] = []): FetchState<T> {
  const [state, setState] = useState<FetchState<T>>({ status: "loading" });

  // oxlint-disable-next-line react-hooks/exhaustive-deps -- deps is intentionally caller-provided, not a static array this rule can verify
  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });

    fetcher()
      .then((data) => {
        if (!cancelled) setState({ status: "success", data });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const isApiError = err instanceof ApiError || (err && typeof err === "object" && "name" in err && err.name === "ApiError");
        const message = isApiError ? (err as ApiError).message : "Something went wrong loading this data.";
        setState({ status: "error", error: message });
      });

    return () => {
      cancelled = true;
    };
    // oxlint-disable-next-line react-hooks/exhaustive-deps -- deps is intentionally caller-provided, not a static array this rule can verify
  }, deps);

  return state;
}
