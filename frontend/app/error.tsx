"use client";

export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="app-shell loading-shell">
      <h1>We could not load ScamShield AI</h1>
      <p>Refresh the experience or try again in a moment.</p>
      <button className="primary-button" onClick={reset} type="button">
        Retry
      </button>
    </main>
  );
}
