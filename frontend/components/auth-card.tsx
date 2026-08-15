"use client";

import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Mail,
  ShieldCheck
} from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, useState } from "react";

import { createClient } from "@/lib/supabase/client";
import { getSiteUrl, isSupabaseConfigured } from "@/lib/supabase/config";

type AuthMode = "login" | "signup" | "forgot" | "reset";

type AuthCardProps = {
  mode: AuthMode;
};

function safeNextPath(value: string | null): string {
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/";
}

function callbackUrl(next: string): string {
  const url = new URL("/auth/callback", getSiteUrl());
  url.searchParams.set("next", next);
  return url.toString();
}

const copy = {
  login: {
    eyebrow: "Protected workspace",
    title: "Welcome back.",
    description: "Sign in to keep every scam scan, result, and risk trend private to your account.",
    submit: "Sign in securely"
  },
  signup: {
    eyebrow: "Private protection",
    title: "Create your shield.",
    description: "Use your email to create a private ScamShield workspace with isolated scan history.",
    submit: "Create secure account"
  },
  forgot: {
    eyebrow: "Account recovery",
    title: "Reset your password.",
    description: "Enter your email and we will send a secure reset link if an account exists.",
    submit: "Send reset link"
  },
  reset: {
    eyebrow: "Account recovery",
    title: "Choose a new password.",
    description: "Use a strong, unique password to protect your personal scam history.",
    submit: "Update password"
  }
} satisfies Record<AuthMode, { eyebrow: string; title: string; description: string; submit: string }>;

export function AuthCard({ mode }: AuthCardProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = safeNextPath(searchParams.get("next"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const authError = searchParams.get("error");
  const [error, setError] = useState<string | null>(
    authError === "callback"
      ? "That sign-in link is invalid or has expired. Please try again."
      : authError === "oauth_state"
        ? "That Google sign-in request expired or was already used. Start a new sign-in."
        : null,
  );
  const isConfigured = isSupabaseConfigured();
  const currentCopy = copy[mode];
  const needsEmail = mode !== "reset";
  const needsPassword = mode === "login" || mode === "signup" || mode === "reset";

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!isConfigured || isSubmitting) {
      return;
    }

    setError(null);
    setNotice(null);

    if ((mode === "signup" || mode === "reset") && password.length < 12) {
      setError("Use at least 12 characters for your password.");
      return;
    }
    if ((mode === "signup" || mode === "reset") && password !== confirmPassword) {
      setError("The passwords do not match.");
      return;
    }

    setIsSubmitting(true);
    try {
      const supabase = createClient();
      if (mode === "login") {
        const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
        if (signInError) {
          setError("Unable to sign in with those details. Check your email and password, then try again.");
          return;
        }
        router.replace(next);
        router.refresh();
        return;
      }

      if (mode === "signup") {
        const { data, error: signUpError } = await supabase.auth.signUp({
          email,
          password,
          options: { emailRedirectTo: callbackUrl("/") }
        });
        if (signUpError) {
          setError("We could not create your account. Try a different email or try again shortly.");
          return;
        }
        if (data.session) {
          router.replace("/");
          router.refresh();
          return;
        }
        setNotice("Check your inbox to confirm your email address, then return here to sign in.");
        return;
      }

      if (mode === "forgot") {
        await supabase.auth.resetPasswordForEmail(email, { redirectTo: callbackUrl("/reset-password") });
        setNotice("If an account exists for that email, a secure password-reset link is on its way.");
        return;
      }

      const { error: updateError } = await supabase.auth.updateUser({ password });
      if (updateError) {
        setError("This recovery link is invalid or expired. Request a new password-reset link.");
        return;
      }
      setNotice("Password updated. You can now continue to your protected dashboard.");
      router.replace("/");
      router.refresh();
    } catch {
      setError("Authentication is temporarily unavailable. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleGoogleSignIn = async () => {
    if (!isConfigured || isSubmitting) {
      return;
    }
    setError(null);
    setIsSubmitting(true);
    try {
      const { error: oauthError } = await createClient().auth.signInWithOAuth({
        provider: "google",
        options: { redirectTo: callbackUrl(next) }
      });
      if (oauthError) {
        setError("Google sign-in is not available yet. Use email and password or finish the provider setup.");
      }
    } catch {
      setError("Google sign-in is temporarily unavailable. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="auth-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <section className="auth-intro">
        <Link className="brand" href="/">
          <span className="brand-mark"><ShieldCheck size={24} /></span>
          <span>ScamShield <strong>AI</strong></span>
        </Link>
        <div className="auth-intro-copy">
          <p className="eyebrow"><LockKeyhole size={15} /> Security starts with identity</p>
          <h1>Detect the scam before you take the bait.</h1>
          <p>Your scans are authenticated, isolated, and protected by shared rate limits designed for a safer service.</p>
        </div>
        <ul className="auth-assurances">
          <li><CheckCircle2 size={17} /> Private, account-scoped history</li>
          <li><CheckCircle2 size={17} /> Secure Supabase authentication</li>
          <li><CheckCircle2 size={17} /> Protected AI-analysis API</li>
        </ul>
      </section>

      <section className="auth-card" aria-labelledby="auth-title">
        <div className="auth-card-icon">{mode === "forgot" || mode === "reset" ? <KeyRound size={24} /> : <ShieldCheck size={24} />}</div>
        <p className="eyebrow">{currentCopy.eyebrow}</p>
        <h2 id="auth-title">{currentCopy.title}</h2>
        <p className="auth-description">{currentCopy.description}</p>

        {!isConfigured && (
          <p className="auth-message error-message"><AlertTriangle size={16} /> Authentication is not configured. Add the public Supabase URL and publishable key.</p>
        )}
        {error && <p className="auth-message error-message"><AlertTriangle size={16} /> {error}</p>}
        {notice && <p className="auth-message success-message"><CheckCircle2 size={16} /> {notice}</p>}

        <form className="auth-form" onSubmit={(event) => void handleSubmit(event)}>
          {needsEmail && (
            <label>
              <span>Email address</span>
              <span className="auth-input"><Mail size={17} /><input autoComplete="email" disabled={!isConfigured || isSubmitting} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" required type="email" value={email} /></span>
            </label>
          )}
          {needsPassword && (
            <label>
              <span>{mode === "reset" ? "New password" : "Password"}</span>
              <span className="auth-input"><LockKeyhole size={17} /><input autoComplete={mode === "reset" ? "new-password" : mode === "signup" ? "new-password" : "current-password"} disabled={!isConfigured || isSubmitting} minLength={mode === "signup" || mode === "reset" ? 12 : 1} onChange={(event) => setPassword(event.target.value)} placeholder={mode === "reset" || mode === "signup" ? "At least 12 characters" : "Your password"} required type="password" value={password} /></span>
            </label>
          )}
          {(mode === "signup" || mode === "reset") && (
            <label>
              <span>Confirm password</span>
              <span className="auth-input"><LockKeyhole size={17} /><input autoComplete="new-password" disabled={!isConfigured || isSubmitting} minLength={12} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Repeat your new password" required type="password" value={confirmPassword} /></span>
            </label>
          )}
          <button className="primary-button auth-submit" disabled={!isConfigured || isSubmitting} type="submit">
            {isSubmitting ? <LoaderCircle className="spin" size={18} /> : <ArrowRight size={18} />}
            {isSubmitting ? "Securing your session..." : currentCopy.submit}
          </button>
        </form>

        {(mode === "login" || mode === "signup") && (
          <>
            <div className="auth-divider"><span>or continue with</span></div>
            <button className="google-button" disabled={!isConfigured || isSubmitting} onClick={() => void handleGoogleSignIn()} type="button">
              <span className="google-mark">G</span> Google
            </button>
          </>
        )}

        <div className="auth-links">
          {mode === "login" && <><Link href="/forgot-password">Forgot password?</Link><span>New to ScamShield? <Link href="/signup">Create an account</Link></span></>}
          {mode === "signup" && <span>Already protected? <Link href="/login">Sign in</Link></span>}
          {mode === "forgot" && <span>Remembered it? <Link href="/login">Back to sign in</Link></span>}
          {mode === "reset" && <span>Need a new link? <Link href="/forgot-password">Request password reset</Link></span>}
        </div>
      </section>
    </main>
  );
}
