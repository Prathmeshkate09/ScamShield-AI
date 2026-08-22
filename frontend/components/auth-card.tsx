"use client";

import { Turnstile, type TurnstileInstance } from "@marsidev/react-turnstile";
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
import { FormEvent, useEffect, useRef, useState } from "react";

import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  buildCallbackUrl,
  normalizeEmail,
  safeNextPath,
  validateNewPassword
} from "@/lib/auth";
import { createClient } from "@/lib/supabase/client";
import { getSiteUrl, getTurnstileSiteKey, isSupabaseConfigured } from "@/lib/supabase/config";

type AuthMode = "login" | "signup" | "verify" | "forgot" | "reset";

type AuthCardProps = {
  mode: AuthMode;
  recoveryAllowed?: boolean;
};

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
    description: "Create a private ScamShield workspace using any valid email address.",
    submit: "Create secure account"
  },
  verify: {
    eyebrow: "Verify ownership",
    title: "Check your inbox.",
    description: "Enter your signup email to request another verification link.",
    submit: "Resend verification email"
  },
  forgot: {
    eyebrow: "Account recovery",
    title: "Reset your password.",
    description: "If you use email and password, enter your email to request a secure reset link.",
    submit: "Send reset link"
  },
  reset: {
    eyebrow: "Account recovery",
    title: "Choose a new password.",
    description: "Use a strong, unique passphrase to protect your personal scam history.",
    submit: "Update password"
  }
} satisfies Record<AuthMode, { eyebrow: string; title: string; description: string; submit: string }>;

function initialError(code: string | null, recoveryAllowed: boolean): string | null {
  if (code === "oauth_state") {
    return "That Google sign-in request expired or was already used. Start a new sign-in.";
  }
  if (code === "account_unavailable") {
    return "This account cannot sign in. Contact the project owner if you believe this is a mistake.";
  }
  if (code === "configuration") {
    return "Authentication is not configured for this environment.";
  }
  if (code === "invalid_link" || code === "callback") {
    return "That authentication link is invalid or has expired. Request a new link.";
  }
  if (!recoveryAllowed) {
    return "Open the latest password-reset link from your email before choosing a new password.";
  }
  return null;
}

export function AuthCard({ mode, recoveryAllowed = true }: AuthCardProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = safeNextPath(searchParams.get("next"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(
    searchParams.get("message") === "password_reset"
      ? "Your password was changed and existing sessions were revoked. Sign in with your new password."
      : searchParams.get("sent") === "verification"
        ? "Check your inbox for a verification link."
        : null,
  );
  const [error, setError] = useState<string | null>(initialError(searchParams.get("error"), mode !== "reset" || recoveryAllowed));
  const turnstileRef = useRef<TurnstileInstance | undefined>(undefined);
  const isConfigured = isSupabaseConfigured();
  const turnstileSiteKey = getTurnstileSiteKey();
  const currentCopy = copy[mode];
  const needsEmail = mode !== "reset";
  const needsPassword = mode === "login" || mode === "signup" || mode === "reset";
  const requiresCaptcha = Boolean(turnstileSiteKey) && mode !== "reset";
  const canSubmit = isConfigured && !isSubmitting && (mode !== "reset" || recoveryAllowed) && (!requiresCaptcha || Boolean(captchaToken));

  useEffect(() => {
    if (mode === "verify") {
      const pendingEmail = sessionStorage.getItem("scamshield.pendingVerificationEmail");
      if (pendingEmail) {
        setEmail(pendingEmail);
      }
    }
  }, [mode]);

  const callbackUrl = (nextPath: string) => buildCallbackUrl(getSiteUrl(), nextPath);

  const resetCaptcha = () => {
    if (requiresCaptcha) {
      setCaptchaToken(null);
      turnstileRef.current?.reset();
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }

    setError(null);
    setNotice(null);

    if (mode === "signup" || mode === "reset") {
      const passwordError = validateNewPassword(password, confirmPassword);
      if (passwordError) {
        setError(passwordError);
        return;
      }
    }

    const normalizedEmail = normalizeEmail(email);
    setIsSubmitting(true);
    try {
      const supabase = createClient();
      if (mode === "login") {
        const { error: signInError } = await supabase.auth.signInWithPassword({
          email: normalizedEmail,
          password,
          options: { captchaToken: captchaToken ?? undefined }
        });
        if (signInError) {
          setError("Unable to sign in with those details. Verify your email, check your password, and try again.");
          return;
        }
        router.replace(next);
        router.refresh();
        return;
      }

      if (mode === "signup") {
        const { data, error: signUpError } = await supabase.auth.signUp({
          email: normalizedEmail,
          password,
          options: {
            captchaToken: captchaToken ?? undefined,
            emailRedirectTo: callbackUrl("/")
          }
        });
        if (signUpError) {
          setError("We could not submit that signup. Check the details and try again shortly.");
          return;
        }
        if (data.session) {
          router.replace("/");
          router.refresh();
          return;
        }
        sessionStorage.setItem("scamshield.pendingVerificationEmail", normalizedEmail);
        router.replace("/verify-email?sent=verification");
        return;
      }

      if (mode === "verify") {
        const { error: resendError } = await supabase.auth.resend({
          type: "signup",
          email: normalizedEmail,
          options: {
            captchaToken: captchaToken ?? undefined,
            emailRedirectTo: callbackUrl("/")
          }
        });
        if (resendError) {
          setError("We could not send a verification email right now. Wait a moment and try again.");
          return;
        }
        setNotice("If that signup is awaiting verification, a new confirmation link is on its way.");
        return;
      }

      if (mode === "forgot") {
        const { error: recoveryError } = await supabase.auth.resetPasswordForEmail(normalizedEmail, {
          captchaToken: captchaToken ?? undefined,
          redirectTo: callbackUrl("/reset-password")
        });
        if (recoveryError) {
          setError("We could not submit account recovery right now. Wait a moment and try again.");
          return;
        }
        setNotice("If an account exists for that email, a secure password-reset link is on its way.");
        return;
      }

      const { error: updateError } = await supabase.auth.updateUser({ password });
      if (updateError) {
        setError("This recovery session is invalid or expired. Request a new password-reset link.");
        return;
      }

      const { error: signOutError } = await supabase.auth.signOut({ scope: "global" });
      await fetch("/auth/recovery-complete", { method: "POST" });
      if (signOutError) {
        setError("Your password changed, but session revocation did not complete. Sign out on every device and contact the project owner.");
        return;
      }
      router.replace("/login?message=password_reset");
      router.refresh();
    } catch {
      setError("Authentication is temporarily unavailable. Please try again.");
    } finally {
      setIsSubmitting(false);
      resetCaptcha();
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
        setError("Google sign-in is temporarily unavailable. Use email and password or try again shortly.");
      }
    } catch {
      setError("Google sign-in is temporarily unavailable. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const showForm = mode !== "reset" || recoveryAllowed;

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
          <li><CheckCircle2 size={17} /> Verified account ownership</li>
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

        {showForm && (
          <form className="auth-form" onSubmit={(event) => void handleSubmit(event)}>
            {needsEmail && (
              <label>
                <span>Email address</span>
                <span className="auth-input"><Mail size={17} /><input autoCapitalize="none" autoComplete="email" disabled={!isConfigured || isSubmitting} inputMode="email" maxLength={254} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" required spellCheck={false} type="email" value={email} /></span>
              </label>
            )}
            {needsPassword && (
              <label>
                <span>{mode === "reset" ? "New password" : "Password"}</span>
                <span className="auth-input"><LockKeyhole size={17} /><input autoComplete={mode === "reset" || mode === "signup" ? "new-password" : "current-password"} disabled={!isConfigured || isSubmitting} maxLength={MAX_PASSWORD_LENGTH} minLength={mode === "signup" || mode === "reset" ? MIN_PASSWORD_LENGTH : 1} onChange={(event) => setPassword(event.target.value)} placeholder={mode === "reset" || mode === "signup" ? "At least 12 characters" : "Your password"} required type="password" value={password} /></span>
              </label>
            )}
            {(mode === "signup" || mode === "reset") && (
              <label>
                <span>Confirm password</span>
                <span className="auth-input"><LockKeyhole size={17} /><input autoComplete="new-password" disabled={!isConfigured || isSubmitting} maxLength={MAX_PASSWORD_LENGTH} minLength={MIN_PASSWORD_LENGTH} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Repeat your new password" required type="password" value={confirmPassword} /></span>
              </label>
            )}
            {turnstileSiteKey && mode !== "reset" && (
              <div className="auth-captcha" aria-label="Bot protection challenge">
                <Turnstile
                  onError={() => setError("Bot protection could not load. Refresh the page and try again.")}
                  onExpire={() => setCaptchaToken(null)}
                  onSuccess={setCaptchaToken}
                  options={{ action: `auth-${mode}`, size: "flexible", theme: "dark" }}
                  ref={turnstileRef}
                  siteKey={turnstileSiteKey}
                />
              </div>
            )}
            <button className="primary-button auth-submit" disabled={!canSubmit} type="submit">
              {isSubmitting ? <LoaderCircle className="spin" size={18} /> : <ArrowRight size={18} />}
              {isSubmitting ? "Securing your request..." : currentCopy.submit}
            </button>
          </form>
        )}

        {(mode === "login" || mode === "signup") && (
          <>
            <div className="auth-divider"><span>or continue with</span></div>
            <button className="google-button" disabled={!isConfigured || isSubmitting} onClick={() => void handleGoogleSignIn()} type="button">
              <span className="google-mark">G</span> Google
            </button>
          </>
        )}

        <div className="auth-links">
          {mode === "login" && <><Link href="/forgot-password">Forgot email password?</Link><span>New to ScamShield? <Link href="/signup">Create an account</Link></span><Link href="/verify-email">Resend verification</Link></>}
          {mode === "signup" && <span>Already protected? <Link href="/login">Sign in</Link></span>}
          {mode === "verify" && <span>Already verified? <Link href="/login">Sign in</Link></span>}
          {mode === "forgot" && <span>Remembered it? <Link href="/login">Back to sign in</Link></span>}
          {mode === "reset" && <span>Need a new link? <Link href="/forgot-password">Request password reset</Link></span>}
        </div>
      </section>
    </main>
  );
}
