export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function validateNewPassword(password: string, confirmation: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Use at least ${MIN_PASSWORD_LENGTH} characters for your password.`;
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return `Use no more than ${MAX_PASSWORD_LENGTH} characters for your password.`;
  }
  if (password !== confirmation) {
    return "The passwords do not match.";
  }
  return null;
}

export function safeNextPath(value: string | null): string {
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/";
}

export function buildCallbackUrl(siteUrl: string, next: string): string {
  const url = new URL("/auth/callback", siteUrl);
  url.searchParams.set("next", safeNextPath(next));
  return url.toString();
}
