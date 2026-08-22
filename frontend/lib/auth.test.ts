import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  buildCallbackUrl,
  normalizeEmail,
  safeNextPath,
  validateNewPassword
} from "./auth";
import { getAuthCookieOptions } from "./supabase/config";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("authentication helpers", () => {
  it("normalizes email input consistently", () => {
    expect(normalizeEmail("  User.Name@Example.COM ")).toBe("user.name@example.com");
  });

  it("accepts passphrase-friendly passwords", () => {
    const password = "a secure phrase with spaces";
    expect(password.length).toBeGreaterThanOrEqual(MIN_PASSWORD_LENGTH);
    expect(validateNewPassword(password, password)).toBeNull();
  });

  it("rejects short, oversized, and mismatched passwords", () => {
    expect(validateNewPassword("too-short", "too-short")).toContain(`${MIN_PASSWORD_LENGTH}`);
    expect(validateNewPassword("a".repeat(MAX_PASSWORD_LENGTH + 1), "a".repeat(MAX_PASSWORD_LENGTH + 1))).toContain(`${MAX_PASSWORD_LENGTH}`);
    expect(validateNewPassword("long-enough-password", "different-password")).toBe("The passwords do not match.");
  });

  it("blocks open redirects in authentication callbacks", () => {
    expect(safeNextPath("//attacker.example/path")).toBe("/");
    expect(safeNextPath("https://attacker.example/path")).toBe("/");
    expect(safeNextPath("/analyses/123")).toBe("/analyses/123");
    expect(buildCallbackUrl("https://scamshield.example", "//attacker.example")).toBe(
      "https://scamshield.example/auth/callback?next=%2F",
    );
  });

  it("uses secure SameSite cookies in production", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(getAuthCookieOptions()).toEqual({ path: "/", sameSite: "lax", secure: true });

    vi.stubEnv("NODE_ENV", "development");
    expect(getAuthCookieOptions()).toEqual({ path: "/", sameSite: "lax", secure: false });
  });
});
