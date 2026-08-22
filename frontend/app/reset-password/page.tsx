import { cookies } from "next/headers";

import { AuthCard } from "@/components/auth-card";

export default async function ResetPasswordPage() {
  const cookieStore = await cookies();
  const recoveryAllowed = cookieStore.get("scamshield-recovery")?.value === "1";
  return <AuthCard mode="reset" recoveryAllowed={recoveryAllowed} />;
}
