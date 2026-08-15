import { redirect } from "next/navigation";

import { Dashboard } from "@/components/dashboard";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

type HomePageProps = {
  searchParams: Promise<{ error_code?: string }>;
};

export default async function HomePage({ searchParams }: HomePageProps) {
  const { error_code: errorCode } = await searchParams;
  const hasExpiredOAuthState = errorCode === "bad_oauth_state";

  if (!isSupabaseConfigured()) {
    redirect("/login?error=configuration");
  }

  const supabase = await createClient();
  const { data } = await supabase.auth.getClaims();
  const claims = data?.claims;
  if (!claims?.sub) {
    redirect(hasExpiredOAuthState ? "/login?error=oauth_state" : "/login");
  }

  if (hasExpiredOAuthState) {
    redirect("/");
  }

  const { data: { user } } = await supabase.auth.getUser();
  const userEmail = user?.email ?? (typeof claims.email === "string" ? claims.email : "Protected account");
  return <Dashboard userEmail={userEmail} />;
}
