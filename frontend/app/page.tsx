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
  const { data: { user }, error: userError } = await supabase.auth.getUser();
  if (userError || !user) {
    redirect(hasExpiredOAuthState ? "/login?error=oauth_state" : "/login");
  }

  if (!user.email_confirmed_at) {
    redirect("/verify-email");
  }

  if (hasExpiredOAuthState) {
    redirect("/");
  }

  const userEmail = user.email ?? "Protected account";
  return <Dashboard userEmail={userEmail} />;
}
