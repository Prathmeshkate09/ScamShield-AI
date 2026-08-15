from app.models.analysis import Analysis


def test_analysis_user_foreign_key_resolves_to_supabase_auth_users() -> None:
    foreign_key = next(key for key in Analysis.__table__.foreign_keys if key.target_fullname == "auth.users.id")

    assert foreign_key.column.table.fullname == "auth.users"
    assert foreign_key.column.name == "id"
