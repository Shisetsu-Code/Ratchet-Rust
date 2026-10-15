use ratchet_core::policy::{
    ChatScope, Role, Viewer, authorize_chat, can_manage_wallpaper, can_mutate,
};

fn viewer() -> Viewer {
    Viewer {
        user_id: "admin-a".into(),
        role: Role::Admin,
        user_active: true,
        device_authorized: true,
        device_revoked: false,
        session_revoked: false,
        expires_at_ms: 1_000_000,
        last_seen_at_ms: 500_000,
        now_ms: 600_000,
    }
}
fn chat() -> ChatScope {
    ChatScope {
        active_member: true,
        owner_admin_user_id: "admin-a".into(),
        staff_role: Some("ADMIN".into()),
        staff_revoked: false,
    }
}

#[test]
fn live_session_still_requires_chat_membership() {
    assert!(authorize_chat(&viewer(), &chat()).is_ok());
    let mut scope = chat();
    scope.active_member = false;
    assert!(authorize_chat(&viewer(), &scope).is_err());
}

#[test]
fn revoked_or_expired_authority_is_never_reusable() {
    for case in 0..6 {
        let mut user = viewer();
        match case {
            0 => user.session_revoked = true,
            1 => user.device_revoked = true,
            2 => user.device_authorized = false,
            3 => user.user_active = false,
            4 => user.expires_at_ms = user.now_ms,
            _ => user.last_seen_at_ms = 0,
        }
        if case == 5 {
            user.now_ms = 72 * 60 * 60 * 1000;
            user.expires_at_ms = user.now_ms + 1;
        }
        assert!(authorize_chat(&user, &chat()).is_err(), "case {case}");
    }
}

#[test]
fn customers_do_not_expire_due_to_admin_idle_rule() {
    let mut user = viewer();
    user.role = Role::Customer;
    user.last_seen_at_ms = 0;
    user.now_ms = 100 * 60 * 60 * 1000;
    user.expires_at_ms = user.now_ms + 1;
    assert!(authorize_chat(&user, &chat()).is_ok());
    assert!(!can_mutate(&user, &chat()));
    assert!(!can_manage_wallpaper(&user, &chat()));
}

#[test]
fn administrators_cannot_change_another_accounts_wallpaper() {
    assert!(can_manage_wallpaper(&viewer(), &chat()));
    let mut scope = chat();
    scope.owner_admin_user_id = "admin-b".into();
    assert!(!can_manage_wallpaper(&viewer(), &scope));
    scope = chat();
    scope.staff_role = Some("OPERATOR".into());
    assert!(!can_manage_wallpaper(&viewer(), &scope));
    assert!(can_mutate(&viewer(), &scope));
    scope.staff_revoked = true;
    assert!(!can_mutate(&viewer(), &scope));
}
