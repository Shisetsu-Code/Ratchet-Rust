use crate::error::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Customer,
}

/// Populate from authoritative server records, never from client frames.
pub struct Viewer {
    pub user_id: String,
    pub role: Role,
    pub user_active: bool,
    pub device_authorized: bool,
    pub device_revoked: bool,
    pub session_revoked: bool,
    pub expires_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub now_ms: u64,
}

pub struct ChatScope {
    pub active_member: bool,
    pub owner_admin_user_id: String,
    pub staff_role: Option<String>,
    pub staff_revoked: bool,
}

pub fn authorize_chat(viewer: &Viewer, chat: &ChatScope) -> Result<(), DomainError> {
    let idle_expired = viewer.role == Role::Admin
        && viewer.now_ms.saturating_sub(viewer.last_seen_at_ms) >= 72 * 60 * 60 * 1000;
    if !viewer.user_active
        || !viewer.device_authorized
        || viewer.device_revoked
        || viewer.session_revoked
        || viewer.expires_at_ms <= viewer.now_ms
        || idle_expired
        || !chat.active_member
    {
        return Err(DomainError::new("CHAT_NOT_AVAILABLE", 403));
    }
    Ok(())
}

pub fn can_mutate(viewer: &Viewer, chat: &ChatScope) -> bool {
    authorize_chat(viewer, chat).is_ok()
        && viewer.role == Role::Admin
        && !chat.staff_revoked
        && matches!(chat.staff_role.as_deref(), Some("ADMIN" | "OPERATOR"))
}

pub fn can_manage_wallpaper(viewer: &Viewer, chat: &ChatScope) -> bool {
    authorize_chat(viewer, chat).is_ok()
        && viewer.role == Role::Admin
        && !chat.staff_revoked
        && viewer.user_id == chat.owner_admin_user_id
        && matches!(chat.staff_role.as_deref(), Some("ADMIN" | "OWNER"))
}
