//! Administrative accounts and opaque, single-use access links.
mod customers;
mod invitations;
mod operators;
use crate::chat::control::{self, MutationPlan};
use crate::{
    auth::{self, AuthContext},
    db::Db,
    http::{self, ApiError, ApiResult},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use worker::{D1PreparedStatement, Date, Env, Method, Request, Response};

pub(super) fn invalid() -> ApiError {
    ApiError::domain("VALIDATION_ERROR", 422)
}
pub(super) fn string<'a>(v: &'a Value, key: &str) -> ApiResult<&'a str> {
    v[key].as_str().ok_or_else(invalid)
}
pub(super) fn id(v: &str) -> ApiResult<&str> {
    if ratchet_core::message::is_uuid(v) {
        Ok(v)
    } else {
        Err(invalid())
    }
}
pub(super) fn text<'a>(v: &'a Value, key: &str, min: usize, max: usize) -> ApiResult<&'a str> {
    let s = string(v, key)?.trim();
    if (min..=max).contains(&s.encode_utf16().count()) {
        Ok(s)
    } else {
        Err(invalid())
    }
}
pub(super) fn token() -> ApiResult<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub(super) fn expires(days: f64) -> String {
    http::iso_at(Date::now().as_millis() as f64 + days * 86400000.0)
}
pub(super) fn plan(response: Value, status: u16) -> MutationPlan {
    MutationPlan {
        statements: vec![],
        affected_users: vec![],
        affected_chats: vec![],
        response,
        status,
        clear_cookie: false,
    }
}
pub(super) const STAFF: &str = "SELECT 1 FROM workspace_staff ws JOIN workspace_memberships wm ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL JOIN users u ON u.user_id=ws.user_id AND u.role='ADMIN' AND u.status='ACTIVE' WHERE ws.workspace_id=?1 AND ws.user_id=?2 AND ws.revoked_at IS NULL AND ws.staff_role IN ('ADMIN','OPERATOR')";
pub(super) async fn staff(
    db: &Db,
    workspace: &str,
    user: &str,
    administrator: bool,
) -> ApiResult<()> {
    let sql = if administrator {
        format!("{STAFF} AND ws.staff_role='ADMIN'")
    } else {
        STAFF.into()
    };
    if db
        .first::<Value>(&sql, &[json!(workspace), json!(user)])
        .await?
        .is_none()
    {
        return Err(ApiError::domain(
            if administrator {
                "WORKSPACE_ADMIN_REQUIRED"
            } else {
                "REFERRAL_ISSUER_REQUIRED"
            },
            403,
        ));
    }
    Ok(())
}
// An assertion inside the same D1 batch prevents a stale authorization read from committing.
pub(super) fn guard(db: &Db, predicate: &str, values: &[Value]) -> ApiResult<D1PreparedStatement> {
    db.statement(&format!("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT 'admin:{}',CASE WHEN ({predicate}) THEN 1 ELSE 0 END",http::random_id()?),values)
}
pub(super) fn cleanup(db: &Db) -> ApiResult<D1PreparedStatement> {
    db.statement(
        "DELETE FROM auth_commit_guards WHERE assertion_id GLOB 'admin:*'",
        &[],
    )
}
pub(super) fn staff_guard(
    db: &Db,
    workspace: &str,
    user: &str,
    administrator: bool,
) -> ApiResult<D1PreparedStatement> {
    guard(
        db,
        &format!(
            "EXISTS({STAFF}{})",
            if administrator {
                " AND ws.staff_role='ADMIN'"
            } else {
                ""
            }
        ),
        &[json!(workspace), json!(user)],
    )
}
pub(super) fn login(v: &Value) -> ApiResult<String> {
    let s = text(v, "login_name", 3, 64)?.to_lowercase();
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(invalid());
    }
    Ok(s)
}
pub(super) async fn unique_login(db: &Db, name: &str, user: &str) -> ApiResult<()> {
    if db
        .first::<Value>(
            "SELECT 1 FROM password_credentials WHERE login_name=?1 AND user_id<>?2",
            &[json!(name), json!(user)],
        )
        .await?
        .is_some()
    {
        return Err(ApiError::domain("LOGIN_NAME_TAKEN", 409));
    }
    Ok(())
}
pub(super) async fn credential(
    db: &Db,
    user: &str,
    name: &str,
    password: &str,
    now: &str,
) -> ApiResult<D1PreparedStatement> {
    let c = crate::password::prepare_credential(db, user, password).await?;
    db.statement("INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?7) ON CONFLICT(user_id) DO UPDATE SET login_name=excluded.login_name,algorithm=excluded.algorithm,iterations=excluded.iterations,salt=excluded.salt,verifier=excluded.verifier,failed_attempts=0,next_allowed_at=NULL,updated_at=excluded.updated_at",&[json!(user),json!(name),json!(c.algorithm),json!(c.iterations),json!(c.salt),json!(c.verifier),json!(now)])
}
pub(super) async fn insert_credential(
    db: &Db,
    user: &str,
    name: &str,
    password: &str,
    now: &str,
) -> ApiResult<D1PreparedStatement> {
    let c = crate::password::prepare_credential(db, user, password).await?;
    db.statement("INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",&[json!(user),json!(name),json!(c.algorithm),json!(c.iterations),json!(c.salt),json!(c.verifier),json!(now)])
}
pub(super) fn chat_statements(
    db: &Db,
    chat: &str,
    workspace: &str,
    issuer: &str,
    customer: &str,
    now: &str,
) -> ApiResult<Vec<D1PreparedStatement>> {
    Ok(vec![db.statement("INSERT INTO chats(chat_id,workspace_id,created_by_user_id,created_at) VALUES(?1,?2,?3,?4)",&[json!(chat),json!(workspace),json!(issuer),json!(now)])?,db.statement("INSERT INTO chat_participants(chat_id,user_id,participant_role,joined_at) VALUES(?1,?2,'CUSTOMER',?3)",&[json!(chat),json!(customer),json!(now)])?,db.statement("INSERT INTO chat_revisions(chat_id) VALUES(?1)",&[json!(chat)])?])
}

pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Option<Response>> {
    let path = request.path();
    if request.method() == Method::Patch && path == "/api/v1/sessions/current/display-name" {
        let data: Value = http::read_json(request, 65536).await?;
        let target = string(&data, "workspace_id")?.to_string();
        return control::domain(request, env, "admin.display_name", &target, data)
            .await
            .map(Some);
    }
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    if request.method() == Method::Post && path == "/api/v1/operator-access/claim" {
        return operators::claim(request, env).await.map(Some);
    }
    if request.method() == Method::Post
        && matches!(
            path.as_str(),
            "/api/v1/lead-access/claim" | "/api/v1/lead-access/customer/claim"
        )
    {
        return customers::claim(request, env, path.ends_with("customer/claim"))
            .await
            .map(Some);
    }
    let route = segments.get(2).copied().unwrap_or("");
    if !matches!(route, "operators" | "invitations" | "leads") {
        return Ok(None);
    }
    let auth = auth::require_session(request, env).await?;
    auth::require_authorized(&auth)?;
    let db = Db(env.d1("DB")?);
    if route == "operators" && request.method() == Method::Get {
        return operators::list(request, env, &auth, &segments)
            .await
            .map(Some);
    }
    let (op, target, mut data) = match (route, request.method(), segments.len()) {
        ("operators", Method::Post, 3) => {
            let data: Value = http::read_json(request, 65536).await?;
            (
                "admin.operator.create",
                string(&data, "workspace_id")?.to_string(),
                data,
            )
        }
        ("operators", Method::Delete, 4) => {
            ("admin.operator.revoke", segments[3].into(), json!({}))
        }
        ("operators", Method::Post, 5) if segments[4] == "access-grants" => {
            ("admin.operator.grant", segments[3].into(), json!({}))
        }
        ("operators", Method::Delete, 6) if segments[4] == "access-grants" => (
            "admin.operator.grant_revoke",
            segments[3].into(),
            json!({"grant_id":segments[5]}),
        ),
        ("invitations", Method::Post, 3) => {
            let data: Value = http::read_json(request, 65536).await?;
            (
                "admin.invitation.create",
                string(&data, "workspace_id")?.to_string(),
                data,
            )
        }
        ("invitations", Method::Post, 5) if segments[4] == "claim" => (
            "admin.invitation.referral_claim",
            segments[3].into(),
            json!({}),
        ),
        ("leads", Method::Post, 5) if segments[4] == "account" => (
            "admin.customer.account",
            segments[3].into(),
            http::read_json(request, 65536).await?,
        ),
        ("leads", Method::Post, 5) if segments[4] == "access" => {
            ("admin.customer.access", segments[3].into(), json!({}))
        }
        ("leads", Method::Put, 6) if segments[4] == "account" && segments[5] == "password" => (
            "admin.customer.password",
            segments[3].into(),
            http::read_json(request, 65536).await?,
        ),
        _ => return Ok(None),
    };
    drop(db);
    if op.starts_with("admin.operator.") {
        auth::require_recent(&auth)?;
        if op != "admin.operator.create" {
            data["workspace_id"] = json!(
                request
                    .url()?
                    .query_pairs()
                    .find(|(k, _)| k == "workspace_id")
                    .map(|(_, v)| v.into_owned())
                    .ok_or_else(invalid)?
            );
        }
    }
    control::domain(request, env, op, &target, data)
        .await
        .map(Some)
}
pub async fn prepare_control(
    env: &Env,
    auth: &AuthContext,
    operation: &str,
    target: &str,
    data: &Value,
) -> ApiResult<MutationPlan> {
    auth::require_authorized(auth)?;
    let db = Db(env.d1("DB")?);
    if operation == "admin.display_name" {
        id(target)?;
        let name = text(data, "display_name", 1, 80)?;
        staff(&db, target, &auth.user_id, false)
            .await
            .map_err(|_| ApiError::domain("STAFF_MEMBERSHIP_NOT_FOUND", 403))?;
        let mut p = plan(json!({"workspace_id":target,"display_name":name}), 200);
        p.affected_users.push(auth.user_id.clone());
        p.statements
            .push(staff_guard(&db, target, &auth.user_id, false)?);
        p.statements.push(db.statement("UPDATE workspace_staff SET display_name=?3 WHERE workspace_id=?1 AND user_id=?2 AND staff_role IN('ADMIN','OPERATOR') AND revoked_at IS NULL",&[json!(target),json!(auth.user_id),json!(name)])?);
        p.statements.push(cleanup(&db)?);
        return Ok(p);
    }
    let mut p = if operation.starts_with("admin.operator.") {
        auth::require_recent(auth)?;
        operators::prepare(&db, auth, operation, target, data).await
    } else if operation.starts_with("admin.customer.") {
        customers::prepare(&db, auth, operation, target, data).await
    } else {
        invitations::prepare(&db, auth, operation, target, data).await
    }?;
    p.statements.push(cleanup(&db)?);
    Ok(p)
}
