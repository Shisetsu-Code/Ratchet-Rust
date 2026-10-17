//! Signed native-console operations. Browser sessions cannot substitute for this proof.
use crate::{
    auth,
    chat::{
        Call,
        authority::Authority,
        control::{MutationPlan, NAME},
        routes,
    },
    db::Db,
    http::{self, ApiError, ApiResult},
    password,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::{MAX_SAFE_INTEGER, is_uuid},
    signatures::{canonical_owner_json, verify_ed25519},
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

const OWNER_SQL: &str = "SELECT pk.user_id AS owner_user_id,ws.workspace_id,pk.public_key FROM portable_key_credentials pk JOIN users u ON u.user_id=pk.user_id AND u.role='ADMIN' AND u.status='ACTIVE' JOIN workspace_staff ws ON ws.user_id=u.user_id AND ws.staff_role='OWNER' AND ws.revoked_at IS NULL JOIN workspace_memberships wm ON wm.user_id=u.user_id AND wm.workspace_id=ws.workspace_id AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL WHERE pk.key_id=?1 AND pk.revoked_at IS NULL ORDER BY ws.workspace_id LIMIT 1";
#[derive(Deserialize)]
struct Owner {
    owner_user_id: String,
    workspace_id: String,
    public_key: String,
}
#[derive(Deserialize)]
struct Challenge {
    challenge_id: String,
    challenge: String,
    owner_key_id: String,
    owner_user_id: String,
    workspace_id: String,
    origin: String,
    operation_digest: String,
    operation_type: String,
    target_id: Option<String>,
    expires_at: String,
    consumed: Option<String>,
}
fn denied() -> ApiError {
    ApiError::domain("OWNER_VERIFICATION_FAILED", 403)
}
fn invalid() -> ApiError {
    ApiError::domain("VALIDATION_ERROR", 422)
}
fn text<'a>(v: &'a Value, key: &str) -> ApiResult<&'a str> {
    v[key].as_str().ok_or_else(invalid)
}
fn strict(v: &Value, keys: &[&str]) -> ApiResult<()> {
    if v.as_object()
        .is_none_or(|o| o.keys().any(|k| !keys.contains(&k.as_str())))
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_operation(op: &Value) -> ApiResult<()> {
    let kind = text(op, "type")?;
    let keys: &[&str] = match kind {
        "accounts.list" | "conversations.list" => &["type", "after", "limit"],
        "conversation.read" => &["type", "chat_id", "after_revision", "limit"],
        "account.recover" => &[
            "type",
            "user_id",
            "new_password",
            "new_key_id",
            "new_public_key",
        ],
        _ => return Err(invalid()),
    };
    strict(op, keys)?;
    for field in ["after", "chat_id", "user_id", "new_key_id"] {
        if let Some(v) = op.get(field)
            && !v.as_str().is_some_and(is_uuid)
        {
            return Err(invalid());
        }
    }
    if let Some(v) = op.get("limit")
        && !v.as_u64().is_some_and(|n| (1..=100).contains(&n))
    {
        return Err(invalid());
    }
    if let Some(v) = op.get("after_revision")
        && !v.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER)
    {
        return Err(invalid());
    }
    if kind == "conversation.read" && !is_uuid(text(op, "chat_id")?) {
        return Err(invalid());
    }
    if kind == "account.recover" {
        if !is_uuid(text(op, "user_id")?)
            || !(15..=256).contains(&text(op, "new_password")?.encode_utf16().count())
        {
            return Err(invalid());
        }
        if op.get("new_key_id").is_some() != op.get("new_public_key").is_some() {
            return Err(invalid());
        }
        if let Some(key) = op.get("new_public_key")
            && !key.as_str().is_some_and(|s| {
                s.len() == 43 && URL_SAFE_NO_PAD.decode(s).is_ok_and(|v| v.len() == 32)
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn challenge_value(c: &Challenge) -> Value {
    json!({"challenge_id":c.challenge_id,"challenge":c.challenge,"purpose":"OWNER_CONSOLE","key_id":c.owner_key_id,"owner_user_id":c.owner_user_id,"workspace_id":c.workspace_id,"origin":c.origin,"operation_digest":c.operation_digest,"expires_at":c.expires_at})
}

pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Option<Response>> {
    if request.method() != Method::Post {
        return Ok(None);
    }
    match request.path().as_str() {
        "/api/v1/owner-console/prepare" => {
            let input: Value = http::read_json(request, 64 * 1024).await?;
            strict(&input, &["owner_key_id", "operation"])?;
            validate_operation(&input["operation"])?;
            let key = text(&input, "owner_key_id")?;
            if !is_uuid(key) {
                return Err(invalid());
            }
            let db = Db(env.d1("DB")?);
            let owner = db
                .first::<Owner>(OWNER_SQL, &[json!(key)])
                .await?
                .ok_or_else(denied)?;
            let op = &input["operation"];
            let kind = text(op, "type")?;
            let target = if kind == "account.recover" {
                op["user_id"].as_str()
            } else {
                op["chat_id"].as_str()
            };
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes)
                .map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
            let row = Challenge {
                challenge_id: http::random_id()?,
                challenge: URL_SAFE_NO_PAD.encode(bytes),
                owner_key_id: key.into(),
                owner_user_id: owner.owner_user_id,
                workspace_id: owner.workspace_id,
                origin: env.var("RP_ORIGIN")?.to_string(),
                operation_digest: auth::sha256_hex(&canonical_owner_json(op)?),
                operation_type: kind.into(),
                target_id: target.map(str::to_owned),
                expires_at: http::iso_at(Date::now().as_millis() as f64 + 120_000.0),
                consumed: None,
            };
            let admission =
                crate::auth_admission::challenge_statement(&db, request, None, key).await?;
            db.0.batch(vec![admission,db.statement("INSERT INTO owner_console_challenges(challenge_id,challenge,owner_key_id,owner_user_id,workspace_id,origin,operation_digest,operation_type,target_id,created_at,expires_at,admission_origin) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",&[json!(row.challenge_id),json!(row.challenge),json!(row.owner_key_id),json!(row.owner_user_id),json!(row.workspace_id),json!(row.origin),json!(row.operation_digest),json!(row.operation_type),json!(row.target_id),json!(http::now_iso()),json!(row.expires_at),json!(crate::auth_admission::origin_hash(request)?)])?]).await.map_err(crate::auth_admission::admission_error)?;
            Ok(Some(http::json(&challenge_value(&row))?))
        }
        "/api/v1/owner-console/complete" => {
            let input: Value = http::read_json(request, 64 * 1024).await?;
            verify(env, &input).await?;
            Ok(Some(
                routes::forward(
                    env,
                    Call {
                        op: "control.owner".into(),
                        authority: Authority {
                            chat_id: NAME.into(),
                            user_id: String::new(),
                            device_id: String::new(),
                            session_id: String::new(),
                        },
                        data: input,
                    },
                )
                .await?,
            ))
        }
        _ => Ok(None),
    }
}

async fn verify(env: &Env, input: &Value) -> ApiResult<Challenge> {
    strict(input, &["challenge_id", "signature", "operation"])?;
    validate_operation(&input["operation"])?;
    let id = text(input, "challenge_id")?;
    if !is_uuid(id) {
        return Err(invalid());
    }
    let db = Db(env.d1("DB")?);
    let row=db.first::<Challenge>("SELECT c.*,x.challenge_id AS consumed FROM owner_console_challenges c LEFT JOIN owner_console_consumptions x ON x.challenge_id=c.challenge_id WHERE c.challenge_id=?1",&[json!(id)]).await?.ok_or_else(||ApiError::domain("CHALLENGE_NOT_FOUND",404))?;
    if row.consumed.is_some() {
        return Err(ApiError::domain("CHALLENGE_CONSUMED", 409));
    }
    if row.expires_at <= http::now_iso() {
        return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
    }
    let owner = db
        .first::<Owner>(OWNER_SQL, &[json!(row.owner_key_id)])
        .await?
        .ok_or_else(denied)?;
    if owner.owner_user_id != row.owner_user_id
        || owner.workspace_id != row.workspace_id
        || row.origin != env.var("RP_ORIGIN")?.to_string()
        || row.operation_digest != auth::sha256_hex(&canonical_owner_json(&input["operation"])?)
    {
        return Err(denied());
    }
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&owner.public_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(denied)?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(text(input, "signature")?)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(denied)?;
    verify_ed25519(
        &public,
        canonical_owner_json(&challenge_value(&row))?.as_bytes(),
        &signature,
    )
    .map_err(|_| denied())?;
    Ok(row)
}

pub async fn require_chat(env: &Env, data: &Value, chat: &str) -> ApiResult<()> {
    let db = Db(env.d1("DB")?);
    let owner = db
        .first::<Owner>(OWNER_SQL, &[json!(text(data, "owner_key_id")?)])
        .await?
        .ok_or_else(denied)?;
    if owner.owner_user_id != text(data, "owner_user_id")?
        || owner.workspace_id != text(data, "workspace_id")?
    {
        return Err(denied());
    }
    if db
        .first::<Value>(
            "SELECT 1 AS n FROM chats WHERE chat_id=?1 AND workspace_id=?2",
            &[json!(chat), json!(owner.workspace_id)],
        )
        .await?
        .is_none()
    {
        return Err(ApiError::domain("CHAT_NOT_FOUND", 404));
    }
    Ok(())
}

pub async fn prepare_control(env: &Env, input: &Value) -> ApiResult<MutationPlan> {
    let row = verify(env, input).await?;
    let op = &input["operation"];
    let db = Db(env.d1("DB")?);
    let now = http::now_iso();
    let mut statements = vec![db.statement(
        "INSERT INTO owner_console_consumptions(challenge_id,consumed_at) VALUES(?1,?2)",
        &[json!(row.challenge_id), json!(now)],
    )?];
    let mut affected_users = vec![];
    let response = if row.operation_type == "account.recover" {
        let user = text(op, "user_id")?;
        let predicate = "EXISTS(SELECT 1 FROM users u JOIN workspace_memberships wm ON wm.user_id=u.user_id JOIN password_credentials p ON p.user_id=u.user_id WHERE u.user_id=?2 AND wm.workspace_id=?3 AND u.status='ACTIVE' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM workspace_staff s WHERE s.user_id=u.user_id AND s.staff_role='OWNER'))";
        if db
            .first::<Value>(
                &format!("SELECT 1 AS n WHERE {predicate}"),
                &[Value::Null, json!(user), json!(row.workspace_id)],
            )
            .await?
            .is_none()
        {
            return Err(ApiError::domain("ACCOUNT_NOT_RECOVERABLE", 403));
        }
        if let Some(key) = op["new_key_id"].as_str()
            && db
                .first::<Value>(
                    "SELECT 1 AS n FROM portable_key_credentials WHERE key_id=?1",
                    &[json!(key)],
                )
                .await?
                .is_some()
        {
            return Err(ApiError::domain("KEY_ID_TAKEN", 409));
        }
        let credential =
            password::prepare_credential(&db, &row.owner_user_id, text(op, "new_password")?)
                .await?;
        let guard = http::random_id()?;
        statements.push(db.statement(&format!("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN {predicate} THEN 1 ELSE 0 END"),&[json!(guard),json!(user),json!(row.workspace_id)])?);
        statements.push(db.statement("UPDATE password_credentials SET algorithm=?2,iterations=?3,salt=?4,verifier=?5,failed_attempts=0,next_allowed_at=NULL,updated_at=?6 WHERE user_id=?1",&[json!(user),json!(credential.algorithm),json!(credential.iterations),json!(credential.salt),json!(credential.verifier),json!(now)])?);
        for table in [
            "sessions",
            "devices",
            "portable_key_credentials",
            "push_subscriptions",
        ] {
            statements.push(db.statement(
                &format!(
                    "UPDATE {table} SET revoked_at=?2 WHERE user_id=?1 AND revoked_at IS NULL"
                ),
                &[json!(user), json!(now)],
            )?);
        }
        statements.push(db.statement("DELETE FROM passkeys WHERE user_id=?1", &[json!(user)])?);
        statements.push(db.statement("DELETE FROM device_prekey_bundles WHERE device_id IN(SELECT device_id FROM devices WHERE user_id=?1)",&[json!(user)])?);
        statements.push(db.statement("UPDATE one_time_prekeys SET consumed_at=?2 WHERE device_id IN(SELECT device_id FROM devices WHERE user_id=?1) AND consumed_at IS NULL",&[json!(user),json!(now)])?);
        statements.push(db.statement("UPDATE device_certificates SET revoked_at=?2 WHERE device_id IN(SELECT device_id FROM devices WHERE user_id=?1) AND revoked_at IS NULL",&[json!(user),json!(now)])?);
        statements.push(db.statement("INSERT OR IGNORE INTO portable_key_challenge_consumptions SELECT challenge_id,?2 FROM portable_key_challenges WHERE user_id=?1",&[json!(user),json!(now)])?);
        statements.push(db.statement("INSERT OR IGNORE INTO webauthn_challenge_consumptions SELECT challenge_id,?2 FROM webauthn_challenges WHERE user_id=?1 OR invitation_id IN(SELECT invitation_id FROM invitations WHERE customer_user_id=?1)",&[json!(user),json!(now)])?);
        statements.push(db.statement("UPDATE invitations SET revoked_at=?2,status='REVOKED' WHERE customer_user_id=?1 AND revoked_at IS NULL AND status='ACTIVE'",&[json!(user),json!(now)])?);
        if let Some(key) = op["new_key_id"].as_str() {
            statements.push(db.statement("INSERT INTO portable_key_credentials(key_id,user_id,public_key,label,created_at) VALUES(?1,?2,?3,'Owner console replacement',?4)",&[json!(key),json!(user),op["new_public_key"].clone(),json!(now)])?);
        }
        statements.push(db.statement(
            "DELETE FROM auth_commit_guards WHERE assertion_id=?1",
            &[json!(guard)],
        )?);
        affected_users.push(user.into());
        json!({"user_id":user,"workspace_id":row.workspace_id,"recovered":true,"key_id":op["new_key_id"]})
    } else if row.operation_type == "conversation.read" {
        let chat = text(op, "chat_id")?;
        let data = json!({"owner_key_id":row.owner_key_id,"owner_user_id":row.owner_user_id,"workspace_id":row.workspace_id,"after":op["after_revision"].as_u64().unwrap_or(0),"limit":op["limit"].as_u64().unwrap_or(50)});
        require_chat(env, &data, chat).await?;
        let mut response = routes::forward(
            env,
            Call {
                op: "owner.read".into(),
                authority: Authority {
                    chat_id: chat.into(),
                    user_id: row.owner_user_id.clone(),
                    session_id: String::new(),
                    device_id: String::new(),
                },
                data,
            },
        )
        .await?;
        if response.status_code() != 200 {
            return Err(ApiError::retryable("CONVERSATION_UNAVAILABLE", 503));
        }
        response.json().await?
    } else {
        let limit = op["limit"].as_u64().unwrap_or(50) as usize;
        let after = op["after"].as_str().unwrap_or("");
        let (sql, key, id) = if row.operation_type == "accounts.list" {
            (
                "SELECT u.user_id,u.role,p.login_name,COALESCE(s.display_name,p.login_name) AS display_name FROM users u JOIN workspace_memberships wm ON wm.user_id=u.user_id LEFT JOIN password_credentials p ON p.user_id=u.user_id LEFT JOIN workspace_staff s ON s.user_id=u.user_id AND s.workspace_id=wm.workspace_id WHERE wm.workspace_id=?1 AND wm.status='ACTIVE' AND wm.revoked_at IS NULL AND u.status='ACTIVE' AND u.user_id>?2 AND NOT EXISTS(SELECT 1 FROM workspace_staff owner WHERE owner.user_id=u.user_id AND owner.staff_role='OWNER') ORDER BY u.user_id LIMIT ?3",
                "accounts",
                "user_id",
            )
        } else {
            (
                "SELECT c.chat_id,c.workspace_id,c.created_at,COALESCE(s.message_count,0) AS message_count,s.last_message_at FROM chats c LEFT JOIN chat_storage_stats s ON s.chat_id=c.chat_id WHERE c.workspace_id=?1 AND c.chat_id>?2 ORDER BY c.chat_id LIMIT ?3",
                "conversations",
                "chat_id",
            )
        };
        let mut rows = db
            .all(
                sql,
                &[json!(row.workspace_id), json!(after), json!(limit + 1)],
            )
            .await?;
        let next = if rows.len() > limit {
            rows[limit - 1][id].clone()
        } else {
            Value::Null
        };
        rows.truncate(limit);
        json!({key:rows,"next_after":next})
    };
    statements.push(db.statement("INSERT INTO owner_console_audit(event_id,challenge_id,workspace_id,actor_user_id,operation_type,target_id,result,created_at) VALUES(?1,?2,?3,?4,?5,?6,'SUCCEEDED',?7)",&[json!(http::random_id()?),json!(row.challenge_id),json!(row.workspace_id),json!(row.owner_user_id),json!(row.operation_type),json!(row.target_id),json!(now)])?);
    Ok(MutationPlan {
        statements,
        affected_users,
        affected_chats: vec![],
        response,
        status: 200,
        clear_cookie: false,
    })
}
