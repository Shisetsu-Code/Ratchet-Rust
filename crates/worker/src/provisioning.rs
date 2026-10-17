use crate::{
    bootstrap::require_token,
    db::Db,
    http::{self, ApiError, ApiResult},
    password::prepare_credential,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::is_uuid,
    signatures::{portable_signature_message, verify_ed25519},
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{Date, Env, Request, Response};

const OWNER_SQL: &str = "SELECT ib.user_id AS owner_user_id,ib.workspace_id,pk.public_key FROM installation_bootstrap ib JOIN users u ON u.user_id=ib.user_id AND u.role='ADMIN' AND u.status='ACTIVE' JOIN workspace_memberships wm ON wm.workspace_id=ib.workspace_id AND wm.user_id=ib.user_id AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL JOIN portable_key_credentials pk ON pk.user_id=ib.user_id AND pk.key_id=?1 AND pk.revoked_at IS NULL JOIN workspace_staff ws ON ws.user_id=ib.user_id AND ws.workspace_id=ib.workspace_id AND ws.staff_role='OWNER' AND ws.revoked_at IS NULL WHERE ib.singleton=1";

#[derive(Deserialize)]
struct Owner {
    owner_user_id: String,
    workspace_id: String,
    public_key: String,
}
#[derive(Deserialize)]
struct Prepare {
    bootstrap_token: String,
    owner_key_id: String,
}
#[derive(Deserialize)]
struct Complete {
    bootstrap_token: String,
    challenge_id: String,
    signature: String,
    key_id: String,
    public_key: String,
    login_name: String,
    master_password: String,
}
#[derive(Deserialize)]
struct Challenge {
    challenge_id: String,
    challenge: String,
    owner_key_id: String,
    owner_user_id: String,
    workspace_id: String,
    expires_at: String,
    consumed: Option<String>,
}

pub async fn prepare(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let input: Prepare = http::read_json(request, 64 * 1024).await?;
    require_token(env, &input.bootstrap_token)?;
    if !is_uuid(&input.owner_key_id) {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    let owner = db
        .first::<Owner>(OWNER_SQL, &[json!(input.owner_key_id)])
        .await?
        .ok_or_else(|| ApiError::domain("OWNER_VERIFICATION_FAILED", 403))?;
    let id = http::random_id()?;
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let challenge = URL_SAFE_NO_PAD.encode(bytes);
    let admission =
        crate::auth_admission::challenge_statement(&db, request, None, &input.owner_key_id).await?;
    db.0.batch(vec![admission,db.statement("INSERT INTO admin_provisioning_challenges(challenge_id,challenge,owner_key_id,owner_user_id,workspace_id,created_at,expires_at,admission_origin) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        &[json!(id),json!(challenge),json!(input.owner_key_id),json!(owner.owner_user_id),json!(owner.workspace_id),json!(http::now_iso()),json!(http::iso_at(Date::now().as_millis() as f64+300_000.0)),json!(crate::auth_admission::origin_hash(request)?)])?]).await.map_err(crate::auth_admission::admission_error)?;
    http::json(
        &json!({"challenge_id":id,"challenge":challenge,"purpose":"ADMIN_PROVISIONING","key_id":input.owner_key_id,"origin":env.var("RP_ORIGIN")?.to_string()}),
    )
}

pub async fn complete(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let input: Complete = http::read_json(request, 64 * 1024).await?;
    require_token(env, &input.bootstrap_token)?;
    let login = input.login_name.trim().to_ascii_lowercase();
    if !is_uuid(&input.challenge_id)
        || !is_uuid(&input.key_id)
        || input.signature.len() != 86
        || input.public_key.len() != 43
        || URL_SAFE_NO_PAD
            .decode(&input.public_key)
            .map(|v| v.len() != 32)
            .unwrap_or(true)
        || !(3..=64).contains(&login.len())
        || !login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    let row=db.first::<Challenge>("SELECT c.*,x.challenge_id AS consumed FROM admin_provisioning_challenges c LEFT JOIN admin_provisioning_challenge_consumptions x ON x.challenge_id=c.challenge_id WHERE c.challenge_id=?1",&[json!(input.challenge_id)]).await?.ok_or_else(||ApiError::domain("CHALLENGE_NOT_FOUND",404))?;
    if row.consumed.is_some() {
        return Err(ApiError::domain("CHALLENGE_CONSUMED", 409));
    }
    if row.expires_at <= http::now_iso() {
        return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
    }
    let owner = db
        .first::<Owner>(OWNER_SQL, &[json!(row.owner_key_id)])
        .await?
        .filter(|o| o.owner_user_id == row.owner_user_id && o.workspace_id == row.workspace_id)
        .ok_or_else(|| ApiError::domain("OWNER_VERIFICATION_FAILED", 403))?;
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&owner.public_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::domain("OWNER_VERIFICATION_FAILED", 403))?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&input.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::domain("OWNER_VERIFICATION_FAILED", 403))?;
    verify_ed25519(
        &public,
        &portable_signature_message(
            "ADMIN_PROVISIONING",
            &row.challenge_id,
            &row.challenge,
            &env.var("RP_ORIGIN")?.to_string(),
            &row.owner_key_id,
        ),
        &signature,
    )
    .map_err(|_| ApiError::domain("OWNER_VERIFICATION_FAILED", 403))?;
    for (sql, value, code) in [
        (
            "SELECT 1 AS n FROM password_credentials WHERE login_name=?1",
            &login,
            "LOGIN_NAME_TAKEN",
        ),
        (
            "SELECT 1 AS n FROM portable_key_credentials WHERE key_id=?1",
            &input.key_id,
            "KEY_ID_TAKEN",
        ),
    ] {
        if db.first::<Value>(sql, &[json!(value)]).await?.is_some() {
            return Err(ApiError::domain(code, 409));
        }
    }
    let credential = prepare_credential(&db, &row.owner_user_id, &input.master_password).await?;
    let now = http::now_iso();
    let user = http::random_id()?;
    let guard = http::random_id()?;
    let check = format!(
        "INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?2,CASE WHEN EXISTS(SELECT 1 FROM ({OWNER_SQL}) current_owner WHERE current_owner.owner_user_id=?3 AND current_owner.workspace_id=?4 AND current_owner.public_key=?5) AND EXISTS(SELECT 1 FROM admin_provisioning_challenges c WHERE c.challenge_id=?6 AND c.expires_at>?7 AND NOT EXISTS(SELECT 1 FROM admin_provisioning_challenge_consumptions x WHERE x.challenge_id=c.challenge_id)) THEN 1 ELSE 0 END"
    );
    let result=db.0.batch(vec![
        db.statement(&check,&[json!(row.owner_key_id),json!(guard),json!(row.owner_user_id),json!(row.workspace_id),json!(owner.public_key),json!(row.challenge_id),json!(now)])?,
        db.statement("INSERT INTO admin_provisioning_challenge_consumptions(challenge_id,consumed_at) VALUES(?1,?2)",&[json!(row.challenge_id),json!(now)])?,
        db.statement("INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES(?1,'ADMIN','ACTIVE',?2,?2)",&[json!(user),json!(now)])?,
        db.statement("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES(?1,?2,'ADMIN','ACTIVE',?3)",&[json!(row.workspace_id),json!(user),json!(now)])?,
        db.statement("INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_by_user_id,created_at) VALUES(?1,?2,'ADMIN',?3,?4,?5)",&[json!(row.workspace_id),json!(user),json!(login),json!(row.owner_user_id),json!(now)])?,
        db.statement("INSERT INTO portable_key_credentials(key_id,user_id,public_key,label,created_at,last_used_at) VALUES(?1,?2,?3,'Llave de administrador',?4,?4)",&[json!(input.key_id),json!(user),json!(input.public_key),json!(now)])?,
        db.statement("INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,failed_attempts,next_allowed_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,0,NULL,?7,?7)",&[json!(user),json!(login),json!(credential.algorithm),json!(credential.iterations),json!(credential.salt),json!(credential.verifier),json!(now)])?,
        db.statement("DELETE FROM auth_commit_guards WHERE assertion_id=?1",&[json!(guard)])?,
    ]).await;
    if let Err(error) = result {
        if db.first::<Value>("SELECT 1 AS n FROM admin_provisioning_challenge_consumptions WHERE challenge_id=?1",&[json!(row.challenge_id)]).await?.is_some(){return Err(ApiError::domain("CHALLENGE_CONSUMED",409));}
        if row.expires_at <= http::now_iso() {
            return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
        }
        for (sql, value, code) in [
            (
                "SELECT 1 AS n FROM password_credentials WHERE login_name=?1",
                &login,
                "LOGIN_NAME_TAKEN",
            ),
            (
                "SELECT 1 AS n FROM portable_key_credentials WHERE key_id=?1",
                &input.key_id,
                "KEY_ID_TAKEN",
            ),
        ] {
            if db.first::<Value>(sql, &[json!(value)]).await?.is_some() {
                return Err(ApiError::domain(code, 409));
            }
        }
        if db
            .first::<Owner>(OWNER_SQL, &[json!(row.owner_key_id)])
            .await?
            .is_none()
        {
            return Err(ApiError::domain("OWNER_VERIFICATION_FAILED", 403));
        }
        return Err(error.into());
    }
    http::json(
        &json!({"user_id":user,"workspace_id":row.workspace_id,"key_id":input.key_id,"role":"ADMIN"}),
    )
}
