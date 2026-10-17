use crate::{
    db::Db,
    http::{ApiError, ApiResult, iso_at, json, now_iso, random_id, read_json},
    password::prepare_credential,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::is_uuid,
    password::token_matches,
    signatures::{portable_signature_message, verify_ed25519},
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{Date, Env, Request, Response};

#[derive(Deserialize)]
struct Prepare {
    bootstrap_token: String,
    key_id: String,
    public_key: String,
}
#[derive(Deserialize)]
struct Complete {
    bootstrap_token: String,
    challenge_id: String,
    signature: String,
    login_name: String,
    master_password: String,
}
#[derive(Deserialize)]
struct Challenge {
    challenge_id: String,
    challenge: String,
    key_id: String,
    public_key: String,
    user_id: String,
    workspace_id: String,
    expires_at: String,
    consumed: Option<String>,
}

async fn completed(db: &Db) -> ApiResult<bool> {
    Ok(db
        .first::<Value>(
            "SELECT 1 FROM installation_bootstrap WHERE singleton=1",
            &[],
        )
        .await?
        .is_some())
}

pub(crate) fn require_token(env: &Env, provided: &str) -> ApiResult<()> {
    let token = env
        .secret("BOOTSTRAP_TOKEN")
        .map(|s| s.to_string())
        .unwrap_or_default();
    if token.len() < 32 {
        return Err(ApiError::domain("BOOTSTRAP_NOT_CONFIGURED", 503));
    }
    if !(32..=512).contains(&provided.len()) {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    if !token_matches(&token, provided) {
        return Err(ApiError::domain("BOOTSTRAP_FORBIDDEN", 403));
    }
    Ok(())
}

pub async fn status(env: &Env) -> ApiResult<Response> {
    let configured = env
        .secret("BOOTSTRAP_TOKEN")
        .map(|s| s.to_string().len() >= 32)
        .unwrap_or(false);
    let available = configured && !completed(&Db(env.d1("DB")?)).await?;
    json(&json!({"configured":configured,"available":available}))
}

pub async fn prepare(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let input: Prepare = read_json(request, 64 * 1024).await?;
    require_token(env, &input.bootstrap_token)?;
    if !is_uuid(&input.key_id)
        || input.public_key.len() != 43
        || URL_SAFE_NO_PAD
            .decode(&input.public_key)
            .map(|v| v.len() != 32)
            .unwrap_or(true)
    {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    if completed(&db).await? {
        return Err(ApiError::domain("BOOTSTRAP_COMPLETED", 410));
    }
    let id = random_id()?;
    let user = random_id()?;
    let workspace = random_id()?;
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let challenge = URL_SAFE_NO_PAD.encode(challenge);
    let now = now_iso();
    let expires = iso_at(Date::now().as_millis() as f64 + 5.0 * 60.0 * 1000.0);
    let admission =
        crate::auth_admission::challenge_statement(&db, request, None, &input.key_id).await?;
    db.0.batch(vec![admission,db.statement("INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,public_key,user_id,workspace_id,created_at,expires_at,admission_origin) VALUES (?1,'BOOTSTRAP',?2,?3,?4,?5,?6,?7,?8,?9)",&[json!(id),json!(challenge),json!(input.key_id),json!(input.public_key),json!(user),json!(workspace),json!(now),json!(expires),json!(crate::auth_admission::origin_hash(request)?)])?]).await.map_err(crate::auth_admission::admission_error)?;
    json(
        &json!({"challenge_id":id,"challenge":challenge,"purpose":"BOOTSTRAP","key_id":input.key_id,"origin":env.var("RP_ORIGIN")?.to_string()}),
    )
}

pub async fn complete(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let input: Complete = read_json(request, 64 * 1024).await?;
    require_token(env, &input.bootstrap_token)?;
    let login = input.login_name.trim().to_lowercase();
    if !is_uuid(&input.challenge_id)
        || !(3..=64).contains(&login.len())
        || !login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || input.signature.len() != 86
    {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    if completed(&db).await? {
        return Err(ApiError::domain("BOOTSTRAP_COMPLETED", 410));
    }
    let row=db.first::<Challenge>("SELECT c.challenge_id,c.challenge,c.key_id,c.public_key,c.user_id,c.workspace_id,c.expires_at,x.challenge_id AS consumed FROM portable_key_challenges c LEFT JOIN portable_key_challenge_consumptions x ON x.challenge_id=c.challenge_id WHERE c.challenge_id=?1 AND c.kind='BOOTSTRAP'",&[json!(input.challenge_id)]).await?
        .ok_or_else(||ApiError::domain("CHALLENGE_NOT_FOUND",404))?;
    if row.consumed.is_some() {
        return Err(ApiError::domain("CHALLENGE_CONSUMED", 409));
    }
    if row.expires_at <= now_iso() {
        return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
    }
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&row.public_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::domain("PORTABLE_KEY_VERIFICATION_FAILED", 403))?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&input.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::domain("PORTABLE_KEY_VERIFICATION_FAILED", 403))?;
    verify_ed25519(
        &public,
        &portable_signature_message(
            "BOOTSTRAP",
            &row.challenge_id,
            &row.challenge,
            &env.var("RP_ORIGIN")?.to_string(),
            &row.key_id,
        ),
        &signature,
    )?;
    let password = prepare_credential(&db, &row.user_id, &input.master_password).await?;
    let now = now_iso();
    let guard = random_id()?;
    let result=db.0.batch(vec![
        db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM portable_key_challenges c WHERE c.challenge_id=?2 AND c.kind='BOOTSTRAP' AND c.public_key=?3 AND c.expires_at>?4 AND NOT EXISTS(SELECT 1 FROM portable_key_challenge_consumptions x WHERE x.challenge_id=c.challenge_id)) AND NOT EXISTS(SELECT 1 FROM installation_bootstrap WHERE singleton=1) THEN 1 ELSE 0 END",&[json!(guard),json!(row.challenge_id),json!(row.public_key),json!(now)])?,
        db.statement("INSERT INTO portable_key_challenge_consumptions(challenge_id,consumed_at) VALUES(?1,?2)",&[json!(row.challenge_id),json!(now)])?,
        db.statement("INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES(?1,'ADMIN','ACTIVE',?2,?2)",&[json!(row.user_id),json!(now)])?,
        db.statement("INSERT INTO workspaces(workspace_id,name,created_at) VALUES(?1,'Ratchet',?2)",&[json!(row.workspace_id),json!(now)])?,
        db.statement("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES(?1,?2,'ADMIN','ACTIVE',?3)",&[json!(row.workspace_id),json!(row.user_id),json!(now)])?,
        db.statement("INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_by_user_id,created_at) VALUES(?1,?2,'OWNER',?3,NULL,?4)",&[json!(row.workspace_id),json!(row.user_id),json!(login),json!(now)])?,
        db.statement("INSERT INTO portable_key_credentials(key_id,user_id,public_key,label,created_at,last_used_at) VALUES(?1,?2,?3,'Llave principal',?4,?4)",&[json!(row.key_id),json!(row.user_id),json!(row.public_key),json!(now)])?,
        db.statement("INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,failed_attempts,next_allowed_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,0,NULL,?7,?7)",&[json!(row.user_id),json!(login),json!(password.algorithm),json!(password.iterations),json!(password.salt),json!(password.verifier),json!(now)])?,
        db.statement("INSERT INTO installation_bootstrap(singleton,user_id,workspace_id,completed_at) VALUES(1,?1,?2,?3)",&[json!(row.user_id),json!(row.workspace_id),json!(now)])?,
        db.statement("DELETE FROM auth_commit_guards WHERE assertion_id=?1",&[json!(guard)])?
    ]).await;
    if let Err(error) = result {
        if completed(&db).await? {
            return Err(ApiError::domain("BOOTSTRAP_COMPLETED", 409));
        }
        if row.expires_at <= now_iso() {
            return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
        }
        return Err(error.into());
    }
    json(&json!({"user_id":row.user_id,"workspace_id":row.workspace_id,"key_id":row.key_id}))
}
