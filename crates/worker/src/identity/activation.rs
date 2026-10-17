use super::*;
use crate::auth::sha256_hex;
use crate::auth_admission::{self, PasswordProof};
use crate::http::iso_at;
use crate::password::Device;
use ratchet_core::password::{Credential, verify_password_uniform};
use serde::Deserialize;
use worker::Date;
#[derive(Deserialize)]
struct Input {
    access_token: String,
    login_name: String,
    password: String,
    device: Device,
    proof: Option<PasswordProof>,
}
#[derive(Deserialize)]
struct Invitation {
    invitation_id: String,
    workspace_id: String,
    chat_id: String,
    customer_user_id: String,
    expires_at: Option<String>,
    status: String,
    revoked_at: Option<String>,
    login_name: String,
    user_status: String,
    #[serde(flatten)]
    credential: Credential,
}
pub async fn activate(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let input: Input = read_json(request, 65536).await?;
    if !(32..=512).contains(&input.access_token.len())
        || !(15..=256).contains(&input.password.encode_utf16().count())
        || input.login_name.trim().is_empty()
        || input.login_name.trim().encode_utf16().count() > 64
        || !matches!(&input.device, Device::New { .. })
    {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let (device, name, key) = input.device.fields()?;
    let db = Db(env.d1("DB")?);
    let login_name = auth_admission::normalize_login(&input.login_name)?;
    let invitation=db.first::<Invitation>("SELECT i.invitation_id,i.workspace_id,i.chat_id,i.customer_user_id,i.expires_at,i.status,i.revoked_at,pc.login_name,pc.algorithm,pc.iterations,pc.salt,pc.verifier,u.status AS user_status FROM invitations i JOIN users u ON u.user_id=i.customer_user_id JOIN password_credentials pc ON pc.user_id=i.customer_user_id WHERE i.token_hash=?1 AND i.kind='ACCESS' LIMIT 1",&[json!(sha256_hex(&input.access_token))]).await?;
    // An access token fixes the credential being verified. Rotating the submitted
    // login name must not rotate its admission identity or bypass its risk gate.
    let principal = invitation
        .as_ref()
        .map_or(login_name.as_str(), |i| i.login_name.as_str());
    let permit =
        auth_admission::reserve_login(&db, request, principal, input.proof.as_ref()).await?;
    let checked = permit.before_kdf().map(|()| {
        verify_password_uniform(&input.password, invitation.as_ref().map(|i| &i.credential))
    });
    permit.release(&db).await?;
    let valid = checked?;
    if !valid {
        crate::password::record_failure(
            &db,
            invitation.as_ref().map(|i| i.customer_user_id.as_str()),
            invitation.as_ref().map(|i| &i.credential),
        )
        .await?;
    }
    let i = invitation
        .filter(|i| {
            valid
                && ratchet_core::password::token_matches(
                    &i.login_name,
                    &input.login_name.trim().to_lowercase(),
                )
        })
        .ok_or_else(|| ApiError::domain("AUTHENTICATION_FAILED", 401))?;
    if i.revoked_at.is_some()
        || i.status != "ACTIVE"
        || !matches!(i.user_status.as_str(), "INVITED" | "ACTIVE")
    {
        return Err(ApiError::domain("INVITATION_USED", 410));
    }
    if i.expires_at
        .as_ref()
        .is_some_and(|s| worker::js_sys::Date::parse(s) <= Date::now().as_millis() as f64)
    {
        return Err(ApiError::domain("INVITATION_EXPIRED", 410));
    }
    if db
        .first::<Value>("SELECT 1 FROM devices WHERE device_id=?1", &[json!(device)])
        .await?
        .is_some()
    {
        return Err(ApiError::domain("DEVICE_ID_CONFLICT", 409));
    }
    let now = now_iso();
    let guard = random_id()?;
    let session = random_id()?;
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let secret = URL_SAFE_NO_PAD.encode(secret);
    let expires = iso_at(Date::now().as_millis() as f64 + 2592000000.0);
    db.0.batch(vec![
        db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM password_credentials p JOIN users u ON u.user_id=p.user_id JOIN invitations i ON i.customer_user_id=p.user_id WHERE p.user_id=?2 AND p.salt=?3 AND p.verifier=?4 AND p.algorithm=?7 AND p.iterations=?8 AND u.status IN ('INVITED','ACTIVE') AND i.invitation_id=?5 AND i.status='ACTIVE' AND i.revoked_at IS NULL AND i.expires_at>?6) THEN 1 ELSE 0 END",&[json!(guard),json!(i.customer_user_id),json!(i.credential.salt),json!(i.credential.verifier),json!(i.invitation_id),json!(now),json!(i.credential.algorithm),json!(i.credential.iterations)])?,
        db.statement("INSERT INTO invitation_claims(claim_id,invitation_id,user_id,chat_id,claimed_at) VALUES (?1,?2,?3,?4,?5)",&[json!(random_id()?),json!(i.invitation_id),json!(i.customer_user_id),json!(i.chat_id),json!(now)])?,
        db.statement("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES (?1,?2,?3,?4,?5,?5,?5)",&[json!(device),json!(i.customer_user_id),json!(name),json!(key),json!(now)])?,
        db.statement("UPDATE users SET status='ACTIVE',activated_at=COALESCE(activated_at,?2) WHERE user_id=?1 AND status='INVITED'",&[json!(i.customer_user_id),json!(now)])?,
        db.statement("UPDATE workspace_memberships SET status='ACTIVE' WHERE workspace_id=?1 AND user_id=?2 AND role='CUSTOMER' AND status='PENDING'",&[json!(i.workspace_id),json!(i.customer_user_id)])?,
        db.statement("UPDATE invitations SET status='CLAIMED',claimed_at=?2 WHERE invitation_id=?1 AND status='ACTIVE'",&[json!(i.invitation_id),json!(now)])?,
        db.statement("UPDATE password_credentials SET failed_attempts=0,next_allowed_at=NULL WHERE user_id=?1",&[json!(i.customer_user_id)])?,
        db.statement("INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at,webauthn_verified_at,authenticator_verified_at) VALUES (?1,?2,?3,?4,?5,?5,?6,NULL,?5)",&[json!(session),json!(sha256_hex(&secret)),json!(i.customer_user_id),json!(device),json!(now),json!(expires)])?,
        db.statement("DELETE FROM auth_commit_guards WHERE assertion_id=?1",&[json!(guard)])?
    ]).await.map_err(|_|ApiError::domain("REGISTRATION_CONFLICT",409))?;
    let mut response=json(&json!({"session_id":session,"user_id":i.customer_user_id,"device_id":device,"device_state":"AUTHORIZED"}))?.with_status(201);
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "__Host-session={secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000"
        ),
    )?;
    Ok(response)
}
