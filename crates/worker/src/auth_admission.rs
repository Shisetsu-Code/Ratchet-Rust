//! Bounded, global authentication admission; all counters live in D1.
//!
//! The INSERT trigger reserves all rate/concurrency budgets atomically. A
//! released lease still counts against its rate window. The runtime CPU limit
//! must stay <=30 seconds: a KDF starts only with >=30 seconds on its 120s lease.
use crate::{
    auth::{AuthContext, sha256_hex},
    db::Db,
    http::{self, ApiError, ApiResult},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::message::is_uuid;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use worker::{D1PreparedStatement, Date, Env, Request, Response};

const CLEANUP_BATCH: u32 = 64;
// Start at the lowest supported cost for mobile clients. The strict server
// budgets remain authoritative; proof-of-work only raises repeated-attempt cost.
const PROOF_DIFFICULTY: u8 = 18;

pub fn now_seconds() -> u64 {
    Date::now().as_millis() / 1000
}

pub fn origin_hash(request: &Request) -> ApiResult<String> {
    let origin = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "local-network".into());
    Ok(sha256_hex(&format!("auth-origin-v1:{origin}")))
}

pub fn normalize_login(value: &str) -> ApiResult<String> {
    let value = value.trim().to_lowercase();
    if value.is_empty() || value.encode_utf16().count() > 64 {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    Ok(value)
}

pub fn admission_error(error: worker::Error) -> ApiError {
    let message = error.to_string();
    if message.contains("auth_proof_required") {
        ApiError::domain("AUTHENTICATION_PROOF_REQUIRED", 429)
    } else if message.contains("auth_rate_limited") || message.contains("auth_challenge_capacity") {
        ApiError::domain("RATE_LIMITED", 429)
    } else {
        error.into()
    }
}

pub struct Permit {
    id: String,
    issued_at: u64,
}
impl Permit {
    pub fn before_kdf(&self) -> ApiResult<()> {
        if now_seconds() > self.issued_at.saturating_add(90) {
            return Err(ApiError::domain("RATE_LIMITED", 429));
        }
        Ok(())
    }
    pub async fn release(self, db: &Db) -> ApiResult<()> {
        db.run("UPDATE auth_admission_permits SET released_at=COALESCE(released_at,?2) WHERE permit_id=?1", &[json!(self.id),json!(now_seconds())]).await?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordProof {
    challenge_id: String,
    solution: u32,
}

#[derive(Deserialize)]
struct ProofRow {
    challenge_id: String,
    challenge: String,
    difficulty: u8,
    expires_at: u64,
}

fn proof_matches(challenge: &str, solution: u32, difficulty: u8) -> bool {
    if !(18..=22).contains(&difficulty) {
        return false;
    }
    let digest =
        Sha256::digest(format!("ratchet-auth-work-v1\n{challenge}\n{solution}").as_bytes());
    let full = usize::from(difficulty / 8);
    let remaining = difficulty % 8;
    digest[..full].iter().all(|byte| *byte == 0)
        && (remaining == 0 || digest[full] >> (8 - remaining) == 0)
}

fn permit_statement(
    db: &Db,
    scope: &str,
    origin: &str,
    principal: &str,
    proof: Option<&str>,
    active: bool,
) -> ApiResult<(Permit, D1PreparedStatement)> {
    let id = http::random_id()?;
    let now = now_seconds();
    let statement = db.statement("INSERT INTO auth_admission_permits(permit_id,scope,origin_hash,principal_hash,issued_at,leased_until,released_at,proof_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", &[
        json!(id), json!(scope),json!(origin),json!(sha256_hex(&format!("auth-principal-v1:{principal}"))),
        json!(now),json!(if active { now+120 } else { now }),json!(if active { None } else { Some(now) }),json!(proof),
    ])?;
    Ok((Permit { id, issued_at: now }, statement))
}

async fn prune_admission(db: &Db) -> ApiResult<()> {
    let now = now_seconds();
    db.0.batch(vec![
        db.statement("DELETE FROM auth_admission_permits WHERE permit_id IN (SELECT permit_id FROM auth_admission_permits WHERE issued_at<=?1 AND (released_at IS NOT NULL OR leased_until<=?2) ORDER BY issued_at LIMIT 256)", &[json!(now.saturating_sub(600)),json!(now)])?,
        db.statement("DELETE FROM auth_password_proofs WHERE challenge_id IN (SELECT challenge_id FROM auth_password_proofs WHERE expires_at<=?1 ORDER BY expires_at LIMIT 128)", &[json!(now)])?,
    ]).await?;
    Ok(())
}

pub async fn reserve_login(
    db: &Db,
    request: &Request,
    login: &str,
    proof: Option<&PasswordProof>,
) -> ApiResult<Permit> {
    prune_admission(db).await?;
    let origin = origin_hash(request)?;
    let mut verified_proof = None;
    if let Some(proof) = proof {
        if !is_uuid(&proof.challenge_id) {
            return Err(ApiError::domain("AUTHENTICATION_PROOF_REQUIRED", 429));
        }
        let row = db.first::<ProofRow>("SELECT challenge_id,challenge,difficulty,expires_at FROM auth_password_proofs WHERE challenge_id=?1 AND origin_hash=?2 AND principal_hash=?3 AND consumed_at IS NULL AND expires_at>?4", &[
            json!(proof.challenge_id),json!(origin),json!(sha256_hex(&format!("auth-principal-v1:{login}"))),json!(now_seconds()),
        ]).await?;
        if row.is_none_or(|row| !proof_matches(&row.challenge, proof.solution, row.difficulty)) {
            return Err(ApiError::domain("AUTHENTICATION_PROOF_REQUIRED", 429));
        }
        verified_proof = Some(proof.challenge_id.as_str());
    }
    let (permit, statement) =
        permit_statement(db, "password_login", &origin, login, verified_proof, true)?;
    statement.run().await.map_err(admission_error)?;
    Ok(permit)
}

// AuthContext is produced only after the session/device/user checks. Neither a
// supplied cookie nor a supplied device ID can choose this reserved pool.
pub async fn reserve_reauth(db: &Db, request: &Request, auth: &AuthContext) -> ApiResult<Permit> {
    crate::auth::require_authorized(auth)?;
    prune_admission(db).await?;
    let (permit, statement) = permit_statement(
        db,
        "password_reauth",
        &origin_hash(request)?,
        &auth.user_id,
        None,
        true,
    )?;
    statement.run().await.map_err(admission_error)?;
    Ok(permit)
}

// Callers have already validated their invitation/owner signature or authorized
// administrator action. Credential creation has a separate fixed total budget.
pub async fn reserve_write(db: &Db, principal: &str) -> ApiResult<Permit> {
    prune_admission(db).await?;
    let (permit, statement) = permit_statement(
        db,
        "password_write",
        &sha256_hex("authorized-password-write"),
        principal,
        None,
        true,
    )?;
    statement.run().await.map_err(admission_error)?;
    Ok(permit)
}

pub async fn password_challenge(request: &mut Request, env: &Env) -> ApiResult<Response> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        login_name: String,
    }
    let input: Input = http::read_json(request, 1024).await?;
    let login = normalize_login(&input.login_name)?;
    let db = Db(env.d1("DB")?);
    prune_admission(&db).await?;
    let origin = origin_hash(request)?;
    let principal = sha256_hex(&format!("auth-principal-v1:{login}"));
    let (_, statement) = permit_statement(&db, "password_proof", &origin, &login, None, false)?;
    statement.run().await.map_err(admission_error)?;
    let now = now_seconds();
    // Repeated requests reuse their unconsumed challenge instead of accumulating
    // rows. The trigger is still the authority for concurrent distinct requests.
    let existing = db.first::<ProofRow>("SELECT challenge_id,challenge,difficulty,expires_at FROM auth_password_proofs WHERE origin_hash=?1 AND principal_hash=?2 AND consumed_at IS NULL AND expires_at>?3 ORDER BY created_at DESC LIMIT 1", &[json!(origin),json!(principal),json!(now+30)]).await?;
    let row = if let Some(row) = existing {
        row
    } else {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
        let row = ProofRow {
            challenge_id: http::random_id()?,
            challenge: URL_SAFE_NO_PAD.encode(nonce),
            difficulty: PROOF_DIFFICULTY,
            expires_at: now + 120,
        };
        db.statement("INSERT INTO auth_password_proofs(challenge_id,challenge,origin_hash,principal_hash,difficulty,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)", &[json!(row.challenge_id),json!(row.challenge),json!(origin),json!(principal),json!(row.difficulty),json!(now),json!(row.expires_at)])?.run().await.map_err(admission_error)?;
        row
    };
    http::json(
        &json!({"protocol":"ratchet-auth-work-v1","challenge_id":row.challenge_id,"challenge":row.challenge,"difficulty":row.difficulty,"expires_at":row.expires_at}),
    )
}

pub async fn challenge_statement(
    db: &Db,
    request: &Request,
    auth: Option<&AuthContext>,
    principal: &str,
) -> ApiResult<D1PreparedStatement> {
    cleanup_challenges(db, CLEANUP_BATCH).await?;
    prune_admission(db).await?;
    let (scope, principal) = if let Some(auth) = auth {
        crate::auth::require_authorized(auth)?;
        ("challenge_reauth", auth.user_id.as_str())
    } else {
        ("challenge_public", principal)
    };
    Ok(permit_statement(db, scope, &origin_hash(request)?, principal, None, false)?.1)
}

async fn cleanup_challenges(db: &Db, limit: u32) -> ApiResult<()> {
    let parameters = [json!(http::now_iso()), json!(limit)];
    let statements = include_str!("auth-challenges-cleanup.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
        .map(|sql| db.statement(sql, &parameters))
        .collect::<ApiResult<Vec<_>>>()?;
    // The same expired set is removed child-first in one transaction. Deleting
    // consumption markers for live parents would reopen single-use assertions.
    db.0.batch(statements).await?;
    Ok(())
}

pub async fn maintenance(env: &Env) -> ApiResult<()> {
    let db = Db(env.d1("DB")?);
    cleanup_challenges(&db, 512).await?;
    prune_admission(&db).await?;
    // Legacy failure state is observation only, with a finite lifetime.
    db.run("UPDATE password_credentials SET failed_attempts=0,next_allowed_at=NULL WHERE user_id IN (SELECT user_id FROM password_credentials WHERE failed_attempts>0 AND updated_at<?1 ORDER BY updated_at LIMIT 256)", &[json!(http::iso_at(Date::now().as_millis() as f64-900_000.0))]).await?;
    Ok(())
}
