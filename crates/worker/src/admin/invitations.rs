use super::*;
pub async fn prepare(
    db: &Db,
    auth: &AuthContext,
    op: &str,
    target: &str,
    data: &Value,
) -> ApiResult<MutationPlan> {
    if op == "admin.invitation.referral_claim" {
        return referral(db, auth, target).await;
    }
    if op != "admin.invitation.create" {
        return Err(ApiError::domain("NOT_FOUND", 404));
    }
    let workspace = id(target)?;
    let kind = string(data, "kind")?;
    if !matches!(kind, "ACCESS" | "REFERRAL") {
        return Err(invalid());
    }
    staff(db, workspace, &auth.user_id, kind == "ACCESS").await?;
    let token = token()?;
    let invitation = http::random_id()?;
    let now = http::now_iso();
    let mut p = plan(
        json!({"invitation_id":invitation,"kind":kind,"token":token,"expires_at":null,"customer_user_id":null,"chat_id":null,"login_name":null}),
        201,
    );
    p.statements
        .push(staff_guard(db, workspace, &auth.user_id, kind == "ACCESS")?);
    if kind == "REFERRAL" {
        p.statements.push(db.statement("INSERT INTO invitations(invitation_id,kind,workspace_id,token_hash,created_by_user_id,status,created_at) VALUES(?1,'REFERRAL',?2,?3,?4,'ACTIVE',?5)",&[json!(invitation),json!(workspace),json!(auth::sha256_hex(&token)),json!(auth.user_id),json!(now)])?);
        return Ok(p);
    }
    let name = login(data)?;
    unique_login(db, &name, "").await?;
    let user = http::random_id()?;
    let chat = http::random_id()?;
    let expiry = expires(1.0);
    p.statements.push(db.statement(
        "INSERT INTO users(user_id,role,status,created_at) VALUES(?1,'CUSTOMER','INVITED',?2)",
        &[json!(user), json!(now)],
    )?);
    p.statements
        .push(insert_credential(db, &user, &name, string(data, "password")?, &now).await?);
    p.statements.push(db.statement("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES(?1,?2,'CUSTOMER','PENDING',?3)",&[json!(workspace),json!(user),json!(now)])?);
    p.statements.extend(chat_statements(
        db,
        &chat,
        workspace,
        &auth.user_id,
        &user,
        &now,
    )?);
    p.statements.push(db.statement("INSERT INTO invitations(invitation_id,kind,workspace_id,chat_id,customer_user_id,token_hash,created_by_user_id,expires_at,status,created_at) VALUES(?1,'ACCESS',?2,?3,?4,?5,?6,?7,'ACTIVE',?8)",&[json!(invitation),json!(workspace),json!(chat),json!(user),json!(auth::sha256_hex(&token)),json!(auth.user_id),json!(expiry),json!(now)])?);
    p.response = json!({"invitation_id":invitation,"kind":kind,"token":token,"expires_at":expiry,"customer_user_id":user,"chat_id":chat,"login_name":name});
    Ok(p)
}
async fn referral(db: &Db, auth: &AuthContext, token: &str) -> ApiResult<MutationPlan> {
    if auth.role != "CUSTOMER" {
        return Err(ApiError::domain("CUSTOMER_REQUIRED", 403));
    }
    if !(32..=512).contains(&token.len()) {
        return Err(invalid());
    }
    let row = db
        .first::<Value>(
            "SELECT * FROM invitations WHERE token_hash=?1",
            &[json!(auth::sha256_hex(token))],
        )
        .await?
        .ok_or_else(|| ApiError::domain("INVITATION_NOT_FOUND", 404))?;
    if row["kind"] != "REFERRAL" {
        return Err(ApiError::domain("ACCESS_REQUIRES_REGISTRATION", 409));
    }
    if row["status"] != "ACTIVE" || !row["revoked_at"].is_null() {
        return Err(ApiError::domain("INVITATION_REVOKED", 410));
    }
    let now = http::now_iso();
    if row["expires_at"]
        .as_str()
        .is_some_and(|e| e <= now.as_str())
    {
        return Err(ApiError::domain("INVITATION_EXPIRED", 410));
    }
    let workspace = string(&row, "workspace_id")?;
    let issuer = string(&row, "created_by_user_id")?;
    let invitation = string(&row, "invitation_id")?;
    staff(db, workspace, issuer, false)
        .await
        .map_err(|_| ApiError::domain("INVITATION_OWNER_INACTIVE", 410))?;
    if let Some(prior) = db
        .first::<Value>(
            "SELECT chat_id FROM invitation_claims WHERE invitation_id=?1 AND user_id=?2",
            &[json!(invitation), json!(auth.user_id)],
        )
        .await?
    {
        return Ok(plan(
            json!({"invitation_id":invitation,"workspace_id":workspace,"chat_id":prior["chat_id"],"duplicate":true}),
            200,
        ));
    }
    // A revoked membership is not resurrected by an old referral link.
    if db.first::<Value>("SELECT 1 FROM workspace_memberships WHERE workspace_id=?1 AND user_id=?2 AND(role<>'CUSTOMER' OR status='REVOKED' OR revoked_at IS NOT NULL)",&[json!(workspace),json!(auth.user_id)]).await?.is_some(){return Err(ApiError::domain("INVITATION_REVOKED",410))}
    let chat = http::random_id()?;
    let mut p = plan(
        json!({"invitation_id":invitation,"workspace_id":workspace,"chat_id":chat,"duplicate":false}),
        200,
    );
    p.affected_users.push(auth.user_id.clone());
    p.statements
        .push(staff_guard(db, workspace, issuer, false)?);
    p.statements.push(guard(db,"EXISTS(SELECT 1 FROM invitations WHERE invitation_id=?1 AND kind='REFERRAL' AND status='ACTIVE' AND revoked_at IS NULL AND(expires_at IS NULL OR expires_at>?2)) AND NOT EXISTS(SELECT 1 FROM workspace_memberships WHERE workspace_id=?3 AND user_id=?4 AND(role<>'CUSTOMER' OR status='REVOKED' OR revoked_at IS NOT NULL))",&[json!(invitation),json!(now),json!(workspace),json!(auth.user_id)])?);
    p.statements.push(db.statement("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES(?1,?2,'CUSTOMER','ACTIVE',?3) ON CONFLICT(workspace_id,user_id) DO UPDATE SET status='ACTIVE' WHERE role='CUSTOMER' AND revoked_at IS NULL AND status<>'REVOKED'",&[json!(workspace),json!(auth.user_id),json!(now)])?);
    p.statements.extend(chat_statements(
        db,
        &chat,
        workspace,
        issuer,
        &auth.user_id,
        &now,
    )?);
    p.statements.push(db.statement("INSERT INTO invitation_claims(claim_id,invitation_id,user_id,chat_id,claimed_at) VALUES(?1,?2,?3,?4,?5)",&[json!(http::random_id()?),json!(invitation),json!(auth.user_id),json!(chat),json!(now)])?);
    Ok(p)
}
