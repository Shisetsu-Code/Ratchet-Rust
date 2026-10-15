use super::*;
pub async fn list(
    request: &Request,
    env: &Env,
    auth: &AuthContext,
    parts: &[&str],
) -> ApiResult<Response> {
    let db = Db(env.d1("DB")?);
    let workspace = request
        .url()?
        .query_pairs()
        .find(|(k, _)| k == "workspace_id")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(invalid)?;
    id(&workspace)?;
    staff(&db, &workspace, &auth.user_id, true).await?;
    if parts.len() == 3 {
        let operators=db.all("SELECT ws.user_id,ws.workspace_id,ws.staff_role,ws.display_name,ws.created_at,ws.revoked_at,NULL AS login_name,'LINK' AS access_mode,COUNT(DISTINCT CASE WHEN d.authorized_at IS NOT NULL AND d.revoked_at IS NULL THEN d.device_id END) AS active_device_count,COUNT(DISTINCT CASE WHEN g.claimed_at IS NULL AND g.revoked_at IS NULL AND g.expires_at>?3 THEN g.grant_id END) AS pending_access_grant_count,MAX(CASE WHEN d.revoked_at IS NULL THEN d.last_seen_at END) AS last_seen_at FROM workspace_staff ws LEFT JOIN devices d ON d.user_id=ws.user_id LEFT JOIN operator_access_grants g ON g.workspace_id=ws.workspace_id AND g.operator_user_id=ws.user_id WHERE ws.workspace_id=?1 AND (ws.user_id=?2 OR(ws.staff_role='OPERATOR' AND ws.created_by_user_id=?2)) GROUP BY ws.user_id,ws.workspace_id ORDER BY CASE ws.staff_role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END,ws.created_at,ws.user_id",&[json!(workspace),json!(auth.user_id),json!(http::now_iso())]).await?;
        return http::json(
            &json!({"workspace_id":workspace,"can_manage":true,"operators":operators}),
        );
    }
    if parts.len() == 5 && parts[4] == "access-grants" {
        id(parts[3])?;
        managed(&db, &workspace, parts[3], &auth.user_id).await?;
        let grants=db.all("SELECT grant_id,workspace_id,operator_user_id,created_at,expires_at,claimed_at,claimed_device_id,revoked_at FROM operator_access_grants WHERE workspace_id=?1 AND operator_user_id=?2 ORDER BY created_at DESC,grant_id DESC LIMIT 50",&[json!(workspace),json!(parts[3])]).await?;
        return http::json(&json!({"grants":grants}));
    }
    Err(ApiError::domain("NOT_FOUND", 404))
}
async fn managed(db: &Db, workspace: &str, user: &str, issuer: &str) -> ApiResult<Value> {
    db.first::<Value>("SELECT ws.*,u.status AS user_status,wm.status AS membership_status,wm.revoked_at AS membership_revoked_at FROM workspace_staff ws JOIN users u ON u.user_id=ws.user_id JOIN workspace_memberships wm ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id WHERE ws.workspace_id=?1 AND ws.user_id=?2 AND ws.created_by_user_id=?3 AND ws.staff_role='OPERATOR'",&[json!(workspace),json!(user),json!(issuer)]).await?.ok_or_else(||ApiError::domain("OPERATOR_NOT_FOUND",404))
}
pub async fn prepare(
    db: &Db,
    auth: &AuthContext,
    op: &str,
    target: &str,
    data: &Value,
) -> ApiResult<MutationPlan> {
    let workspace = if op == "admin.operator.create" {
        id(target)?
    } else {
        id(string(data, "workspace_id")?)?
    };
    staff(db, workspace, &auth.user_id, true).await?;
    let now = http::now_iso();
    let mut p = plan(Value::Null, 204);
    p.statements
        .push(staff_guard(db, workspace, &auth.user_id, true)?);
    if op == "admin.operator.create" {
        let name = text(data, "display_name", 1, 80)?;
        let user = http::random_id()?;
        p.status = 201;
        p.response = json!({"user_id":user,"workspace_id":workspace,"staff_role":"OPERATOR","display_name":name,"login_name":null,"access_mode":"LINK","created_at":now,"revoked_at":null,"active_device_count":0,"pending_access_grant_count":0,"last_seen_at":null});
        p.statements.extend([
 db.statement("INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES(?1,'ADMIN','ACTIVE',?2,?2)",&[json!(user),json!(now)])?,
 db.statement("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES(?1,?2,'ADMIN','ACTIVE',?3)",&[json!(workspace),json!(user),json!(now)])?,
 db.statement("INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_by_user_id,created_at) VALUES(?1,?2,'OPERATOR',?3,?4,?5)",&[json!(workspace),json!(user),json!(name),json!(auth.user_id),json!(now)])?,
 db.statement("INSERT INTO workspace_audit_events(event_id,workspace_id,actor_user_id,subject_user_id,event_type,created_at) VALUES(?1,?2,?3,?4,'OPERATOR_CREATED',?5)",&[json!(http::random_id()?),json!(workspace),json!(auth.user_id),json!(user),json!(now)])?]);
        return Ok(p);
    }
    id(target)?;
    if op == "admin.operator.revoke" && target == auth.user_id {
        return Err(ApiError::domain("ADMIN_SELF_REVOKE_FORBIDDEN", 409));
    }
    let row = managed(db, workspace, target, &auth.user_id).await?;
    p.statements.push(guard(db,"EXISTS(SELECT 1 FROM workspace_staff WHERE workspace_id=?1 AND user_id=?2 AND created_by_user_id=?3 AND staff_role='OPERATOR')",&[json!(workspace),json!(target),json!(auth.user_id)])?);
    match op {
        "admin.operator.grant" => {
            if !row["revoked_at"].is_null()
                || row["user_status"] != "ACTIVE"
                || row["membership_status"] != "ACTIVE"
                || !row["membership_revoked_at"].is_null()
            {
                return Err(ApiError::domain("OPERATOR_INACTIVE", 409));
            }
            let token = token()?;
            let grant = http::random_id()?;
            let expiry = expires(1.0 / 3.0);
            p.status = 201;
            p.response = json!({"grant_id":grant,"workspace_id":workspace,"operator_user_id":target,"token":token,"created_at":now,"expires_at":expiry,"claimed_at":null,"claimed_device_id":null,"revoked_at":null});
            p.statements.push(guard(db,"EXISTS(SELECT 1 FROM workspace_staff ws JOIN users u ON u.user_id=ws.user_id JOIN workspace_memberships wm ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id WHERE ws.workspace_id=?1 AND ws.user_id=?2 AND ws.revoked_at IS NULL AND u.status='ACTIVE' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL)",&[json!(workspace),json!(target)])?);
            p.statements.push(db.statement("INSERT INTO operator_access_grants(grant_id,workspace_id,operator_user_id,token_hash,created_by_user_id,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",&[json!(grant),json!(workspace),json!(target),json!(auth::sha256_hex(&token)),json!(auth.user_id),json!(now),json!(expiry)])?);
        }
        "admin.operator.grant_revoke" => {
            let grant = id(string(data, "grant_id")?)?;
            let row=db.first::<Value>("SELECT claimed_at,revoked_at FROM operator_access_grants WHERE grant_id=?1 AND workspace_id=?2 AND operator_user_id=?3",&[json!(grant),json!(workspace),json!(target)]).await?.ok_or_else(||ApiError::domain("AGENT_ACCESS_NOT_FOUND",404))?;
            if !row["claimed_at"].is_null() {
                return Err(ApiError::domain("AGENT_ACCESS_ALREADY_USED", 409));
            }
            p.statements.push(guard(db,"EXISTS(SELECT 1 FROM operator_access_grants WHERE grant_id=?1 AND workspace_id=?2 AND operator_user_id=?3 AND claimed_at IS NULL)",&[json!(grant),json!(workspace),json!(target)])?);
            p.statements.push(db.statement("UPDATE operator_access_grants SET revoked_at=COALESCE(revoked_at,?4) WHERE grant_id=?1 AND workspace_id=?2 AND operator_user_id=?3 AND claimed_at IS NULL",&[json!(grant),json!(workspace),json!(target),json!(now)])?);
        }
        "admin.operator.revoke" => {
            p.affected_users.push(target.into());
            if !row["revoked_at"].is_null() {
                return Ok(p);
            }
            p.statements.extend([
 db.statement("INSERT INTO workspace_audit_events(event_id,workspace_id,actor_user_id,subject_user_id,event_type,created_at) VALUES(?1,?2,?3,?4,'OPERATOR_REVOKED',?5)",&[json!(http::random_id()?),json!(workspace),json!(auth.user_id),json!(target),json!(now)])?,
 db.statement("UPDATE operator_access_grants SET revoked_at=COALESCE(revoked_at,?3) WHERE workspace_id=?1 AND operator_user_id=?2 AND claimed_at IS NULL",&[json!(workspace),json!(target),json!(now)])?,
 db.statement("UPDATE workspace_staff SET revoked_at=?3 WHERE workspace_id=?1 AND user_id=?2 AND revoked_at IS NULL",&[json!(workspace),json!(target),json!(now)])?,
 db.statement("UPDATE workspace_memberships SET status='REVOKED',revoked_at=?3 WHERE workspace_id=?1 AND user_id=?2",&[json!(workspace),json!(target),json!(now)])?]);
            let inactive = "NOT EXISTS(SELECT 1 FROM workspace_memberships WHERE user_id=?1 AND role='ADMIN' AND status='ACTIVE' AND revoked_at IS NULL)";
            p.statements.push(db.statement(
                &format!("UPDATE users SET status='SUSPENDED' WHERE user_id=?1 AND {inactive}"),
                &[json!(target)],
            )?);
            for table in ["sessions", "devices", "push_subscriptions"] {
                p.statements.push(db.statement(&format!("UPDATE {table} SET revoked_at=COALESCE(revoked_at,?2) WHERE user_id=?1 AND {inactive}"),&[json!(target),json!(now)])?)
            }
            p.statements.push(db.statement(&format!("DELETE FROM device_prekey_bundles WHERE device_id IN(SELECT device_id FROM devices WHERE user_id=?1) AND {inactive}"),&[json!(target)])?);
            for (table, column) in [
                ("one_time_prekeys", "consumed_at"),
                ("device_certificates", "revoked_at"),
            ] {
                p.statements.push(db.statement(&format!("UPDATE {table} SET {column}=COALESCE({column},?2) WHERE device_id IN(SELECT device_id FROM devices WHERE user_id=?1) AND {inactive}"),&[json!(target),json!(now)])?)
            }
        }
        _ => return Err(ApiError::domain("NOT_FOUND", 404)),
    }
    Ok(p)
}

pub async fn claim(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let data: Value = http::read_json(request, 65536).await?;
    let raw = text(&data, "access_token", 32, 512)?;
    let device = &data["device"];
    let device_id = id(string(device, "device_id")?)?;
    let name = text(device, "display_name", 1, 120)?;
    let key = string(device, "crypto_identity_public_key")?;
    if !(32..=4096).contains(&key.encode_utf16().count()) {
        return Err(invalid());
    }
    let db = Db(env.d1("DB")?);
    let now = http::now_iso();
    let row = db
        .first::<Value>(
            "SELECT * FROM operator_access_grants WHERE token_hash=?1",
            &[json!(auth::sha256_hex(raw))],
        )
        .await?
        .ok_or_else(|| ApiError::domain("AGENT_ACCESS_INVALID", 404))?;
    if !row["claimed_at"].is_null() {
        return Err(ApiError::domain("AGENT_ACCESS_USED", 410));
    }
    if !row["revoked_at"].is_null() {
        return Err(ApiError::domain("AGENT_ACCESS_REVOKED", 410));
    }
    if row["expires_at"].as_str().unwrap_or("") <= now.as_str() {
        return Err(ApiError::domain("AGENT_ACCESS_EXPIRED", 410));
    }
    let user = string(&row, "operator_user_id")?;
    let grant = string(&row, "grant_id")?;
    let workspace = string(&row, "workspace_id")?;
    let issuer = string(&row, "created_by_user_id")?;
    let claim = http::random_id()?;
    let session = http::random_id()?;
    let secret = token()?;
    let predicate = "EXISTS(SELECT 1 FROM operator_access_grants g JOIN workspace_staff ws ON ws.workspace_id=g.workspace_id AND ws.user_id=g.operator_user_id AND ws.staff_role='OPERATOR' AND ws.revoked_at IS NULL AND ws.created_by_user_id=g.created_by_user_id JOIN workspace_memberships wm ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL JOIN users u ON u.user_id=ws.user_id AND u.role='ADMIN' AND u.status='ACTIVE' WHERE g.grant_id=?1 AND g.claimed_at IS NULL AND g.revoked_at IS NULL AND g.expires_at>?2)".to_string();
    let mut writes=vec![guard(&db,&predicate,&[json!(grant),json!(now)])?,staff_guard(&db,workspace,issuer,true)?,db.statement("INSERT INTO operator_access_claims(claim_id,grant_id,device_id,session_id,claimed_at) VALUES(?1,?2,?3,?4,?5)",&[json!(claim),json!(grant),json!(device_id),json!(session),json!(now)])?,db.statement("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES(?1,?2,?3,?4,?5,?5,?5)",&[json!(device_id),json!(user),json!(name),json!(key),json!(now)])?,db.statement("INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES(?1,?2,?3,?4,?5,?5,?6)",&[json!(session),json!(auth::sha256_hex(&secret)),json!(user),json!(device_id),json!(now),json!(expires(30.0))])?,db.statement("UPDATE operator_access_grants SET claimed_at=?2,claimed_device_id=?3 WHERE grant_id=?1",&[json!(grant),json!(now),json!(device_id)])?];
    writes.push(cleanup(&db)?);
    if let Err(e) = db.0.batch(writes).await {
        if db
            .first::<Value>(
                "SELECT 1 FROM devices WHERE device_id=?1",
                &[json!(device_id)],
            )
            .await?
            .is_some()
        {
            return Err(ApiError::domain("DEVICE_ID_CONFLICT", 409));
        }
        if e.to_string().contains("constraint") {
            return Err(ApiError::domain("AGENT_ACCESS_CONFLICT", 409));
        }
        return Err(e.into());
    }
    let mut response=http::json(&json!({"session_id":session,"user_id":user,"device_id":device_id,"device_state":"AUTHORIZED"}))?.with_status(201);
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "__Host-session={secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000"
        ),
    )?;
    Ok(response)
}
