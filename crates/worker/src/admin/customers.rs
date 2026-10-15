use super::*;
async fn scope(db: &Db, auth: &AuthContext, chat: &str, account: bool) -> ApiResult<Value> {
    id(chat)?;
    if db
        .first::<Value>(
            "SELECT 1 FROM active_chat_members WHERE chat_id=?1 AND user_id=?2",
            &[json!(chat), json!(auth.user_id)],
        )
        .await?
        .is_none()
    {
        return Err(ApiError::domain("CHAT_FORBIDDEN", 403));
    }
    let row=db.first::<Value>("SELECT c.workspace_id,p.user_id AS customer_user_id,cc.display_name FROM chats c JOIN active_chat_members p ON p.chat_id=c.chat_id AND p.participant_role='CUSTOMER' LEFT JOIN customer_contacts cc ON cc.workspace_id=c.workspace_id AND cc.user_id=p.user_id WHERE c.chat_id=?1 LIMIT 1",&[json!(chat)]).await?.ok_or_else(||ApiError::domain("CHAT_NOT_FOUND",404))?;
    if account
        && db
            .first::<Value>(
                "SELECT 1 FROM customer_accounts WHERE user_id=?1",
                &[row["customer_user_id"].clone()],
            )
            .await?
            .is_none()
    {
        return Err(ApiError::domain("CUSTOMER_ACCOUNT_NOT_FOUND", 404));
    }
    Ok(row)
}
pub async fn prepare(
    db: &Db,
    auth: &AuthContext,
    op: &str,
    chat: &str,
    data: &Value,
) -> ApiResult<MutationPlan> {
    let row = scope(db, auth, chat, op != "admin.customer.account").await?;
    let workspace = string(&row, "workspace_id")?;
    let customer = string(&row, "customer_user_id")?;
    staff(
        db,
        workspace,
        &auth.user_id,
        op == "admin.customer.password",
    )
    .await?;
    let now = http::now_iso();
    let mut p = plan(Value::Null, 201);
    p.statements.push(staff_guard(
        db,
        workspace,
        &auth.user_id,
        op == "admin.customer.password",
    )?);
    p.statements.push(guard(db,"EXISTS(SELECT 1 FROM active_chat_members WHERE chat_id=?1 AND user_id=?2 AND participant_role='ADMIN') AND EXISTS(SELECT 1 FROM active_chat_members WHERE chat_id=?1 AND user_id=?3 AND participant_role='CUSTOMER')",&[json!(chat),json!(auth.user_id),json!(customer)])?);
    if op == "admin.customer.password" {
        let name = login(data)?;
        unique_login(db, &name, customer).await?;
        p.statements
            .push(credential(db, customer, &name, string(data, "password")?, &now).await?);
        p.statements.push(db.statement(
            "UPDATE sessions SET revoked_at=COALESCE(revoked_at,?2) WHERE user_id=?1",
            &[json!(customer), json!(now)],
        )?);
        p.affected_users.push(customer.into());
        p.status = 200;
        p.response = json!({"login_name":name,"updated_at":now});
        return Ok(p);
    }
    let mut name = Value::Null;
    let mut display = row["display_name"].clone();
    if op == "admin.customer.account" {
        display = json!(text(data, "display_name", 1, 80)?);
        if db
            .first::<Value>(
                "SELECT 1 FROM customer_accounts WHERE user_id=?1 UNION ALL SELECT 1 FROM password_credentials WHERE user_id=?1",
                &[json!(customer)],
            )
            .await?
            .is_some()
        {
            return Err(ApiError::domain("CUSTOMER_ACCOUNT_EXISTS", 409));
        }
        if data.get("login_name").is_some() != data.get("password").is_some() {
            return Err(invalid());
        }
        if data.get("login_name").is_some() {
            let login = login(data)?;
            unique_login(db, &login, customer).await?;
            p.statements.push(
                insert_credential(db, customer, &login, string(data, "password")?, &now).await?,
            );
            name = json!(login)
        }
        p.statements.push(db.statement(
            "INSERT INTO customer_accounts(user_id,created_by_user_id,created_at) VALUES(?1,?2,?3)",
            &[json!(customer), json!(auth.user_id), json!(now)],
        )?);
        p.statements.push(db.statement("INSERT INTO customer_contacts(workspace_id,user_id,display_name,created_by_user_id,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5)",&[json!(workspace),json!(customer),display.clone(),json!(auth.user_id),json!(now)])?);
    } else if op != "admin.customer.access" {
        return Err(ApiError::domain("NOT_FOUND", 404));
    }
    let invitation = http::random_id()?;
    let token = token()?;
    let expiry = expires(1.0);
    p.statements.push(db.statement("INSERT INTO invitations(invitation_id,kind,workspace_id,chat_id,customer_user_id,token_hash,created_by_user_id,expires_at,status,created_at) VALUES(?1,'ACCESS',?2,?3,?4,?5,?6,?7,'ACTIVE',?8)",&[json!(invitation),json!(workspace),json!(chat),json!(customer),json!(auth::sha256_hex(&token)),json!(auth.user_id),json!(expiry),json!(now)])?);
    p.response = json!({"invitation_id":invitation,"customer_user_id":customer,"chat_id":chat,"login_name":name,"token":token,"expires_at":expiry,"display_name":display});
    Ok(p)
}

pub async fn claim(request: &mut Request, env: &Env, access: bool) -> ApiResult<Response> {
    let data: Value = http::read_json(request, 65536).await?;
    let raw = text(
        &data,
        if access {
            "access_token"
        } else {
            "invitation_token"
        },
        32,
        512,
    )?;
    let device = &data["device"];
    let device_id = id(string(device, "device_id")?)?;
    let name = text(device, "display_name", 1, 120)?;
    let key = string(device, "crypto_identity_public_key")?;
    if !(32..=4096).contains(&key.encode_utf16().count()) {
        return Err(invalid());
    }
    let db = Db(env.d1("DB")?);
    let row = db
        .first::<Value>(
            "SELECT * FROM invitations WHERE token_hash=?1 AND kind=?2",
            &[
                json!(auth::sha256_hex(raw)),
                json!(if access { "ACCESS" } else { "REFERRAL" }),
            ],
        )
        .await?
        .ok_or_else(|| {
            ApiError::domain(
                if access {
                    "ACCESS_INVALID"
                } else {
                    "INVITATION_NOT_FOUND"
                },
                if access { 410 } else { 404 },
            )
        })?;
    let now = http::now_iso();
    if row["status"] != "ACTIVE" || !row["revoked_at"].is_null() {
        return Err(ApiError::domain(
            if access {
                "ACCESS_INVALID"
            } else {
                "INVITATION_REVOKED"
            },
            410,
        ));
    }
    if row["expires_at"]
        .as_str()
        .is_some_and(|e| e <= now.as_str())
    {
        return Err(ApiError::domain(
            if access {
                "ACCESS_EXPIRED"
            } else {
                "INVITATION_EXPIRED"
            },
            410,
        ));
    }
    let workspace = string(&row, "workspace_id")?;
    let issuer = string(&row, "created_by_user_id")?;
    let invitation = string(&row, "invitation_id")?;
    staff(&db, workspace, issuer, false)
        .await
        .map_err(|_| ApiError::domain("INVITATION_OWNER_INACTIVE", 410))?;
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
    let user = if access {
        string(&row, "customer_user_id")?.to_string()
    } else {
        http::random_id()?
    };
    let chat = if access {
        string(&row, "chat_id")?.to_string()
    } else {
        http::random_id()?
    };
    let session = http::random_id()?;
    let secret = token()?;
    let mut writes = vec![
        guard(
            &db,
            "EXISTS(SELECT 1 FROM invitations WHERE invitation_id=?1 AND status='ACTIVE' AND revoked_at IS NULL AND(expires_at IS NULL OR expires_at>?2))",
            &[json!(invitation), json!(now)],
        )?,
        staff_guard(&db, workspace, issuer, false)?,
    ];
    if access {
        writes.push(guard(&db,"EXISTS(SELECT 1 FROM users u JOIN workspace_memberships wm ON wm.user_id=u.user_id JOIN chat_participants cp ON cp.user_id=u.user_id JOIN chats c ON c.chat_id=cp.chat_id AND c.workspace_id=wm.workspace_id WHERE u.user_id=?1 AND u.role='CUSTOMER' AND u.status IN('INVITED','ACTIVE') AND wm.workspace_id=?2 AND wm.role='CUSTOMER' AND wm.status IN('PENDING','ACTIVE') AND wm.revoked_at IS NULL AND cp.chat_id=?3 AND cp.participant_role='CUSTOMER' AND cp.left_at IS NULL)",&[json!(user),json!(workspace),json!(chat)])?);
        writes.push(db.statement("INSERT OR IGNORE INTO customer_accounts(user_id,created_by_user_id,created_at) VALUES(?1,?2,?3)",&[json!(user),json!(issuer),json!(now)])?);
        writes.push(db.statement("UPDATE users SET status='ACTIVE',activated_at=COALESCE(activated_at,?2) WHERE user_id=?1 AND status='INVITED'",&[json!(user),json!(now)])?);
        writes.push(db.statement("UPDATE workspace_memberships SET status='ACTIVE' WHERE workspace_id=?1 AND user_id=?2 AND status='PENDING'",&[json!(workspace),json!(user)])?);
        writes.push(db.statement(
            "UPDATE invitations SET status='CLAIMED',claimed_at=?2 WHERE invitation_id=?1",
            &[json!(invitation), json!(now)],
        )?);
    } else {
        writes.push(db.statement("INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES(?1,'CUSTOMER','ACTIVE',?2,?2)",&[json!(user),json!(now)])?);
        writes.push(db.statement("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES(?1,?2,'CUSTOMER','ACTIVE',?3)",&[json!(workspace),json!(user),json!(now)])?);
        writes.extend(chat_statements(&db, &chat, workspace, issuer, &user, &now)?);
    }
    writes.extend([db.statement("INSERT INTO invitation_claims(claim_id,invitation_id,user_id,chat_id,claimed_at) VALUES(?1,?2,?3,?4,?5)",&[json!(http::random_id()?),json!(invitation),json!(user),json!(chat),json!(now)])?,db.statement("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES(?1,?2,?3,?4,?5,?5,?5)",&[json!(device_id),json!(user),json!(name),json!(key),json!(now)])?,db.statement("INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES(?1,?2,?3,?4,?5,?5,?6)",&[json!(session),json!(auth::sha256_hex(&secret)),json!(user),json!(device_id),json!(now),json!(expires(365.0))])?]);
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
            return Err(ApiError::domain(
                if access {
                    "ACCESS_ALREADY_USED"
                } else {
                    "INVITATION_REVOKED"
                },
                409,
            ));
        }
        return Err(e.into());
    }
    let mut response=http::json(&json!({"session_id":session,"user_id":user,"device_id":device_id,"chat_id":chat,"device_state":"AUTHORIZED"}))?.with_status(201);
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "__Host-session={secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000"
        ),
    )?;
    Ok(response)
}
