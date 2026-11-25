-- ============================================================================
-- 01-supabase-db/003_vault_rpc_functions.sql
-- Toàn bộ 12 hàm RPC bảo mật (SECURITY DEFINER) cho Kho Bảo Mật Admin (AAL2).
-- Cơ chế Write-Only: tuyệt đối không trả plaintext token/mật khẩu về trình duyệt.
-- ============================================================================

-- 1. Xác nhận hoàn tất đổi mật khẩu lần đầu (cho bất kỳ user đang active nào)
CREATE OR REPLACE FUNCTION public.complete_first_password_change()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_uid       UUID := auth.uid();
  v_email     TEXT;
  v_is_active BOOLEAN;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION '42501: Chưa đăng nhập.' USING ERRCODE = '42501';
  END IF;

  SELECT u.email, u.is_active
  INTO v_email, v_is_active
  FROM public.users u
  WHERE u.id = v_uid;

  IF NOT FOUND OR NOT COALESCE(v_is_active, false) THEN
    RAISE EXCEPTION '42501: Tài khoản không hợp lệ hoặc đang bị khóa.' USING ERRCODE = '42501';
  END IF;

  UPDATE public.users
  SET must_change_password = false,
      updated_at = now()
  WHERE id = v_uid;

  PERFORM private.write_audit_log(
    v_uid,
    v_email,
    'FIRST_PASSWORD_CHANGED',
    v_uid,
    v_email,
    jsonb_build_object('completed_at', now())
  );

  RETURN jsonb_build_object('ok', true, 'user_id', v_uid);
END;
$$;

-- 2. Danh sách tài khoản & phân quyền khu vực (Tab 1)
CREATE OR REPLACE FUNCTION public.admin_list_users()
RETURNS TABLE (
  id                   UUID,
  email                TEXT,
  full_name            TEXT,
  role_code            TEXT,
  is_active            BOOLEAN,
  must_change_password BOOLEAN,
  mfa_required         BOOLEAN,
  note                 TEXT,
  created_at           TIMESTAMPTZ,
  permissions          JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
BEGIN
  PERFORM private.assert_admin_aal2();

  RETURN QUERY
  SELECT
    u.id,
    u.email,
    u.full_name,
    r.code AS role_code,
    u.is_active,
    u.must_change_password,
    u.mfa_required,
    u.note,
    u.created_at,
    COALESCE(
      (
        SELECT jsonb_agg(
          jsonb_build_object(
            'region_id',   p.region_id,
            'region_code', reg.code,
            'region_name', reg.name,
            'status',      p.status,
            'note',        p.note,
            'reviewed_at', p.reviewed_at
          )
          ORDER BY reg.id ASC
        )
        FROM public.user_region_permissions p
        JOIN public.regions reg ON reg.id = p.region_id
        WHERE p.user_id = u.id
      ),
      '[]'::jsonb
    ) AS permissions
  FROM public.users u
  JOIN public.roles r ON r.id = u.role_id
  ORDER BY
    CASE r.code WHEN 'admin' THEN 1 WHEN 'hq' THEN 2 ELSE 3 END,
    u.created_at DESC;
END;
$$;

-- 3. Duyệt / cập nhật vai trò / thu hồi quyền người dùng (Tab 1)
CREATE OR REPLACE FUNCTION public.admin_review_permission(
  p_target_user_id UUID,
  p_region_id      INTEGER DEFAULT NULL,
  p_status         TEXT DEFAULT 'approved',
  p_role_code      TEXT DEFAULT 'regional',
  p_activate_user  BOOLEAN DEFAULT true,
  p_note           TEXT DEFAULT ''
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_actor        RECORD;
  v_role_id      SMALLINT;
  v_clean_role   TEXT := lower(btrim(COALESCE(p_role_code, '')));
  v_clean_status TEXT := lower(btrim(COALESCE(p_status, '')));
  v_clean_note   TEXT := btrim(COALESCE(p_note, ''));
  v_target_email TEXT;
  v_region_code  TEXT := NULL;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  IF p_target_user_id IS NULL THEN
    RAISE EXCEPTION '22023: Thiếu mã người dùng mục tiêu.' USING ERRCODE = '22023';
  END IF;

  IF v_clean_status NOT IN ('approved', 'revoked') THEN
    RAISE EXCEPTION '22023: Trạng thái duyệt quyền không hợp lệ (%).', v_clean_status USING ERRCODE = '22023';
  END IF;

  IF v_clean_role NOT IN ('regional', 'hq', 'admin') THEN
    RAISE EXCEPTION '22023: Vai trò không hợp lệ (%).', v_clean_role USING ERRCODE = '22023';
  END IF;

  -- Chống tự khóa / tự hạ quyền Admin đang thao tác
  IF p_target_user_id = v_actor.actor_id AND (NOT COALESCE(p_activate_user, false) OR v_clean_role <> 'admin' OR v_clean_status = 'revoked') THEN
    RAISE EXCEPTION '22023: Không thể tự thu hồi quyền hoặc hạ vai trò tài khoản Admin đang đăng nhập.'
      USING ERRCODE = '22023';
  END IF;

  SELECT u.email INTO v_target_email
  FROM public.users u
  WHERE u.id = p_target_user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'P0002: Không tìm thấy người dùng mục tiêu.' USING ERRCODE = 'P0002';
  END IF;

  SELECT id INTO v_role_id FROM public.roles WHERE code = v_clean_role;
  IF NOT FOUND THEN
    RAISE EXCEPTION '22023: Không tìm thấy định nghĩa vai trò %.', v_clean_role USING ERRCODE = '22023';
  END IF;

  IF v_clean_role = 'regional' AND v_clean_status = 'approved' THEN
    IF p_region_id IS NULL THEN
      RAISE EXCEPTION '22023: Tài khoản Regional bắt buộc phải gán 1 trong 7 khu vực.' USING ERRCODE = '22023';
    END IF;
    SELECT code INTO v_region_code FROM public.regions WHERE id = p_region_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION '22023: Khu vực (region_id=%) không tồn tại.', p_region_id USING ERRCODE = '22023';
    END IF;
  END IF;

  -- Cập nhật hồ sơ user
  UPDATE public.users
  SET role_id      = v_role_id,
      is_active    = COALESCE(p_activate_user, false),
      mfa_required = (v_clean_role IN ('hq', 'admin')),
      updated_at   = now()
  WHERE id = p_target_user_id;

  -- Cập nhật phân quyền khu vực
  IF v_clean_role = 'regional' THEN
    IF v_clean_status = 'approved' THEN
      -- Mỗi tài khoản Regional chỉ hoạt động trên 1 khu vực được gán
      UPDATE public.user_region_permissions
      SET status      = 'revoked',
          reviewed_by = v_actor.actor_id,
          reviewed_at = now(),
          note        = 'Chuyển vùng quản lý bởi Admin'
      WHERE user_id = p_target_user_id
        AND region_id <> p_region_id
        AND status = 'approved';

      INSERT INTO public.user_region_permissions (
        user_id, region_id, status, note, reviewed_by, reviewed_at
      )
      VALUES (
        p_target_user_id, p_region_id, 'approved', v_clean_note, v_actor.actor_id, now()
      )
      ON CONFLICT (user_id, region_id) DO UPDATE
      SET status      = 'approved',
          note        = EXCLUDED.note,
          reviewed_by = EXCLUDED.reviewed_by,
          reviewed_at = EXCLUDED.reviewed_at;
    ELSE
      -- Thu hồi toàn bộ quyền khu vực của user
      UPDATE public.user_region_permissions
      SET status      = 'revoked',
          note        = v_clean_note,
          reviewed_by = v_actor.actor_id,
          reviewed_at = now()
      WHERE user_id = p_target_user_id;
    END IF;
  ELSE
    -- HQ / Admin có phạm vi toàn quốc -> vô hiệu hóa các gán khu vực cũ nếu có
    UPDATE public.user_region_permissions
    SET status      = 'revoked',
        note        = 'Chuyển sang vai trò toàn quốc (' || v_clean_role || ')',
        reviewed_by = v_actor.actor_id,
        reviewed_at = now()
    WHERE user_id = p_target_user_id
      AND status <> 'revoked';
  END IF;

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    CASE WHEN v_clean_status = 'approved' THEN 'PERMISSION_APPROVED' ELSE 'PERMISSION_REVOKED' END,
    p_target_user_id,
    v_target_email,
    jsonb_build_object(
      'role_code',     v_clean_role,
      'region_id',     p_region_id,
      'region_code',   v_region_code,
      'status',        v_clean_status,
      'activate_user', COALESCE(p_activate_user, false),
      'note',          v_clean_note
    )
  );

  RETURN jsonb_build_object(
    'ok', true,
    'target_user_id', p_target_user_id,
    'role_code', v_clean_role,
    'status', v_clean_status
  );
END;
$$;

-- 4. Liệt kê Token ở chế độ che chuỗi (Tab 2 — Write-Only)
CREATE OR REPLACE FUNCTION public.admin_list_tokens_masked()
RETURNS TABLE (
  id                     BIGINT,
  token_name             TEXT,
  token_type             TEXT,
  region_code            TEXT,
  priority               SMALLINT,
  masked_preview         TEXT,
  masked_refresh_preview TEXT,
  expires_at             TIMESTAMPTZ,
  status                 TEXT,
  last_error             TEXT,
  note                   TEXT,
  updated_at             TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
BEGIN
  PERFORM private.assert_admin_aal2();

  RETURN QUERY
  SELECT
    t.id,
    t.token_name,
    t.token_type,
    t.region_code,
    t.priority,
    t.masked_preview,
    t.masked_refresh_preview,
    t.expires_at,
    t.status,
    t.last_error,
    t.note,
    t.updated_at
  FROM public.vault_tokens t
  ORDER BY t.token_type ASC, t.region_code ASC, t.priority ASC, t.token_name ASC;
END;
$$;

-- 5. Lưu / Xoay vòng Token vào Supabase Vault (Tab 2 — Write-Only)
CREATE OR REPLACE FUNCTION public.admin_save_token(
  p_token_name          TEXT,
  p_token_type          TEXT,
  p_plain_token         TEXT,
  p_region_code         TEXT DEFAULT 'ALL',
  p_priority            INTEGER DEFAULT 1,
  p_refresh_action      TEXT DEFAULT 'keep',
  p_plain_refresh_token TEXT DEFAULT NULL,
  p_expires_at          TIMESTAMPTZ DEFAULT NULL,
  p_note                TEXT DEFAULT ''
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, vault, auth
AS $$
DECLARE
  v_actor             RECORD;
  v_existing          public.vault_tokens%ROWTYPE;
  v_is_rotation       BOOLEAN := false;
  v_name              TEXT := upper(btrim(COALESCE(p_token_name, '')));
  v_type              TEXT := lower(btrim(COALESCE(p_token_type, '')));
  v_plain             TEXT := btrim(COALESCE(p_plain_token, ''));
  v_region            TEXT := upper(btrim(COALESCE(p_region_code, 'ALL')));
  v_priority          SMALLINT;
  v_refresh_action    TEXT := lower(btrim(COALESCE(p_refresh_action, 'keep')));
  v_plain_refresh     TEXT := btrim(COALESCE(p_plain_refresh_token, ''));
  v_note              TEXT := btrim(COALESCE(p_note, ''));
  v_secret_id         UUID;
  v_refresh_secret_id UUID := NULL;
  v_masked_preview    TEXT;
  v_masked_refresh    TEXT := NULL;
  v_saved_id          BIGINT;
  v_saved_updated_at  TIMESTAMPTZ;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  IF v_name !~ '^[A-Z0-9_.-]{2,64}$' THEN
    RAISE EXCEPTION '22023: Tên định danh token chỉ được chứa A-Z, 0-9, _, ., - (2–64 ký tự).'
      USING ERRCODE = '22023';
  END IF;

  IF v_type NOT IN ('jms_auth', 'feishu_oauth') THEN
    RAISE EXCEPTION '22023: Loại token không hợp lệ (%).', v_type USING ERRCODE = '22023';
  END IF;

  IF char_length(v_plain) < 6 THEN
    RAISE EXCEPTION '22023: Giá trị token quá ngắn (tối thiểu 6 ký tự).' USING ERRCODE = '22023';
  END IF;

  IF v_region <> 'ALL' AND NOT EXISTS (SELECT 1 FROM public.regions WHERE code = v_region) THEN
    RAISE EXCEPTION '22023: Mã khu vực (%) không hợp lệ.', v_region USING ERRCODE = '22023';
  END IF;

  IF p_priority IS NULL OR p_priority < 1 OR p_priority > 99 THEN
    RAISE EXCEPTION '22023: Độ ưu tiên phải từ 1 đến 99.' USING ERRCODE = '22023';
  END IF;
  v_priority := p_priority::SMALLINT;

  IF v_type <> 'feishu_oauth' THEN
    v_refresh_action := 'clear';
  END IF;

  IF v_refresh_action NOT IN ('keep', 'replace', 'clear') THEN
    RAISE EXCEPTION '22023: Hành động refresh token không hợp lệ (%).', v_refresh_action USING ERRCODE = '22023';
  END IF;

  IF v_type = 'feishu_oauth' AND v_refresh_action = 'replace' AND char_length(v_plain_refresh) < 6 THEN
    RAISE EXCEPTION '22023: Phải nhập Feishu Refresh Token hợp lệ khi chọn replace.' USING ERRCODE = '22023';
  END IF;

  v_masked_preview := private.mask_secret(v_plain);

  SELECT * INTO v_existing
  FROM public.vault_tokens
  WHERE token_name = v_name;

  v_is_rotation := FOUND;

  IF v_is_rotation THEN
    -- Xoay vòng secret chính ngay tại chỗ trong Supabase Vault
    PERFORM vault.update_secret(
      v_existing.vault_secret_id,
      v_plain,
      'jt_token:' || v_name,
      'J&T Vault Token (' || v_type || ' · ' || v_region || ')'
    );
    v_secret_id := v_existing.vault_secret_id;

    -- Xử lý Refresh Token theo hành động keep / replace / clear
    IF v_refresh_action = 'keep' THEN
      v_refresh_secret_id := v_existing.vault_refresh_secret_id;
      v_masked_refresh    := v_existing.masked_refresh_preview;
    ELSIF v_refresh_action = 'replace' THEN
      v_masked_refresh := private.mask_secret(v_plain_refresh);
      IF v_existing.vault_refresh_secret_id IS NOT NULL THEN
        PERFORM vault.update_secret(
          v_existing.vault_refresh_secret_id,
          v_plain_refresh,
          'jt_token_refresh:' || v_name,
          'J&T Feishu Refresh Token (' || v_region || ')'
        );
        v_refresh_secret_id := v_existing.vault_refresh_secret_id;
      ELSE
        v_refresh_secret_id := vault.create_secret(
          v_plain_refresh,
          'jt_token_refresh:' || v_name,
          'J&T Feishu Refresh Token (' || v_region || ')'
        );
      END IF;
    ELSE
      -- clear
      IF v_existing.vault_refresh_secret_id IS NOT NULL THEN
        DELETE FROM vault.secrets WHERE id = v_existing.vault_refresh_secret_id;
      END IF;
      v_refresh_secret_id := NULL;
      v_masked_refresh    := NULL;
    END IF;

    UPDATE public.vault_tokens
    SET token_type              = v_type,
        region_code             = v_region,
        priority                = v_priority,
        masked_preview          = v_masked_preview,
        vault_refresh_secret_id = v_refresh_secret_id,
        masked_refresh_preview  = v_masked_refresh,
        expires_at              = CASE WHEN v_type = 'feishu_oauth' THEN p_expires_at ELSE NULL END,
        status                  = 'active',
        last_error              = NULL,
        note                    = v_note,
        updated_by              = v_actor.actor_id,
        updated_at              = now()
    WHERE id = v_existing.id
    RETURNING id, updated_at INTO v_saved_id, v_saved_updated_at;
  ELSE
    -- Tạo secret mới trong Supabase Vault
    v_secret_id := vault.create_secret(
      v_plain,
      'jt_token:' || v_name,
      'J&T Vault Token (' || v_type || ' · ' || v_region || ')'
    );

    IF v_type = 'feishu_oauth' AND v_refresh_action = 'replace' THEN
      v_masked_refresh := private.mask_secret(v_plain_refresh);
      v_refresh_secret_id := vault.create_secret(
        v_plain_refresh,
        'jt_token_refresh:' || v_name,
        'J&T Feishu Refresh Token (' || v_region || ')'
      );
    END IF;

    INSERT INTO public.vault_tokens (
      token_name, token_type, region_code, priority,
      vault_secret_id, masked_preview,
      vault_refresh_secret_id, masked_refresh_preview,
      expires_at, status, last_error, note, updated_by
    )
    VALUES (
      v_name, v_type, v_region, v_priority,
      v_secret_id, v_masked_preview,
      v_refresh_secret_id, v_masked_refresh,
      CASE WHEN v_type = 'feishu_oauth' THEN p_expires_at ELSE NULL END,
      'active', NULL, v_note, v_actor.actor_id
    )
    RETURNING id, updated_at INTO v_saved_id, v_saved_updated_at;
  END IF;

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    'TOKEN_SAVED',
    NULL,
    v_name,
    jsonb_build_object(
      'token_id',       v_saved_id,
      'token_name',     v_name,
      'token_type',     v_type,
      'region_code',    v_region,
      'priority',       v_priority,
      'rotated',        v_is_rotation,
      'refresh_action', v_refresh_action,
      'masked_preview', v_masked_preview
    )
  );

  RETURN jsonb_build_object(
    'id',                     v_saved_id,
    'token_name',             v_name,
    'token_type',             v_type,
    'region_code',            v_region,
    'priority',               v_priority,
    'masked_preview',         v_masked_preview,
    'masked_refresh_preview', v_masked_refresh,
    'status',                 'active',
    'updated_at',             v_saved_updated_at
  );
END;
$$;

-- 6. Bật / Tắt trạng thái Token (Tab 2)
CREATE OR REPLACE FUNCTION public.admin_toggle_token(
  p_token_id BIGINT,
  p_status   TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_actor      RECORD;
  v_clean_stat TEXT := lower(btrim(COALESCE(p_status, '')));
  v_row        public.vault_tokens%ROWTYPE;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  IF v_clean_stat NOT IN ('active', 'disabled', 'expired') THEN
    RAISE EXCEPTION '22023: Trạng thái token không hợp lệ (%).', v_clean_stat USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_row FROM public.vault_tokens WHERE id = p_token_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'P0002: Không tìm thấy token mục tiêu.' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.vault_tokens
  SET status     = v_clean_stat,
      updated_by = v_actor.actor_id,
      updated_at = now()
  WHERE id = p_token_id;

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    'TOKEN_STATUS_CHANGED',
    NULL,
    v_row.token_name,
    jsonb_build_object(
      'token_id',    p_token_id,
      'token_name',  v_row.token_name,
      'prev_status', v_row.status,
      'next_status', v_clean_stat
    )
  );

  RETURN jsonb_build_object('ok', true, 'id', p_token_id, 'status', v_clean_stat);
END;
$$;

-- 7. Xóa vĩnh viễn Token & hủy bản ghi mã hóa trong Supabase Vault (Tab 2)
CREATE OR REPLACE FUNCTION public.admin_delete_token(p_token_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, vault, auth
AS $$
DECLARE
  v_actor RECORD;
  v_row   public.vault_tokens%ROWTYPE;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  SELECT * INTO v_row FROM public.vault_tokens WHERE id = p_token_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'P0002: Không tìm thấy token cần xóa.' USING ERRCODE = 'P0002';
  END IF;

  DELETE FROM public.vault_tokens WHERE id = p_token_id;
  DELETE FROM vault.secrets WHERE id = v_row.vault_secret_id;
  IF v_row.vault_refresh_secret_id IS NOT NULL THEN
    DELETE FROM vault.secrets WHERE id = v_row.vault_refresh_secret_id;
  END IF;

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    'TOKEN_DELETED',
    NULL,
    v_row.token_name,
    jsonb_build_object(
      'token_id',    p_token_id,
      'token_name',  v_row.token_name,
      'token_type',  v_row.token_type,
      'region_code', v_row.region_code
    )
  );

  RETURN jsonb_build_object('ok', true, 'deleted_token_name', v_row.token_name);
END;
$$;

-- 8. Liệt kê Tài khoản / MK JMS ở chế độ che (Tab 3 — Write-Only)
CREATE OR REPLACE FUNCTION public.admin_list_jms_credentials_masked()
RETURNS TABLE (
  id              BIGINT,
  cred_name       TEXT,
  region_code     TEXT,
  priority        SMALLINT,
  masked_username TEXT,
  status          TEXT,
  last_login_at   TIMESTAMPTZ,
  last_error      TEXT,
  note            TEXT,
  updated_at      TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
BEGIN
  PERFORM private.assert_admin_aal2();

  RETURN QUERY
  SELECT
    c.id,
    c.cred_name,
    c.region_code,
    c.priority,
    c.masked_username,
    c.status,
    c.last_login_at,
    c.last_error,
    c.note,
    c.updated_at
  FROM public.jms_credentials c
  ORDER BY c.region_code ASC, c.priority ASC, c.cred_name ASC;
END;
$$;

-- 9. Lưu / Cập nhật cặp Tài khoản & Mật khẩu JMS vào Supabase Vault (Tab 3)
CREATE OR REPLACE FUNCTION public.admin_save_jms_credentials(
  p_cred_name      TEXT,
  p_plain_username TEXT,
  p_plain_password TEXT,
  p_region_code    TEXT DEFAULT 'ALL',
  p_priority       INTEGER DEFAULT 1,
  p_note           TEXT DEFAULT ''
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, vault, auth
AS $$
DECLARE
  v_actor         RECORD;
  v_existing      public.jms_credentials%ROWTYPE;
  v_is_rotation   BOOLEAN := false;
  v_name          TEXT := upper(btrim(COALESCE(p_cred_name, '')));
  v_user          TEXT := btrim(COALESCE(p_plain_username, ''));
  v_pass          TEXT := btrim(COALESCE(p_plain_password, ''));
  v_region        TEXT := upper(btrim(COALESCE(p_region_code, 'ALL')));
  v_priority      SMALLINT;
  v_note          TEXT := btrim(COALESCE(p_note, ''));
  v_masked_user   TEXT;
  v_user_sec_id   UUID;
  v_pass_sec_id   UUID;
  v_saved_id      BIGINT;
  v_saved_updated TIMESTAMPTZ;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  IF v_name !~ '^[A-Z0-9_.-]{2,64}$' THEN
    RAISE EXCEPTION '22023: Tên định danh tài khoản JMS chỉ được chứa A-Z, 0-9, _, ., - (2–64 ký tự).'
      USING ERRCODE = '22023';
  END IF;

  IF char_length(v_user) < 2 OR char_length(v_pass) < 4 THEN
    RAISE EXCEPTION '22023: Tài khoản và mật khẩu JMS không được để trống.' USING ERRCODE = '22023';
  END IF;

  IF v_region <> 'ALL' AND NOT EXISTS (SELECT 1 FROM public.regions WHERE code = v_region) THEN
    RAISE EXCEPTION '22023: Mã khu vực (%) không hợp lệ.', v_region USING ERRCODE = '22023';
  END IF;

  IF p_priority IS NULL OR p_priority < 1 OR p_priority > 99 THEN
    RAISE EXCEPTION '22023: Độ ưu tiên phải từ 1 đến 99.' USING ERRCODE = '22023';
  END IF;
  v_priority := p_priority::SMALLINT;

  v_masked_user := private.mask_username(v_user);

  SELECT * INTO v_existing
  FROM public.jms_credentials
  WHERE cred_name = v_name;

  v_is_rotation := FOUND;

  IF v_is_rotation THEN
    PERFORM vault.update_secret(
      v_existing.vault_username_secret_id,
      v_user,
      'jt_jms_user:' || v_name,
      'J&T JMS Login Username (' || v_region || ')'
    );
    PERFORM vault.update_secret(
      v_existing.vault_password_secret_id,
      v_pass,
      'jt_jms_pass:' || v_name,
      'J&T JMS Login Password (' || v_region || ')'
    );

    UPDATE public.jms_credentials
    SET region_code     = v_region,
        priority        = v_priority,
        masked_username = v_masked_user,
        status          = 'active',
        last_error      = NULL,
        note            = v_note,
        updated_by      = v_actor.actor_id,
        updated_at      = now()
    WHERE id = v_existing.id
    RETURNING id, updated_at INTO v_saved_id, v_saved_updated;
  ELSE
    v_user_sec_id := vault.create_secret(
      v_user,
      'jt_jms_user:' || v_name,
      'J&T JMS Login Username (' || v_region || ')'
    );
    v_pass_sec_id := vault.create_secret(
      v_pass,
      'jt_jms_pass:' || v_name,
      'J&T JMS Login Password (' || v_region || ')'
    );

    INSERT INTO public.jms_credentials (
      cred_name, region_code, priority,
      vault_username_secret_id, vault_password_secret_id,
      masked_username, status, last_error, note, updated_by
    )
    VALUES (
      v_name, v_region, v_priority,
      v_user_sec_id, v_pass_sec_id,
      v_masked_user, 'active', NULL, v_note, v_actor.actor_id
    )
    RETURNING id, updated_at INTO v_saved_id, v_saved_updated;
  END IF;

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    'JMS_CREDENTIAL_SAVED',
    NULL,
    v_name,
    jsonb_build_object(
      'cred_id',         v_saved_id,
      'cred_name',       v_name,
      'region_code',     v_region,
      'priority',        v_priority,
      'rotated',         v_is_rotation,
      'masked_username', v_masked_user
    )
  );

  RETURN jsonb_build_object(
    'id',              v_saved_id,
    'cred_name',       v_name,
    'region_code',     v_region,
    'priority',        v_priority,
    'masked_username', v_masked_user,
    'status',          'active',
    'updated_at',      v_saved_updated
  );
END;
$$;

-- 10. Bật / Tắt tài khoản JMS (Tab 3)
CREATE OR REPLACE FUNCTION public.admin_toggle_jms_credential(
  p_cred_id BIGINT,
  p_status  TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_actor      RECORD;
  v_clean_stat TEXT := lower(btrim(COALESCE(p_status, '')));
  v_row        public.jms_credentials%ROWTYPE;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  IF v_clean_stat NOT IN ('active', 'disabled') THEN
    RAISE EXCEPTION '22023: Trạng thái tài khoản JMS không hợp lệ (%).', v_clean_stat USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_row FROM public.jms_credentials WHERE id = p_cred_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'P0002: Không tìm thấy tài khoản JMS mục tiêu.' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.jms_credentials
  SET status     = v_clean_stat,
      updated_by = v_actor.actor_id,
      updated_at = now()
  WHERE id = p_cred_id;

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    'JMS_CREDENTIAL_STATUS_CHANGED',
    NULL,
    v_row.cred_name,
    jsonb_build_object(
      'cred_id',     p_cred_id,
      'cred_name',   v_row.cred_name,
      'prev_status', v_row.status,
      'next_status', v_clean_stat
    )
  );

  RETURN jsonb_build_object('ok', true, 'id', p_cred_id, 'status', v_clean_stat);
END;
$$;

-- 11. Xóa vĩnh viễn tài khoản JMS & hủy bản ghi mã hóa Vault (Tab 3)
CREATE OR REPLACE FUNCTION public.admin_delete_jms_credential(p_cred_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, vault, auth
AS $$
DECLARE
  v_actor RECORD;
  v_row   public.jms_credentials%ROWTYPE;
BEGIN
  SELECT * INTO v_actor FROM private.assert_admin_aal2();

  SELECT * INTO v_row FROM public.jms_credentials WHERE id = p_cred_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'P0002: Không tìm thấy tài khoản JMS cần xóa.' USING ERRCODE = 'P0002';
  END IF;

  DELETE FROM public.jms_credentials WHERE id = p_cred_id;
  DELETE FROM vault.secrets WHERE id IN (v_row.vault_username_secret_id, v_row.vault_password_secret_id);

  PERFORM private.write_audit_log(
    v_actor.actor_id,
    v_actor.actor_email,
    'JMS_CREDENTIAL_DELETED',
    NULL,
    v_row.cred_name,
    jsonb_build_object(
      'cred_id',     p_cred_id,
      'cred_name',   v_row.cred_name,
      'region_code', v_row.region_code
    )
  );

  RETURN jsonb_build_object('ok', true, 'deleted_cred_name', v_row.cred_name);
END;
$$;

-- 12. Đọc Nhật ký bảo mật bất biến (Tab 4 — Chỉ đọc)
CREATE OR REPLACE FUNCTION public.admin_get_audit_logs(p_limit INTEGER DEFAULT 120)
RETURNS TABLE (
  id           BIGINT,
  created_at   TIMESTAMPTZ,
  actor_email  TEXT,
  action       TEXT,
  target_email TEXT,
  metadata     JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_safe_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 120), 1), 500);
BEGIN
  PERFORM private.assert_admin_aal2();

  RETURN QUERY
  SELECT
    l.id,
    l.created_at,
    l.actor_email,
    l.action,
    l.target_email,
    l.metadata
  FROM public.security_audit_logs l
  ORDER BY l.created_at DESC, l.id DESC
  LIMIT v_safe_limit;
END;
$$;

-- 13. Khóa quyền gọi RPC: chỉ authenticated mới được gọi (anon bị chặn hoàn toàn)
REVOKE ALL ON FUNCTION
  public.complete_first_password_change(),
  public.admin_list_users(),
  public.admin_review_permission(UUID, INTEGER, TEXT, TEXT, BOOLEAN, TEXT),
  public.admin_list_tokens_masked(),
  public.admin_save_token(TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TIMESTAMPTZ, TEXT),
  public.admin_toggle_token(BIGINT, TEXT),
  public.admin_delete_token(BIGINT),
  public.admin_list_jms_credentials_masked(),
  public.admin_save_jms_credentials(TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT),
  public.admin_toggle_jms_credential(BIGINT, TEXT),
  public.admin_delete_jms_credential(BIGINT),
  public.admin_get_audit_logs(INTEGER)
FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION
  public.complete_first_password_change(),
  public.admin_list_users(),
  public.admin_review_permission(UUID, INTEGER, TEXT, TEXT, BOOLEAN, TEXT),
  public.admin_list_tokens_masked(),
  public.admin_save_token(TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TIMESTAMPTZ, TEXT),
  public.admin_toggle_token(BIGINT, TEXT),
  public.admin_delete_token(BIGINT),
  public.admin_list_jms_credentials_masked(),
  public.admin_save_jms_credentials(TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT),
  public.admin_toggle_jms_credential(BIGINT, TEXT),
  public.admin_delete_jms_credential(BIGINT),
  public.admin_get_audit_logs(INTEGER)
TO authenticated;
