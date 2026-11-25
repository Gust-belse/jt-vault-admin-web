-- ============================================================================
-- 01-supabase-db/001_schema_and_seed.sql
-- Schema & Seed dữ liệu nền tảng cho Kho Bảo Mật Tài Khoản & Bí Mật (J&T Express)
-- Tương thích Supabase Cloud PostgreSQL 15/16+ (có Supabase Vault) & Sandbox PG16.
-- ============================================================================

-- 1. Extensions & Private Schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Bật Supabase Vault nếu đang chạy trên Supabase Cloud (bỏ qua nếu sandbox đã shim sẵn schema vault)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.schemata WHERE schema_name = 'vault'
  ) THEN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'supabase_vault') THEN
      CREATE EXTENSION IF NOT EXISTS supabase_vault WITH SCHEMA vault;
    END IF;
  END IF;
END;
$$;

-- Schema nội bộ không lộ qua PostgREST API công khai
CREATE SCHEMA IF NOT EXISTS private;
REVOKE ALL ON SCHEMA private FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON SCHEMA private FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON SCHEMA private FROM authenticated;
  END IF;
END;
$$;

-- 2. Trigger cập nhật updated_at tự động
CREATE OR REPLACE FUNCTION private.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- 3. Bảng roles (3 vai trò: regional, hq, admin)
CREATE TABLE IF NOT EXISTS public.roles (
  id          SMALLINT PRIMARY KEY,
  code        TEXT NOT NULL UNIQUE CHECK (code IN ('regional', 'hq', 'admin')),
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. Bảng regions (7 Khu vực vận hành J&T Express Việt Nam)
CREATE TABLE IF NOT EXISTS public.regions (
  id          SMALLINT PRIMARY KEY,
  code        TEXT NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9_-]{2,16}$' AND code <> 'ALL'),
  name        TEXT NOT NULL,
  hub_codes   TEXT[] NOT NULL DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. Bảng users (Hồ sơ nội bộ gắn 1-1 với auth.users)
CREATE TABLE IF NOT EXISTS public.users (
  id                   UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email                TEXT NOT NULL UNIQUE,
  full_name            TEXT NOT NULL CHECK (char_length(btrim(full_name)) >= 2),
  role_id              SMALLINT NOT NULL REFERENCES public.roles(id) ON DELETE RESTRICT,
  is_active            BOOLEAN NOT NULL DEFAULT false,
  must_change_password BOOLEAN NOT NULL DEFAULT true,
  mfa_required         BOOLEAN NOT NULL DEFAULT false,
  note                 TEXT NOT NULL DEFAULT '',
  created_by           UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_role_id ON public.users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON public.users(is_active);

DROP TRIGGER IF EXISTS trg_users_updated_at ON public.users;
CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW
  EXECUTE FUNCTION private.set_updated_at();

-- 6. Bảng user_region_permissions (Phân quyền khu vực cho tài khoản Regional)
CREATE TABLE IF NOT EXISTS public.user_region_permissions (
  id          BIGSERIAL PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  region_id   SMALLINT NOT NULL REFERENCES public.regions(id) ON DELETE RESTRICT,
  status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'revoked')),
  note        TEXT NOT NULL DEFAULT '',
  reviewed_by UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, region_id)
);

CREATE INDEX IF NOT EXISTS idx_user_region_perms_user_id ON public.user_region_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_region_perms_status ON public.user_region_permissions(status);

DROP TRIGGER IF EXISTS trg_user_region_perms_updated_at ON public.user_region_permissions;
CREATE TRIGGER trg_user_region_perms_updated_at
  BEFORE UPDATE ON public.user_region_permissions
  FOR EACH ROW
  EXECUTE FUNCTION private.set_updated_at();

-- 7. Bảng vault_tokens (Metadata token Write-Only; giá trị thực lưu mã hóa tại vault.secrets)
CREATE TABLE IF NOT EXISTS public.vault_tokens (
  id                      BIGSERIAL PRIMARY KEY,
  token_name              TEXT NOT NULL UNIQUE CHECK (token_name ~ '^[A-Z0-9_.-]{2,64}$'),
  token_type              TEXT NOT NULL CHECK (token_type IN ('jms_auth', 'feishu_oauth')),
  region_code             TEXT NOT NULL DEFAULT 'ALL',
  priority                SMALLINT NOT NULL DEFAULT 1 CHECK (priority BETWEEN 1 AND 99),
  vault_secret_id         UUID NOT NULL,
  masked_preview          TEXT NOT NULL,
  vault_refresh_secret_id UUID NULL,
  masked_refresh_preview  TEXT NULL,
  expires_at              TIMESTAMPTZ NULL,
  status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'disabled')),
  last_error              TEXT NULL,
  note                    TEXT NOT NULL DEFAULT '',
  updated_by              UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_tokens_type_region_priority
  ON public.vault_tokens(token_type, region_code, priority);
CREATE INDEX IF NOT EXISTS idx_vault_tokens_status ON public.vault_tokens(status);

DROP TRIGGER IF EXISTS trg_vault_tokens_updated_at ON public.vault_tokens;
CREATE TRIGGER trg_vault_tokens_updated_at
  BEFORE UPDATE ON public.vault_tokens
  FOR EACH ROW
  EXECUTE FUNCTION private.set_updated_at();

-- 8. Bảng jms_credentials (Metadata tài khoản/mật khẩu đăng nhập JMS Write-Only)
CREATE TABLE IF NOT EXISTS public.jms_credentials (
  id                       BIGSERIAL PRIMARY KEY,
  cred_name                TEXT NOT NULL UNIQUE CHECK (cred_name ~ '^[A-Z0-9_.-]{2,64}$'),
  region_code              TEXT NOT NULL DEFAULT 'ALL',
  priority                 SMALLINT NOT NULL DEFAULT 1 CHECK (priority BETWEEN 1 AND 99),
  vault_username_secret_id UUID NOT NULL,
  vault_password_secret_id UUID NOT NULL,
  masked_username          TEXT NOT NULL,
  status                   TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  last_login_at            TIMESTAMPTZ NULL,
  last_error               TEXT NULL,
  note                     TEXT NOT NULL DEFAULT '',
  updated_by               UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_jms_creds_region_priority
  ON public.jms_credentials(region_code, priority);
CREATE INDEX IF NOT EXISTS idx_jms_creds_status ON public.jms_credentials(status);

DROP TRIGGER IF EXISTS trg_jms_creds_updated_at ON public.jms_credentials;
CREATE TRIGGER trg_jms_creds_updated_at
  BEFORE UPDATE ON public.jms_credentials
  FOR EACH ROW
  EXECUTE FUNCTION private.set_updated_at();

-- 9. Bảng security_audit_logs (Nhật ký bảo mật bất biến — Append-Only, cấm UPDATE/DELETE)
CREATE TABLE IF NOT EXISTS public.security_audit_logs (
  id             BIGSERIAL PRIMARY KEY,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id       UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  actor_email    TEXT NOT NULL DEFAULT 'SYSTEM',
  action         TEXT NOT NULL CHECK (action IN (
    'ADMIN_CREATED_USER',
    'PERMISSION_APPROVED',
    'PERMISSION_REVOKED',
    'TOKEN_SAVED',
    'TOKEN_STATUS_CHANGED',
    'TOKEN_DELETED',
    'JMS_CREDENTIAL_SAVED',
    'JMS_CREDENTIAL_STATUS_CHANGED',
    'JMS_CREDENTIAL_DELETED',
    'FIRST_PASSWORD_CHANGED',
    'BOOTSTRAP_ADMIN_GRANTED'
  )),
  target_user_id UUID NULL,
  target_email   TEXT NULL,
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.security_audit_logs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON public.security_audit_logs(action);

-- 10. Seed dữ liệu chuẩn (Idempotent)
INSERT INTO public.roles (id, code, name, description)
VALUES
  (1, 'regional', 'Regional Operations', 'Nhân sự vận hành khu vực — chỉ xem dữ liệu 1 khu vực được gán'),
  (2, 'hq',       'Headquarters (HQ)',   'Điều phối trung tâm — xem dữ liệu toàn quốc 7 khu vực, bắt buộc MFA'),
  (3, 'admin',    'Vault Administrator', 'Quản trị viên Kho Bảo Mật — cấp tài khoản & quản lý bí mật, bắt buộc MFA AAL2')
ON CONFLICT (id) DO UPDATE
SET code = EXCLUDED.code,
    name = EXCLUDED.name,
    description = EXCLUDED.description;

INSERT INTO public.regions (id, code, name, hub_codes)
VALUES
  (1, 'HN',  'Miền Bắc — Hà Nội',              ARRAY['024GW0', '024GW1', '024GW2']),
  (2, 'HP',  'Đông Bắc Bộ — Hải Phòng',        ARRAY['0225GW0', '0225GW1']),
  (3, 'BN',  'Trung Du Bắc Bộ — Bắc Ninh',     ARRAY['0222GW0', '0222GW1']),
  (4, 'DN',  'Miền Trung — Đà Nẵng',           ARRAY['0236GW0', '0236GW1']),
  (5, 'HCM', 'Hồ Chí Minh',                    ARRAY['028GW0', '028GW5', '028GW6']),
  (6, 'BD',  'Đông Nam Bộ — Bình Dương',       ARRAY['0274GW0', '0251GW0']),
  (7, 'CT',  'Tây Nam Bộ — Cần Thơ',           ARRAY['0292GW0', '0292GW1'])
ON CONFLICT (id) DO UPDATE
SET code = EXCLUDED.code,
    name = EXCLUDED.name,
    hub_codes = EXCLUDED.hub_codes;
-- ============================================================================
-- 01-supabase-db/002_rls_and_security_helpers.sql
-- Thiết lập RLS chặt chẽ, khóa bảng bí mật (Deny-All cho client),
-- trigger bất biến cho Audit Log, và hàm kiểm tra Admin AAL2 4 lớp.
-- ============================================================================

-- 1. Bật Row Level Security trên toàn bộ bảng public
ALTER TABLE public.roles                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.regions                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_region_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_tokens            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jms_credentials         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_audit_logs     ENABLE ROW LEVEL SECURITY;

-- Ép RLS kể cả khi có role bypass không mong muốn (trừ table owner/superuser/service_role)
ALTER TABLE public.vault_tokens            FORCE ROW LEVEL SECURITY;
ALTER TABLE public.jms_credentials         FORCE ROW LEVEL SECURITY;
ALTER TABLE public.security_audit_logs     FORCE ROW LEVEL SECURITY;

-- 2. Thu hồi toàn bộ quyền mặc định trên bảng từ anon & authenticated
REVOKE ALL ON TABLE
  public.roles,
  public.regions,
  public.users,
  public.user_region_permissions,
  public.vault_tokens,
  public.jms_credentials,
  public.security_audit_logs
FROM PUBLIC, anon, authenticated;

-- Chỉ cấp quyền SELECT tối thiểu cho authenticated ở 4 bảng hồ sơ/danh mục
-- (vault_tokens, jms_credentials, security_audit_logs KHÔNG cấp bất kỳ quyền trực tiếp nào!)
GRANT SELECT ON TABLE public.roles                   TO authenticated;
GRANT SELECT ON TABLE public.regions                 TO authenticated;
GRANT SELECT ON TABLE public.users                   TO authenticated;
GRANT SELECT ON TABLE public.user_region_permissions TO authenticated;

-- service_role toàn quyền phục vụ Edge Functions & Sync Worker
GRANT ALL ON TABLE
  public.roles,
  public.regions,
  public.users,
  public.user_region_permissions,
  public.vault_tokens,
  public.jms_credentials,
  public.security_audit_logs
TO service_role;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- 3. Chính sách RLS (Deny-by-Default cho anon; self-read cho authenticated)
DROP POLICY IF EXISTS roles_select_authenticated ON public.roles;
CREATE POLICY roles_select_authenticated
  ON public.roles
  FOR SELECT
  TO authenticated
  USING (true);

DROP POLICY IF EXISTS regions_select_authenticated ON public.regions;
CREATE POLICY regions_select_authenticated
  ON public.regions
  FOR SELECT
  TO authenticated
  USING (true);

DROP POLICY IF EXISTS users_select_own ON public.users;
CREATE POLICY users_select_own
  ON public.users
  FOR SELECT
  TO authenticated
  USING (id = auth.uid());

DROP POLICY IF EXISTS user_region_permissions_select_own ON public.user_region_permissions;
CREATE POLICY user_region_permissions_select_own
  ON public.user_region_permissions
  FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

-- Lưu ý: vault_tokens, jms_credentials, security_audit_logs cố tình KHÔNG tạo policy nào
-- cho anon hoặc authenticated => mọi truy vấn trực tiếp từ client đều bị chặn hoàn toàn.

-- 4. Bảo vệ tính bất biến (Append-Only) cho security_audit_logs
CREATE OR REPLACE FUNCTION private.prevent_audit_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '42501: Nhật ký bảo mật (security_audit_logs) là bất biến — cấm sửa hoặc xóa.'
    USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON public.security_audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
  BEFORE UPDATE OR DELETE ON public.security_audit_logs
  FOR EACH ROW
  EXECUTE FUNCTION private.prevent_audit_log_mutation();

-- 5. Hàm che chuỗi bí mật (Write-Only masking)
CREATE OR REPLACE FUNCTION private.mask_secret(p_plain TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_clean TEXT := COALESCE(btrim(p_plain), '');
  v_len   INTEGER := char_length(v_clean);
BEGIN
  IF v_len = 0 THEN
    RETURN '••••••••';
  ELSIF v_len <= 6 THEN
    RETURN '••••••••';
  ELSIF v_len <= 11 THEN
    RETURN left(v_clean, 2) || '••••••••' || right(v_clean, 2);
  ELSE
    RETURN left(v_clean, 4) || '••••••••' || right(v_clean, 4);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION private.mask_username(p_plain TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_clean TEXT := COALESCE(btrim(p_plain), '');
  v_len   INTEGER := char_length(v_clean);
BEGIN
  IF v_len <= 2 THEN
    RETURN '•••';
  ELSIF v_len <= 5 THEN
    RETURN left(v_clean, 1) || '***' || right(v_clean, 1);
  ELSE
    RETURN left(v_clean, 2) || '••••' || right(v_clean, 2);
  END IF;
END;
$$;

-- 6. Hàm ghi Nhật ký bảo mật tập trung (không bao giờ lưu plaintext secret)
CREATE OR REPLACE FUNCTION private.write_audit_log(
  p_actor_id       UUID,
  p_actor_email    TEXT,
  p_action         TEXT,
  p_target_user_id UUID DEFAULT NULL,
  p_target_email   TEXT DEFAULT NULL,
  p_metadata       JSONB DEFAULT '{}'::jsonb
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private
AS $$
BEGIN
  INSERT INTO public.security_audit_logs (
    actor_id,
    actor_email,
    action,
    target_user_id,
    target_email,
    metadata
  )
  VALUES (
    p_actor_id,
    COALESCE(NULLIF(btrim(p_actor_email), ''), 'SYSTEM'),
    p_action,
    p_target_user_id,
    p_target_email,
    COALESCE(p_metadata, '{}'::jsonb)
  );
END;
$$;

-- 7. Lớp bảo vệ 4 tầng ngay trong PostgreSQL:
--    (1) Đã đăng nhập (auth.uid() NOT NULL)
--    (2) Hồ sơ tồn tại & đang kích hoạt (is_active = true) & đã đổi MK lần đầu (must_change_password = false)
--    (3) Vai trò chính xác là 'admin'
--    (4) JWT đã xác thực 2 lớp MFA mức 'aal2'
CREATE OR REPLACE FUNCTION private.assert_admin_aal2()
RETURNS TABLE (actor_id UUID, actor_email TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_uid        UUID;
  v_aal        TEXT;
  v_email      TEXT;
  v_is_active  BOOLEAN;
  v_must_chg   BOOLEAN;
  v_role_code  TEXT;
BEGIN
  v_uid := auth.uid();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION '42501: Chưa đăng nhập hệ thống.'
      USING ERRCODE = '42501';
  END IF;

  SELECT u.email, u.is_active, u.must_change_password, r.code
  INTO v_email, v_is_active, v_must_chg, v_role_code
  FROM public.users u
  JOIN public.roles r ON r.id = u.role_id
  WHERE u.id = v_uid;

  IF NOT FOUND THEN
    RAISE EXCEPTION '42501: Không tìm thấy hồ sơ quản trị viên.'
      USING ERRCODE = '42501';
  END IF;

  IF NOT COALESCE(v_is_active, false) THEN
    RAISE EXCEPTION '42501: Tài khoản đang bị khóa hoặc chưa kích hoạt.'
      USING ERRCODE = '42501';
  END IF;

  IF v_role_code IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION '42501: Forbidden — Chức năng này chỉ dành cho vai trò ADMIN.'
      USING ERRCODE = '42501';
  END IF;

  IF COALESCE(v_must_chg, true) THEN
    RAISE EXCEPTION '42501: Phải hoàn tất đổi mật khẩu lần đầu trước khi truy cập Kho Bảo Mật.'
      USING ERRCODE = '42501';
  END IF;

  v_aal := COALESCE(auth.jwt() ->> 'aal', 'aal1');
  IF v_aal IS DISTINCT FROM 'aal2' THEN
    RAISE EXCEPTION '42501: Yêu cầu xác thực 2 lớp MFA (AAL2) trước khi thực thi thao tác.'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY SELECT v_uid, v_email;
END;
$$;

REVOKE ALL ON FUNCTION
  private.set_updated_at(),
  private.prevent_audit_log_mutation(),
  private.mask_secret(TEXT),
  private.mask_username(TEXT),
  private.write_audit_log(UUID, TEXT, TEXT, UUID, TEXT, JSONB),
  private.assert_admin_aal2()
FROM PUBLIC, anon, authenticated;
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
-- ============================================================================
-- 01-supabase-db/004_bootstrap_first_admin.sql
-- Hàm & lệnh mẫu khởi tạo Super Admin đầu tiên (CHỈ chạy tại Supabase SQL Editor).
--
-- CÁCH DÙNG TRÊN SUPABASE CLOUD:
--   Bước 1: Vào Supabase Dashboard -> Authentication -> Users -> "Add user"
--           -> Tạo tài khoản admin (Email + mật khẩu mạnh >= 12 ký tự, tick Auto Confirm User).
--   Bước 2: Mở SQL Editor, bỏ comment dòng SELECT bên dưới và thay đúng email của bạn rồi Run!
-- ============================================================================

CREATE OR REPLACE FUNCTION private.bootstrap_first_admin(
  p_email                TEXT,
  p_full_name            TEXT DEFAULT 'Super Admin',
  p_must_change_password BOOLEAN DEFAULT false
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, auth
AS $$
DECLARE
  v_clean_email TEXT := lower(btrim(COALESCE(p_email, '')));
  v_auth_uid    UUID;
  v_admin_role  SMALLINT;
BEGIN
  IF v_clean_email = '' THEN
    RAISE EXCEPTION '22023: Email Admin không được để trống.' USING ERRCODE = '22023';
  END IF;

  SELECT id INTO v_auth_uid
  FROM auth.users
  WHERE lower(email) = v_clean_email
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'P0002: Chưa tìm thấy email % trong auth.users. Hãy tạo user trong Supabase Authentication trước.', v_clean_email
      USING ERRCODE = 'P0002';
  END IF;

  SELECT id INTO v_admin_role FROM public.roles WHERE code = 'admin';

  INSERT INTO public.users (
    id, email, full_name, role_id, is_active, must_change_password, mfa_required, note
  )
  VALUES (
    v_auth_uid,
    v_clean_email,
    COALESCE(NULLIF(btrim(p_full_name), ''), 'Super Admin'),
    v_admin_role,
    true,
    COALESCE(p_must_change_password, false),
    true,
    'Bootstrap Super Admin khởi tạo hệ thống'
  )
  ON CONFLICT (id) DO UPDATE
  SET role_id              = v_admin_role,
      is_active            = true,
      must_change_password = COALESCE(p_must_change_password, false),
      mfa_required         = true,
      updated_at           = now();

  PERFORM private.write_audit_log(
    v_auth_uid,
    v_clean_email,
    'BOOTSTRAP_ADMIN_GRANTED',
    v_auth_uid,
    v_clean_email,
    jsonb_build_object(
      'full_name', p_full_name,
      'must_change_password', COALESCE(p_must_change_password, false)
    )
  );

  RETURN jsonb_build_object(
    'ok', true,
    'admin_id', v_auth_uid,
    'email', v_clean_email,
    'role', 'admin',
    'mfa_required', true
  );
END;
$$;

REVOKE ALL ON FUNCTION private.bootstrap_first_admin(TEXT, TEXT, BOOLEAN)
  FROM PUBLIC, anon, authenticated;

-- ============================================================================
-- BỎ COMMENT DÒNG DƯỚI ĐÂY KHI CHẠY TRONG SUPABASE SQL EDITOR ĐỂ CẤP ADMIN ĐẦU TIÊN:
-- ============================================================================
-- SELECT private.bootstrap_first_admin('admin@jtexpress.vn', 'Quản Trị Viên Hệ Thống', false);
-- ============================================================================
-- 01-supabase-db/005_worker_service_role_rpcs.sql
-- Hàm RPC giải mã bí mật DÀNH RIÊNG CHO SYNC WORKER PYTHON (service_role).
-- BẢO MẬT: Tuyệt đối REVOKE khỏi PUBLIC, anon, authenticated!
-- ============================================================================

-- 1. Lấy danh sách token đang active kèm giá trị giải mã cho Sync Worker
CREATE OR REPLACE FUNCTION public.worker_get_active_tokens(
  p_token_type  TEXT,
  p_region_code TEXT DEFAULT NULL
)
RETURNS TABLE (
  id                      BIGINT,
  token_name              TEXT,
  token_type              TEXT,
  region_code             TEXT,
  priority                SMALLINT,
  decrypted_token         TEXT,
  decrypted_refresh_token TEXT,
  expires_at              TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, vault
AS $$
DECLARE
  v_type   TEXT := lower(btrim(COALESCE(p_token_type, '')));
  v_region TEXT := upper(btrim(COALESCE(p_region_code, '')));
BEGIN
  IF v_type NOT IN ('jms_auth', 'feishu_oauth') THEN
    RAISE EXCEPTION '22023: Loại token không hợp lệ (%).', v_type USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT
    t.id,
    t.token_name,
    t.token_type,
    t.region_code,
    t.priority,
    s_main.decrypted_secret    AS decrypted_token,
    s_ref.decrypted_secret     AS decrypted_refresh_token,
    t.expires_at
  FROM public.vault_tokens t
  JOIN vault.decrypted_secrets s_main ON s_main.id = t.vault_secret_id
  LEFT JOIN vault.decrypted_secrets s_ref ON s_ref.id = t.vault_refresh_secret_id
  WHERE t.token_type = v_type
    AND t.status = 'active'
    AND (
      v_region = ''
      OR t.region_code = v_region
      OR t.region_code = 'ALL'
    )
  ORDER BY
    CASE WHEN v_region <> '' AND t.region_code = v_region THEN 0 ELSE 1 END,
    t.priority ASC,
    t.id ASC;
END;
$$;

-- 2. Lấy cặp tài khoản / mật khẩu JMS đang active cho Sync Worker tự login cấp lại authToken
CREATE OR REPLACE FUNCTION public.worker_get_active_jms_credentials(
  p_region_code TEXT DEFAULT NULL
)
RETURNS TABLE (
  id                 BIGINT,
  cred_name          TEXT,
  region_code        TEXT,
  priority           SMALLINT,
  decrypted_username TEXT,
  decrypted_password TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, vault
AS $$
DECLARE
  v_region TEXT := upper(btrim(COALESCE(p_region_code, '')));
BEGIN
  RETURN QUERY
  SELECT
    c.id,
    c.cred_name,
    c.region_code,
    c.priority,
    s_u.decrypted_secret AS decrypted_username,
    s_p.decrypted_secret AS decrypted_password
  FROM public.jms_credentials c
  JOIN vault.decrypted_secrets s_u ON s_u.id = c.vault_username_secret_id
  JOIN vault.decrypted_secrets s_p ON s_p.id = c.vault_password_secret_id
  WHERE c.status = 'active'
    AND (
      v_region = ''
      OR c.region_code = v_region
      OR c.region_code = 'ALL'
    )
  ORDER BY
    CASE WHEN v_region <> '' AND c.region_code = v_region THEN 0 ELSE 1 END,
    c.priority ASC,
    c.id ASC;
END;
$$;

-- 3. Worker báo trạng thái / lỗi của token (VD: đánh dấu expired khi JMS trả 401)
CREATE OR REPLACE FUNCTION public.worker_report_token_status(
  p_token_id   BIGINT,
  p_status     TEXT,
  p_last_error TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_stat TEXT := lower(btrim(COALESCE(p_status, '')));
BEGIN
  IF v_stat NOT IN ('active', 'expired', 'disabled') THEN
    RAISE EXCEPTION '22023: Trạng thái không hợp lệ.' USING ERRCODE = '22023';
  END IF;

  UPDATE public.vault_tokens
  SET status     = v_stat,
      last_error = NULLIF(left(btrim(COALESCE(p_last_error, '')), 500), ''),
      updated_at = now()
  WHERE id = p_token_id;
END;
$$;

-- 4. Worker báo kết quả đăng nhập tự động JMS
CREATE OR REPLACE FUNCTION public.worker_report_jms_login_result(
  p_cred_id    BIGINT,
  p_success    BOOLEAN,
  p_last_error TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.jms_credentials
  SET last_login_at = CASE WHEN COALESCE(p_success, false) THEN now() ELSE last_login_at END,
      last_error    = CASE WHEN COALESCE(p_success, false) THEN NULL ELSE left(COALESCE(p_last_error, 'Login failed'), 500) END,
      updated_at    = now()
  WHERE id = p_cred_id;
END;
$$;

-- KHÓA CỨNG: CHỈ service_role ĐƯỢC PHÉP THỰC THI
REVOKE ALL ON FUNCTION
  public.worker_get_active_tokens(TEXT, TEXT),
  public.worker_get_active_jms_credentials(TEXT),
  public.worker_report_token_status(BIGINT, TEXT, TEXT),
  public.worker_report_jms_login_result(BIGINT, BOOLEAN, TEXT)
FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION
  public.worker_get_active_tokens(TEXT, TEXT),
  public.worker_get_active_jms_credentials(TEXT),
  public.worker_report_token_status(BIGINT, TEXT, TEXT),
  public.worker_report_jms_login_result(BIGINT, BOOLEAN, TEXT)
TO service_role;
