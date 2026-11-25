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
