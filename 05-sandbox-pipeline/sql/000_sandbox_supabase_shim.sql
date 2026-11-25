-- ============================================================================
-- 05-sandbox-pipeline/sql/000_sandbox_supabase_shim.sql
-- Mô phỏng các đối tượng nội bộ của Supabase Cloud (roles, auth.*, vault.*)
-- trên PostgreSQL 16 thuần để kiểm thử tự động 100% SQL production.
-- KHÔNG chạy tệp này trên Supabase Cloud (Supabase Cloud đã có sẵn auth & vault).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Tạo các role tiêu chuẩn của Supabase
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
  END IF;
END;
$$;

GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- 2. Mô phỏng schema auth của Supabase GoTrue
CREATE SCHEMA IF NOT EXISTS auth;
GRANT USAGE ON SCHEMA auth TO authenticated, service_role;

CREATE TABLE IF NOT EXISTS auth.users (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email      TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS JSONB
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  );
$$;

CREATE OR REPLACE FUNCTION auth.uid()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(auth.jwt() ->> 'sub', '')::uuid;
$$;

GRANT EXECUTE ON FUNCTION auth.jwt(), auth.uid() TO anon, authenticated, service_role;

-- 3. Mô phỏng schema vault của Supabase Vault (mã hóa đối xứng pgp_sym_encrypt trong sandbox)
CREATE SCHEMA IF NOT EXISTS vault;
REVOKE ALL ON SCHEMA vault FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA vault TO service_role;

CREATE TABLE IF NOT EXISTS vault.secrets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  secret      BYTEA NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

REVOKE ALL ON TABLE vault.secrets FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE vault.secrets TO service_role;

CREATE OR REPLACE VIEW vault.decrypted_secrets AS
SELECT
  id,
  name,
  description,
  pgp_sym_decrypt(secret, 'kpi_dpgs_sandbox_internal_vault_key_2026') AS decrypted_secret,
  created_at,
  updated_at
FROM vault.secrets;

REVOKE ALL ON TABLE vault.decrypted_secrets FROM PUBLIC, anon, authenticated;
GRANT SELECT ON TABLE vault.decrypted_secrets TO service_role;

CREATE OR REPLACE FUNCTION vault.create_secret(
  new_secret      TEXT,
  new_name        TEXT DEFAULT NULL,
  new_description TEXT DEFAULT '',
  new_key_id      UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = vault, public
AS $$
DECLARE
  v_id UUID;
BEGIN
  INSERT INTO vault.secrets (name, description, secret)
  VALUES (
    new_name,
    COALESCE(new_description, ''),
    pgp_sym_encrypt(new_secret, 'kpi_dpgs_sandbox_internal_vault_key_2026')
  )
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION vault.update_secret(
  secret_id       UUID,
  new_secret      TEXT DEFAULT NULL,
  new_name        TEXT DEFAULT NULL,
  new_description TEXT DEFAULT NULL,
  new_key_id      UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = vault, public
AS $$
BEGIN
  UPDATE vault.secrets
  SET secret      = CASE WHEN new_secret IS NOT NULL
                         THEN pgp_sym_encrypt(new_secret, 'kpi_dpgs_sandbox_internal_vault_key_2026')
                         ELSE secret END,
      name        = COALESCE(new_name, name),
      description = COALESCE(new_description, description),
      updated_at  = now()
  WHERE id = secret_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Vault secret % not found', secret_id USING ERRCODE = 'P0002';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION
  vault.create_secret(TEXT, TEXT, TEXT, UUID),
  vault.update_secret(UUID, TEXT, TEXT, TEXT, UUID)
FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION
  vault.create_secret(TEXT, TEXT, TEXT, UUID),
  vault.update_secret(UUID, TEXT, TEXT, TEXT, UUID)
TO service_role;
