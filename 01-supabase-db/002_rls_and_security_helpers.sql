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
