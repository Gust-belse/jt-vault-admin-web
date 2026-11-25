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
