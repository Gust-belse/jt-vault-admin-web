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
