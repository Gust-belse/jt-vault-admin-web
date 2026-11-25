#!/usr/bin/env python3
"""
05-sandbox-pipeline/run_executor_and_integration.py
Bộ kiểm thử tích hợp & bảo mật tự động 4 tầng cho hệ thống Kho Bảo Mật Admin (J&T Express KPI-DPGS).

Chạy đầy đủ:
  docker compose -f 05-sandbox-pipeline/docker-compose.test.yml up -d
  python3 05-sandbox-pipeline/run_executor_and_integration.py --stage all
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT_DIR / "05-sandbox-pipeline" / "docker-compose.test.yml"
SHIM_SQL = ROOT_DIR / "05-sandbox-pipeline" / "sql" / "000_sandbox_supabase_shim.sql"
DB_DIR = ROOT_DIR / "01-supabase-db"
UI_DIR = ROOT_DIR / "02-vault-admin-ui"
EDGE_FN = ROOT_DIR / "supabase" / "functions" / "admin-create-user" / "index.ts"

MIGRATION_FILES = [
    DB_DIR / "001_schema_and_seed.sql",
    DB_DIR / "002_rls_and_security_helpers.sql",
    DB_DIR / "003_vault_rpc_functions.sql",
    DB_DIR / "004_bootstrap_first_admin.sql",
    DB_DIR / "005_worker_service_role_rpcs.sql",
]

PG_SERVICE = "vault-postgres-test"
PG_USER = "postgres"
PG_DB = "vault_sandbox"


class TestFailure(Exception):
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


def run_psql(sql: str, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = [
        "docker", "compose", "-f", str(COMPOSE_FILE),
        "exec", "-T", PG_SERVICE,
        "psql", "-U", PG_USER, "-d", PG_DB,
        "-v", "ON_ERROR_STOP=1",
        "-X", "-q", "-t", "-A",
    ]
    proc = subprocess.run(cmd, input=sql, text=True, capture_output=True)
    if expect_ok and proc.returncode != 0:
        raise TestFailure(f"SQL failed (rc={proc.returncode}):\n{proc.stderr}\n--- SQL ---\n{sql[:400]}")
    return proc


def run_psql_file(path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    run_psql(sql, expect_ok=True)


def wait_for_postgres(timeout_s: int = 45) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        proc = subprocess.run(
            [
                "docker", "compose", "-f", str(COMPOSE_FILE),
                "exec", "-T", PG_SERVICE,
                "pg_isready", "-U", PG_USER, "-d", PG_DB,
            ],
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            return
        time.sleep(1)
    raise TestFailure("PostgreSQL sandbox container did not become ready in time.")


def run_as_jwt(role: str, sub: str | None, aal: str | None, body_sql: str, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
    claims: dict[str, str] = {}
    if sub:
        claims["sub"] = sub
    if aal:
        claims["aal"] = aal
    claims["role"] = role
    claims_json = json.dumps(claims).replace("'", "''")
    wrapped = f"""
    BEGIN;
    SET LOCAL "request.jwt.claims" = '{claims_json}';
    SET LOCAL ROLE {role};
    {body_sql}
    COMMIT;
    """
    return run_psql(wrapped, expect_ok=expect_ok)


def assert_sql_fails_with(proc: subprocess.CompletedProcess[str], expected_fragment: str, label: str) -> None:
    if proc.returncode == 0:
        raise TestFailure(f"[{label}] Expected SQL failure containing '{expected_fragment}', but succeeded! stdout={proc.stdout}")
    combined = f"{proc.stderr}\n{proc.stdout}"
    if expected_fragment.lower() not in combined.lower():
        raise TestFailure(f"[{label}] Expected error fragment '{expected_fragment}', got:\n{combined}")


def stage_db() -> None:
    log("\n=== [STAGE 1/4: DB] Khởi tạo Schema, RLS, Vault & Kiểm tra Idempotency ===")
    wait_for_postgres()

    # Dọn sạch DB để mỗi lần chạy đều deterministic
    run_psql("DROP SCHEMA IF EXISTS public, private, auth, vault CASCADE; CREATE SCHEMA public;")
    run_psql_file(SHIM_SQL)

    for mig in MIGRATION_FILES:
        run_psql_file(mig)
    log("  ✓ Áp dụng thành công lần 1 cho 5 tệp SQL migration (001 -> 005)")

    # Áp dụng lại lần 2 để kiểm tra idempotency
    for mig in MIGRATION_FILES:
        run_psql_file(mig)
    log("  ✓ Áp dụng lại lần 2 (idempotent 100%)")

    # Kiểm tra combined SQL file khớp với 5 tệp thành phần
    combined_path = DB_DIR / "full_deploy_supabase_sql_editor.sql"
    supa_mig_path = ROOT_DIR / "supabase" / "migrations" / "20261125000001_init_vault_backend.sql"
    expected_combined = "".join(p.read_text(encoding="utf-8") for p in MIGRATION_FILES)
    if combined_path.read_text(encoding="utf-8") != expected_combined:
        raise TestFailure("full_deploy_supabase_sql_editor.sql không đồng bộ với các tệp 001..005!")
    if supa_mig_path.read_text(encoding="utf-8") != expected_combined:
        raise TestFailure("supabase/migrations/20261125000001_init_vault_backend.sql không đồng bộ!")
    log("  ✓ Tệp SQL tổng hợp Dashboard & Supabase CLI migration đồng bộ hoàn toàn")

    # Kiểm tra seed 3 roles & 7 regions
    roles_cnt = int(run_psql("SELECT count(*) FROM public.roles;").stdout.strip())
    regions_cnt = int(run_psql("SELECT count(*) FROM public.regions;").stdout.strip())
    if roles_cnt != 3 or regions_cnt != 7:
        raise TestFailure(f"Seed count sai: roles={roles_cnt} (expected 3), regions={regions_cnt} (expected 7)")
    log("  ✓ Đủ 3 vai trò (regional, hq, admin) và 7 khu vực J&T Express Việt Nam")

    # Kiểm tra RLS bật trên toàn bộ 7 bảng public
    rls_off = run_psql("""
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN ('roles','regions','users','user_region_permissions','vault_tokens','jms_credentials','security_audit_logs')
          AND NOT rowsecurity;
    """).stdout.strip()
    if rls_off:
        raise TestFailure(f"Bảng chưa bật RLS: {rls_off}")
    log("  ✓ Toàn bộ 7 bảng public đều đã bật Row Level Security (RLS)")


def stage_security() -> None:
    log("\n=== [STAGE 2/4: SECURITY] Kiểm thử 4 tầng AAL2, Write-Only Vault, Audit bất biến & Worker RPC ===")

    # Tạo 5 tài khoản kiểm thử trong auth.users
    uids = {
        "superadmin": "11111111-1111-4111-8111-111111111111",
        "admin_firstpass": "22222222-2222-4222-8222-222222222222",
        "admin_locked": "33333333-3333-4333-8333-333333333333",
        "hq": "44444444-4444-4444-8444-444444444444",
        "regional_hcm": "55555555-5555-4555-8555-555555555555",
    }

    run_psql(f"""
        INSERT INTO auth.users (id, email) VALUES
          ('{uids["superadmin"]}',      'superadmin@jtexpress.vn'),
          ('{uids["admin_firstpass"]}', 'admin.first@jtexpress.vn'),
          ('{uids["admin_locked"]}',    'admin.locked@jtexpress.vn'),
          ('{uids["hq"]}',              'hq.ops@jtexpress.vn'),
          ('{uids["regional_hcm"]}',    'hcm.ops@jtexpress.vn')
        ON CONFLICT (id) DO NOTHING;

        SELECT private.bootstrap_first_admin('superadmin@jtexpress.vn', 'Super Admin Test', false);

        INSERT INTO public.users (id, email, full_name, role_id, is_active, must_change_password, mfa_required)
        VALUES
          ('{uids["admin_firstpass"]}', 'admin.first@jtexpress.vn',  'Admin First Login', (SELECT id FROM public.roles WHERE code='admin'),    true,  true,  true),
          ('{uids["admin_locked"]}',    'admin.locked@jtexpress.vn', 'Admin Locked',      (SELECT id FROM public.roles WHERE code='admin'),    false, false, true),
          ('{uids["hq"]}',              'hq.ops@jtexpress.vn',       'HQ Viewer',         (SELECT id FROM public.roles WHERE code='hq'),       true,  false, true),
          ('{uids["regional_hcm"]}',    'hcm.ops@jtexpress.vn',      'Regional HCM',      (SELECT id FROM public.roles WHERE code='regional'), true,  false, false)
        ON CONFLICT (id) DO NOTHING;
    """)
    log("  ✓ Bootstrap Super Admin & tạo bộ 5 tài khoản kiểm thử (Admin, FirstPass, Locked, HQ, Regional)")

    # 1. Kiểm tra anon bị chặn hoàn toàn
    assert_sql_fails_with(run_as_jwt("anon", None, None, "SELECT * FROM public.users;", expect_ok=False), "permission denied", "anon-users")
    assert_sql_fails_with(run_as_jwt("anon", None, None, "SELECT * FROM public.admin_list_users();", expect_ok=False), "permission denied", "anon-rpc")
    log("  ✓ [401/42501] Vai trò anon bị chặn truy cập bảng và RPC")

    # 2. Kiểm tra Regional & HQ bị chặn 42501 ngay cả khi có AAL2
    for label, uid in [("regional-aal2", uids["regional_hcm"]), ("hq-aal2", uids["hq"])]:
        assert_sql_fails_with(run_as_jwt("authenticated", uid, "aal2", "SELECT * FROM public.admin_list_users();", expect_ok=False), "42501", label)
        assert_sql_fails_with(run_as_jwt("authenticated", uid, "aal2", "SELECT public.admin_save_token('T1','jms_auth','secret_token_123456','HCM',1,'clear',NULL,NULL,'');", expect_ok=False), "42501", f"{label}-token")
        assert_sql_fails_with(run_as_jwt("authenticated", uid, "aal2", "SELECT * FROM public.admin_get_audit_logs(10);", expect_ok=False), "42501", f"{label}-audit")
    log("  ✓ [42501] Tài khoản Regional và HQ bị PostgreSQL chặn cứng (kể cả có AAL2)")

    # 3. Kiểm tra Admin thiếu AAL2 (chỉ aal1) và Admin bị khóa
    assert_sql_fails_with(run_as_jwt("authenticated", uids["superadmin"], "aal1", "SELECT * FROM public.admin_list_users();", expect_ok=False), "42501", "admin-aal1")
    assert_sql_fails_with(run_as_jwt("authenticated", uids["admin_locked"], "aal2", "SELECT * FROM public.admin_list_users();", expect_ok=False), "42501", "admin-locked")
    log("  ✓ [42501] Admin chưa MFA (AAL1) và Admin bị khóa đều bị chặn")

    # 4. Kiểm tra Admin chưa đổi MK lần đầu -> bị chặn Admin RPC, nhưng được gọi complete_first_password_change()
    assert_sql_fails_with(run_as_jwt("authenticated", uids["admin_firstpass"], "aal2", "SELECT * FROM public.admin_list_users();", expect_ok=False), "42501", "admin-firstpass-blocked")
    run_as_jwt("authenticated", uids["admin_firstpass"], "aal1", "SELECT public.complete_first_password_change();", expect_ok=True)
    res_after = run_as_jwt("authenticated", uids["admin_firstpass"], "aal2", "SELECT count(*) FROM public.admin_list_users();", expect_ok=True)
    if res_after.stdout.strip() != "5":
        raise TestFailure(f"Expected 5 users after first password change, got: {res_after.stdout}")
    log("  ✓ Luồng ép đổi mật khẩu lần đầu (complete_first_password_change) hoạt động chính xác")

    # 5. Kiểm tra RLS cô lập dòng users & Deny-All trên bảng bí mật
    reg_visible = run_as_jwt("authenticated", uids["regional_hcm"], "aal1", "SELECT count(*) FROM public.users;", expect_ok=True).stdout.strip()
    if reg_visible != "1":
        raise TestFailure(f"RLS leak: Regional user saw {reg_visible} rows in public.users (expected 1)")
    for tbl in ["public.vault_tokens", "public.jms_credentials", "public.security_audit_logs", "vault.secrets", "vault.decrypted_secrets"]:
        assert_sql_fails_with(run_as_jwt("authenticated", uids["superadmin"], "aal2", f"SELECT * FROM {tbl};", expect_ok=False), "permission denied", f"direct-{tbl}")
    log("  ✓ RLS cô lập hồ sơ cá nhân & Deny-All chặn đọc trực tiếp mọi bảng bí mật/vault")

    # 6. Kiểm tra Tab 1: Duyệt / Thu hồi quyền + Chống tự khóa + Mã lỗi 22023 / P0002
    assert_sql_fails_with(
        run_as_jwt("authenticated", uids["superadmin"], "aal2",
                   f"SELECT public.admin_review_permission('{uids['superadmin']}', NULL, 'revoked', 'admin', false, 'self lock');",
                   expect_ok=False),
        "22023", "self-lockout"
    )
    assert_sql_fails_with(
        run_as_jwt("authenticated", uids["superadmin"], "aal2",
                   "SELECT public.admin_review_permission('99999999-9999-4999-8999-999999999999', 5, 'approved', 'regional', true, 'missing');",
                   expect_ok=False),
        "P0002", "missing-user"
    )
    run_as_jwt(
        "authenticated", uids["superadmin"], "aal2",
        f"SELECT public.admin_review_permission('{uids['regional_hcm']}', 5, 'approved', 'regional', true, 'Gan cum HCM');",
        expect_ok=True,
    )
    run_as_jwt(
        "authenticated", uids["superadmin"], "aal2",
        f"SELECT public.admin_review_permission('{uids['regional_hcm']}', 5, 'revoked', 'regional', false, 'Thu hoi quyen');",
        expect_ok=True,
    )
    log("  ✓ Tab 1 (admin_review_permission): duyệt 7 KV, thu hồi, chống tự khóa (22023) & P0002")

    # 7. Kiểm tra Tab 2: Lưu / Xoay vòng Token (JMS + Feishu keep/replace/clear) & Write-Only
    plain_jms_v1 = "JMS_SUPER_SECRET_TOKEN_ALPHA_998877"
    plain_jms_v2 = "JMS_ROTATED_SECRET_TOKEN_BETA_112233"
    plain_feishu = "FEISHU_USER_ACCESS_TOKEN_XYZ_776655"
    plain_refresh = "FEISHU_REFRESH_SECRET_TOKEN_RT_445566"

    saved_jms = json.loads(
        run_as_jwt(
            "authenticated", uids["superadmin"], "aal2",
            f"SELECT public.admin_save_token('jms_hcm_primary', 'jms_auth', '{plain_jms_v1}', 'HCM', 1, 'clear', NULL, NULL, 'Cum HCM');",
            expect_ok=True,
        ).stdout.strip()
    )
    if plain_jms_v1 in json.dumps(saved_jms) or saved_jms["token_name"] != "JMS_HCM_PRIMARY":
        raise TestFailure(f"Token save contract invalid: {saved_jms}")

    # Xoay vòng JMS token
    run_as_jwt(
        "authenticated", uids["superadmin"], "aal2",
        f"SELECT public.admin_save_token('JMS_HCM_PRIMARY', 'jms_auth', '{plain_jms_v2}', 'HCM', 1, 'clear', NULL, NULL, 'Rotated v2');",
        expect_ok=True,
    )

    # Lưu Feishu OAuth kèm Refresh Token -> xoay vòng giữ nguyên (keep) -> xóa refresh (clear)
    saved_feishu = json.loads(
        run_as_jwt(
            "authenticated", uids["superadmin"], "aal2",
            f"SELECT public.admin_save_token('FEISHU_VIEW_ALL', 'feishu_oauth', '{plain_feishu}', 'ALL', 1, 'replace', '{plain_refresh}', now() + interval '7 days', 'View only');",
            expect_ok=True,
        ).stdout.strip()
    )
    if not saved_feishu.get("masked_refresh_preview") or plain_refresh in json.dumps(saved_feishu):
        raise TestFailure(f"Feishu refresh mask invalid: {saved_feishu}")

    rotated_keep = json.loads(
        run_as_jwt(
            "authenticated", uids["superadmin"], "aal2",
            f"SELECT public.admin_save_token('FEISHU_VIEW_ALL', 'feishu_oauth', '{plain_feishu}_NEW', 'ALL', 1, 'keep', NULL, now() + interval '14 days', 'Keep RT');",
            expect_ok=True,
        ).stdout.strip()
    )
    if rotated_keep.get("masked_refresh_preview") != saved_feishu.get("masked_refresh_preview"):
        raise TestFailure("Feishu refresh_action='keep' did not preserve refresh token!")

    rotated_clear = json.loads(
        run_as_jwt(
            "authenticated", uids["superadmin"], "aal2",
            f"SELECT public.admin_save_token('FEISHU_VIEW_ALL', 'feishu_oauth', '{plain_feishu}_V3', 'ALL', 1, 'clear', NULL, NULL, 'Clear RT');",
            expect_ok=True,
        ).stdout.strip()
    )
    if rotated_clear.get("masked_refresh_preview") is not None:
        raise TestFailure("Feishu refresh_action='clear' did not clear masked_refresh_preview!")

    # Kiểm tra masked listing không lộ plaintext
    masked_tokens_out = run_as_jwt(
        "authenticated", uids["superadmin"], "aal2",
        "SELECT jsonb_agg(to_jsonb(t)) FROM public.admin_list_tokens_masked() t;",
        expect_ok=True,
    ).stdout.strip()
    for secret_str in [plain_jms_v1, plain_jms_v2, plain_feishu, plain_refresh]:
        if secret_str in masked_tokens_out:
            raise TestFailure(f"SECURITY LEAK: Plaintext secret found in admin_list_tokens_masked()!")

    # Toggle & Delete token Feishu + xác minh bản ghi trong vault.secrets bị xóa sạch
    feishu_id = int(saved_feishu["id"])
    run_as_jwt("authenticated", uids["superadmin"], "aal2", f"SELECT public.admin_toggle_token({feishu_id}, 'disabled');", expect_ok=True)
    run_as_jwt("authenticated", uids["superadmin"], "aal2", f"SELECT public.admin_delete_token({feishu_id});", expect_ok=True)
    leftover_feishu_secrets = int(run_psql("SELECT count(*) FROM vault.secrets WHERE name LIKE '%FEISHU_VIEW_ALL%';").stdout.strip())
    if leftover_feishu_secrets != 0:
        raise TestFailure(f"Orphaned secrets remain in vault.secrets after token delete: {leftover_feishu_secrets}")
    log("  ✓ Tab 2 (Vault Tokens): mã hóa Write-Only, xoay vòng keep/replace/clear, bật/tắt & xóa sạch Vault")

    # 8. Kiểm tra Tab 3: Tài khoản / Mật khẩu JMS
    plain_jms_user = "jt_tms_reader_hcm01"
    plain_jms_pass = "VerySecretJmsPass!2026#99"
    saved_cred = json.loads(
        run_as_jwt(
            "authenticated", uids["superadmin"], "aal2",
            f"SELECT public.admin_save_jms_credentials('JMS_LOGIN_HCM_01', '{plain_jms_user}', '{plain_jms_pass}', 'HCM', 1, 'Auto login TMS');",
            expect_ok=True,
        ).stdout.strip()
    )
    masked_creds_out = run_as_jwt(
        "authenticated", uids["superadmin"], "aal2",
        "SELECT jsonb_agg(to_jsonb(c)) FROM public.admin_list_jms_credentials_masked() c;",
        expect_ok=True,
    ).stdout.strip()
    if plain_jms_pass in masked_creds_out or plain_jms_user in masked_creds_out:
        raise TestFailure("SECURITY LEAK: Plaintext JMS credential found in admin_list_jms_credentials_masked()!")

    # Tạo thêm 1 bản ghi để test toggle & delete
    saved_cred_del = json.loads(
        run_as_jwt(
            "authenticated", uids["superadmin"], "aal2",
            "SELECT public.admin_save_jms_credentials('JMS_LOGIN_TEMP', 'temp_user_01', 'TempPass!12345', 'HN', 2, 'Temp');",
            expect_ok=True,
        ).stdout.strip()
    )
    del_id = int(saved_cred_del["id"])
    run_as_jwt("authenticated", uids["superadmin"], "aal2", f"SELECT public.admin_toggle_jms_credential({del_id}, 'disabled');", expect_ok=True)
    run_as_jwt("authenticated", uids["superadmin"], "aal2", f"SELECT public.admin_delete_jms_credential({del_id});", expect_ok=True)
    leftover_cred_secrets = int(run_psql("SELECT count(*) FROM vault.secrets WHERE name LIKE '%JMS_LOGIN_TEMP%';").stdout.strip())
    if leftover_cred_secrets != 0:
        raise TestFailure("Orphaned JMS credential secrets remain in vault.secrets!")
    log("  ✓ Tab 3 (JMS Credentials): mã hóa kép username/password Write-Only, bật/tắt & xóa sạch Vault")

    # 9. Kiểm tra Tab 4: Nhật ký bảo mật bất biến (không rò plaintext + cấm UPDATE/DELETE)
    audit_dump = run_as_jwt(
        "authenticated", uids["superadmin"], "aal2",
        "SELECT jsonb_agg(to_jsonb(a)) FROM public.admin_get_audit_logs(200) a;",
        expect_ok=True,
    ).stdout.strip()
    for secret_str in [plain_jms_v1, plain_jms_v2, plain_feishu, plain_refresh, plain_jms_user, plain_jms_pass]:
        if secret_str in audit_dump:
            raise TestFailure("SECURITY LEAK: Plaintext secret leaked into security_audit_logs!")

    expected_actions = [
        "BOOTSTRAP_ADMIN_GRANTED",
        "FIRST_PASSWORD_CHANGED",
        "PERMISSION_APPROVED",
        "PERMISSION_REVOKED",
        "TOKEN_SAVED",
        "TOKEN_STATUS_CHANGED",
        "TOKEN_DELETED",
        "JMS_CREDENTIAL_SAVED",
        "JMS_CREDENTIAL_STATUS_CHANGED",
        "JMS_CREDENTIAL_DELETED",
    ]
    for act in expected_actions:
        if act not in audit_dump:
            raise TestFailure(f"Missing expected audit action: {act}")

    assert_sql_fails_with(run_psql("UPDATE public.security_audit_logs SET action = 'TOKEN_DELETED';", expect_ok=False), "42501", "audit-no-update")
    assert_sql_fails_with(run_psql("DELETE FROM public.security_audit_logs;", expect_ok=False), "42501", "audit-no-delete")
    log("  ✓ Tab 4 (Audit Logs): đủ 10 hành động kiểm thử, không lộ plaintext, bất biến (cấm UPDATE/DELETE)")

    # 10. Kiểm tra Worker Service-Role RPCs
    assert_sql_fails_with(
        run_as_jwt("authenticated", uids["superadmin"], "aal2", "SELECT * FROM public.worker_get_active_tokens('jms_auth', 'HCM');", expect_ok=False),
        "permission denied", "admin-cannot-call-worker-rpc"
    )
    worker_token = run_as_jwt(
        "service_role", None, None,
        "SELECT decrypted_token FROM public.worker_get_active_tokens('jms_auth', 'HCM') LIMIT 1;",
        expect_ok=True,
    ).stdout.strip()
    if worker_token != plain_jms_v2:
        raise TestFailure(f"Worker decrypted token mismatch: got '{worker_token}', expected '{plain_jms_v2}'")

    worker_cred = run_as_jwt(
        "service_role", None, None,
        "SELECT decrypted_username || '|' || decrypted_password FROM public.worker_get_active_jms_credentials('HCM') LIMIT 1;",
        expect_ok=True,
    ).stdout.strip()
    if worker_cred != f"{plain_jms_user}|{plain_jms_pass}":
        raise TestFailure("Worker decrypted JMS credential mismatch!")

    run_as_jwt(
        "service_role", None, None,
        f"SELECT public.worker_report_jms_login_result({int(saved_cred['id'])}, true, NULL);",
        expect_ok=True,
    )
    run_as_jwt(
        "service_role", None, None,
        f"SELECT public.worker_report_token_status({int(saved_jms['id'])}, 'expired', 'HTTP 401 Token Expired');",
        expect_ok=True,
    )
    log("  ✓ Worker RPC (service_role only): chặn client, giải mã chính xác & cập nhật trạng thái/lỗi")


def stage_edge() -> None:
    log("\n=== [STAGE 3/4: EDGE] Kiểm tra hợp đồng bảo mật Edge Function admin-create-user ===")
    if not EDGE_FN.exists():
        raise TestFailure(f"Missing Edge Function: {EDGE_FN}")
    src = EDGE_FN.read_text(encoding="utf-8")

    required_patterns = [
        ("CORS preflight OPTIONS", r"req\.method\s*===\s*'OPTIONS'"),
        ("Verify caller JWT via Auth", r"auth\.getUser"),
        ("Enforce AAL2", r"aal\s*!==\s*'aal2'"),
        ("Enforce active admin role", r"callerRole\s*!==\s*'admin'"),
        ("Strong password regex", r"STRONG_PASSWORD_REGEX"),
        ("Force first password change", r"must_change_password:\s*true"),
        ("Atomic rollback deleteUser", r"auth\.admin\.deleteUser"),
        ("Immutable audit log ADMIN_CREATED_USER", r"'ADMIN_CREATED_USER'"),
    ]
    for label, pattern in required_patterns:
        if not re.search(pattern, src):
            raise TestFailure(f"Edge Function missing required security control: {label}")

    # Đảm bảo không ghi tempPassword vào audit log metadata
    audit_section = src[src.find("ADMIN_CREATED_USER"):]
    if "tempPassword" in audit_section or "temp_password" in audit_section:
        raise TestFailure("SECURITY LEAK: Edge Function references tempPassword inside audit log section!")
    log("  ✓ Edge Function admin-create-user đạt đầy đủ 8 tiêu chí bảo mật & rollback nguyên tử")


def stage_ui() -> None:
    log("\n=== [STAGE 4/4: UI] Kiểm tra cú pháp ES Modules, đối chiếu DOM ID & tên RPC ===")
    vault_html_path = UI_DIR / "vault.html"
    index_html_path = ROOT_DIR / "index.html"
    if not vault_html_path.exists() or not index_html_path.exists():
        raise TestFailure("Thiếu index.html hoặc 02-vault-admin-ui/vault.html")

    vault_html = vault_html_path.read_text(encoding="utf-8")
    html_ids = set(re.findall(r'\bid="([^"]+)"', vault_html))

    js_files = sorted((UI_DIR / "js").glob("*.js"))
    if len(js_files) != 8:
        raise TestFailure(f"Expected 8 JS files in 02-vault-admin-ui/js, found {len(js_files)}")

    # 1. Kiểm tra cú pháp JS bằng Node (nếu có node)
    node_bin = shutil.which("node")
    if node_bin:
        for js_file in js_files:
            proc = subprocess.run([node_bin, "--check", str(js_file)], text=True, capture_output=True)
            if proc.returncode != 0:
                raise TestFailure(f"JS syntax error in {js_file.name}:\n{proc.stderr}")
        log(f"  ✓ Kiểm tra cú pháp thành công toàn bộ {len(js_files)} tệp ES Module (.js)")

    # 2. Đối chiếu mọi getElementById(...) trong JS phải tồn tại trong vault.html
    missing_ids: list[str] = []
    rpc_names_used: set[str] = set()
    for js_file in js_files:
        code = js_file.read_text(encoding="utf-8")
        # Chặn rò khóa service_role trong frontend
        if "SUPABASE_SERVICE_ROLE_KEY" in code:
            raise TestFailure(f"SECURITY LEAK: Frontend file {js_file.name} references SUPABASE_SERVICE_ROLE_KEY!")
        for dom_id in re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", code):
            if dom_id not in html_ids:
                missing_ids.append(f"{js_file.name}: #{dom_id}")
        for rpc_name in re.findall(r"\.rpc\(\s*['\"]([a-z0-9_]+)['\"]", code):
            rpc_names_used.add(rpc_name)

    if missing_ids:
        raise TestFailure(f"DOM ID mismatch between JS and vault.html: {missing_ids}")
    log(f"  ✓ Đối chiếu 100% DOM ID giữa 8 tệp JS và vault.html (0 thiếu hụt)")

    # 3. Đối chiếu mọi hàm RPC gọi từ JS đều có định nghĩa trong SQL 003
    rpc_sql = (DB_DIR / "003_vault_rpc_functions.sql").read_text(encoding="utf-8")
    defined_rpcs = set(re.findall(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.([a-z0-9_]+)\s*\(", rpc_sql, re.IGNORECASE))
    missing_rpcs = sorted(rpc_names_used - defined_rpcs)
    if missing_rpcs:
        raise TestFailure(f"RPC mismatch! Frontend calls undefined RPCs: {missing_rpcs}")
    log(f"  ✓ Đối chiếu 100% {len(rpc_names_used)} hàm RPC giữa Frontend JS và PostgreSQL SQL")


def main() -> int:
    parser = argparse.ArgumentParser(description="J&T Express KPI-DPGS Vault Integration Test Runner")
    parser.add_argument("--stage", choices=["all", "db", "security", "edge", "ui"], default="all")
    args = parser.parse_args()

    try:
        if args.stage in ("all", "db"):
            stage_db()
        if args.stage in ("all", "security"):
            if args.stage == "security":
                stage_db()
            stage_security()
        if args.stage in ("all", "edge"):
            stage_edge()
        if args.stage in ("all", "ui"):
            stage_ui()
    except TestFailure as exc:
        log(f"\n❌ KIỂM THỬ THẤT BẠI: {exc}")
        return 1

    log("\n✅ TOÀN BỘ KIỂM THỬ TÍCH HỢP & BẢO MẬT ĐÃ PASS 100%!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
