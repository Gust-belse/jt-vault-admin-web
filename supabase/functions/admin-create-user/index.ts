/**
 * supabase/functions/admin-create-user/index.ts
 * Edge Function cấp tài khoản nội bộ (Regional / HQ / Admin) dành riêng cho Admin AAL2.
 *
 * Luồng bảo mật:
 *  1. Xác thực chữ ký JWT người gọi qua Supabase Auth (auth.getUser).
 *  2. Kiểm tra claim `aal === 'aal2'` trong JWT đã được xác thực.
 *  3. Kiểm tra bảng `public.users` + `public.roles`: is_active = true, must_change_password = false, role = 'admin'.
 *  4. Validate email, họ tên, mật khẩu tạm mạnh (12-72 ký tự), vai trò và region_id (bắt buộc cho Regional).
 *  5. Dùng SUPABASE_SERVICE_ROLE_KEY tạo user trong auth.users (email_confirm: true),
 *     ghi public.users (must_change_password: true) + user_region_permissions + security_audit_logs.
 *  6. Rollback xóa auth.users nếu ghi DB thất bại để không sinh tài khoản mồ côi.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.4';

const STRONG_PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,72}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_ROLES = new Set(['regional', 'hq', 'admin']);

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8'
};

function jsonResponse(payload: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: CORS_HEADERS
  });
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    const decoded = atob(padded);
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: CORS_HEADERS });
  }

  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY') ?? '';
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';

  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
    return jsonResponse({ error: 'Thiếu biến môi trường Supabase trên Edge Function.' }, 500);
  }

  // 1. Kiểm tra Authorization Bearer JWT
  const authHeader = req.headers.get('Authorization') ?? '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return jsonResponse({ error: '42501: Thiếu token xác thực Authorization.' }, 401);
  }
  const callerJwt = match[1].trim();

  // Xác thực chữ ký JWT bằng Supabase Auth server
  const callerClient = createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: `Bearer ${callerJwt}` } },
    auth: { persistSession: false, autoRefreshToken: false }
  });

  const { data: callerAuthData, error: callerAuthErr } = await callerClient.auth.getUser(callerJwt);
  const callerUser = callerAuthData?.user ?? null;
  if (callerAuthErr || !callerUser) {
    return jsonResponse({ error: '42501: Phiên đăng nhập không hợp lệ hoặc đã hết hạn.' }, 401);
  }

  // 2. Kiểm tra mức xác thực 2 lớp MFA (AAL2) từ JWT đã được verify chữ ký
  const jwtPayload = decodeJwtPayload(callerJwt);
  const aal = String(jwtPayload?.aal ?? 'aal1');
  if (aal !== 'aal2') {
    return jsonResponse(
      { error: '42501: Yêu cầu quyền Admin đã xác thực 2 lớp MFA (AAL2).' },
      403
    );
  }

  // 3. Khởi tạo Service Role Client để kiểm tra hồ sơ Admin và tạo user
  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false }
  });

  const { data: callerProfile, error: profileErr } = await adminClient
    .from('users')
    .select('id, email, is_active, must_change_password, roles(code)')
    .eq('id', callerUser.id)
    .single();

  const callerRole = (callerProfile?.roles as { code?: string } | null)?.code ?? '';
  if (
    profileErr ||
    !callerProfile ||
    !callerProfile.is_active ||
    callerProfile.must_change_password ||
    callerRole !== 'admin'
  ) {
    return jsonResponse(
      { error: '42501: Forbidden — Chỉ Quản trị viên đang hoạt động (AAL2) mới được cấp tài khoản.' },
      403
    );
  }

  // 4. Đọc và kiểm tra đầu vào JSON
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return jsonResponse({ error: '22023: Payload JSON không hợp lệ.' }, 400);
  }

  const email = String(body.email ?? '').trim().toLowerCase();
  const fullName = String(body.full_name ?? '').trim();
  const tempPassword = String(body.temp_password ?? '');
  const roleCode = String(body.role_code ?? 'regional').trim().toLowerCase();
  const regionIdRaw = body.region_id;
  const note = String(body.note ?? '').trim().slice(0, 500);

  if (!EMAIL_REGEX.test(email)) {
    return jsonResponse({ error: '22023: Email nhân sự không hợp lệ.' }, 400);
  }
  if (fullName.length < 2 || fullName.length > 120) {
    return jsonResponse({ error: '22023: Họ tên nhân sự phải từ 2–120 ký tự.' }, 400);
  }
  if (!STRONG_PASSWORD_REGEX.test(tempPassword)) {
    return jsonResponse(
      { error: '22023: Mật khẩu tạm phải từ 12–72 ký tự, gồm chữ hoa, chữ thường, chữ số và ký tự đặc biệt.' },
      400
    );
  }
  if (!ALLOWED_ROLES.has(roleCode)) {
    return jsonResponse({ error: '22023: Vai trò không hợp lệ (regional / hq / admin).' }, 400);
  }

  const regionId = roleCode === 'regional' ? Number(regionIdRaw) : null;
  if (roleCode === 'regional' && (!Number.isInteger(regionId) || (regionId as number) <= 0)) {
    return jsonResponse({ error: '22023: Tài khoản Regional bắt buộc chọn 1 trong 7 khu vực.' }, 400);
  }

  // Kiểm tra role & region tồn tại trong DB trước khi tạo auth user
  const { data: roleRow, error: roleErr } = await adminClient
    .from('roles')
    .select('id, code')
    .eq('code', roleCode)
    .single();

  if (roleErr || !roleRow) {
    return jsonResponse({ error: '22023: Không tìm thấy vai trò trong hệ thống.' }, 400);
  }

  let regionCode: string | null = null;
  if (roleCode === 'regional' && regionId !== null) {
    const { data: regRow, error: regErr } = await adminClient
      .from('regions')
      .select('id, code')
      .eq('id', regionId)
      .single();

    if (regErr || !regRow) {
      return jsonResponse({ error: '22023: Khu vực được chọn không tồn tại.' }, 400);
    }
    regionCode = regRow.code;
  }

  // 5. Tạo tài khoản trong auth.users (xác thực email sẵn vì Admin cấp trực tiếp)
  const { data: createdAuth, error: createAuthErr } = await adminClient.auth.admin.createUser({
    email,
    password: tempPassword,
    email_confirm: true,
    user_metadata: {
      full_name: fullName,
      created_by_admin: callerProfile.email
    }
  });

  if (createAuthErr || !createdAuth?.user) {
    const errMsg = createAuthErr?.message || 'Không thể tạo tài khoản Auth.';
    const status = errMsg.toLowerCase().includes('already') ? 409 : 400;
    return jsonResponse({ error: errMsg }, status);
  }

  const newUserId = createdAuth.user.id;
  const mfaRequired = roleCode === 'hq' || roleCode === 'admin';

  try {
    // Ghi hồ sơ public.users (ép đổi mật khẩu lần đầu)
    const { error: insertUserErr } = await adminClient.from('users').insert({
      id: newUserId,
      email,
      full_name: fullName,
      role_id: roleRow.id,
      is_active: true,
      must_change_password: true,
      mfa_required: mfaRequired,
      note,
      created_by: callerUser.id
    });

    if (insertUserErr) {
      throw new Error(insertUserErr.message);
    }

    // Nếu là Regional -> gán quyền khu vực đã duyệt sẵn
    if (roleCode === 'regional' && regionId !== null) {
      const { error: permErr } = await adminClient.from('user_region_permissions').insert({
        user_id: newUserId,
        region_id: regionId,
        status: 'approved',
        note: note || 'Cấp quyền ban đầu khi Admin tạo tài khoản',
        reviewed_by: callerUser.id,
        reviewed_at: new Date().toISOString()
      });

      if (permErr) {
        throw new Error(permErr.message);
      }
    }

    // Ghi Nhật ký bảo mật bất biến (TUYỆT ĐỐI không lưu mật khẩu tạm!)
    const { error: auditErr } = await adminClient.from('security_audit_logs').insert({
      actor_id: callerUser.id,
      actor_email: callerProfile.email,
      action: 'ADMIN_CREATED_USER',
      target_user_id: newUserId,
      target_email: email,
      metadata: {
        full_name: fullName,
        role_code: roleCode,
        region_id: regionId,
        region_code: regionCode,
        mfa_required: mfaRequired,
        must_change_password: true,
        note
      }
    });

    if (auditErr) {
      throw new Error(auditErr.message);
    }
  } catch (dbErr) {
    // Rollback auth.users nếu ghi DB lỗi để tránh tài khoản mồ côi
    await adminClient.auth.admin.deleteUser(newUserId).catch(() => undefined);
    const msg = dbErr instanceof Error ? dbErr.message : 'Lỗi ghi dữ liệu hồ sơ người dùng.';
    return jsonResponse({ error: `Tạo tài khoản thất bại (đã rollback): ${msg}` }, 500);
  }

  return jsonResponse(
    {
      ok: true,
      user_id: newUserId,
      email,
      full_name: fullName,
      role_code: roleCode,
      region_id: regionId,
      region_code: regionCode,
      must_change_password: true,
      mfa_required: mfaRequired
    },
    200
  );
});
