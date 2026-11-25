/**
 * 02-vault-admin-ui/js/vault-api.js
 * Tầng gọi API tập trung cho Kho Bảo Mật Admin.
 */

import { getSupabaseClient } from './auth-guard.js';
import { STRONG_PASSWORD_REGEX, VAULT_POLICY } from './config.js';

export function normalizeVaultError(err, fallbackMsg = 'Thao tác thất bại.') {
  if (!err) return fallbackMsg;

  const code = String(err.code || '');
  const rawMsg = String(err.message || err.error || fallbackMsg);

  if (code === '42501' || rawMsg.includes('42501') || rawMsg.toLowerCase().includes('forbidden')) {
    return 'Từ chối truy cập (42501): Yêu cầu quyền Admin đang kích hoạt và đã xác thực 2 lớp MFA (AAL2).';
  }
  if (code === '22023' || rawMsg.includes('22023')) {
    return `Dữ liệu đầu vào không hợp lệ (22023): ${rawMsg}`;
  }
  if (code === 'P0002' || rawMsg.includes('P0002')) {
    return 'Không tìm thấy bản ghi mục tiêu trong hệ thống.';
  }
  return rawMsg;
}

function assertClient() {
  const supabase = getSupabaseClient();
  if (!supabase) {
    throw new Error('Chưa cấu hình kết nối Supabase.');
  }
  return supabase;
}

export async function fetchVaultUsers() {
  const supabase = assertClient();
  const { data, error } = await supabase.rpc('admin_list_users');
  if (error) throw new Error(normalizeVaultError(error, 'Không thể tải danh sách tài khoản.'));
  return Array.isArray(data) ? data : [];
}

export async function createInternalUser({
  email,
  fullName,
  tempPassword,
  roleCode,
  regionId = null,
  note = ''
}) {
  const supabase = assertClient();
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanName = String(fullName || '').trim();
  const cleanRole = String(roleCode || 'regional').trim().toLowerCase();

  if (!cleanEmail || !cleanEmail.includes('@')) {
    throw new Error('Email nhân sự không hợp lệ.');
  }
  if (cleanName.length < 2) {
    throw new Error('Họ tên nhân sự phải có ít nhất 2 ký tự.');
  }
  if (!STRONG_PASSWORD_REGEX.test(String(tempPassword || ''))) {
    throw new Error('Mật khẩu tạm phải từ 12–72 ký tự, gồm chữ hoa, chữ thường, chữ số và ký tự đặc biệt.');
  }
  if (!['regional', 'hq', 'admin'].includes(cleanRole)) {
    throw new Error('Vai trò không hợp lệ.');
  }
  if (cleanRole === 'regional' && !regionId) {
    throw new Error('Tài khoản Regional bắt buộc phải chọn 1 trong 7 khu vực.');
  }

  const { data, error } = await supabase.functions.invoke('admin-create-user', {
    body: {
      email: cleanEmail,
      full_name: cleanName,
      temp_password: String(tempPassword),
      role_code: cleanRole,
      region_id: cleanRole === 'regional' ? Number(regionId) : null,
      note: String(note || '').trim()
    }
  });

  if (error) {
    let detailedErr = error;
    try {
      if (error.context && typeof error.context.json === 'function') {
        const bodyJson = await error.context.json();
        if (bodyJson?.error) {
          detailedErr = { message: bodyJson.error };
        }
      }
    } catch {
      // keep original error object
    }
    throw new Error(normalizeVaultError(detailedErr, 'Lỗi kết nối Edge Function tạo tài khoản.'));
  }
  if (data?.error) {
    throw new Error(normalizeVaultError({ message: data.error }, 'Tạo tài khoản thất bại.'));
  }
  return data;
}

export async function reviewUserPermission({
  targetUserId,
  regionId = null,
  status,
  roleCode = 'regional',
  activateUser = true,
  note = ''
}) {
  const supabase = assertClient();
  const { error } = await supabase.rpc('admin_review_permission', {
    p_target_user_id: targetUserId,
    p_region_id: roleCode === 'regional' && regionId ? Number(regionId) : null,
    p_status: status,
    p_role_code: roleCode,
    p_activate_user: Boolean(activateUser),
    p_note: String(note || '').trim()
  });

  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể cập nhật phân quyền người dùng.'));
  }
}

export async function fetchMaskedTokens() {
  const supabase = assertClient();
  const { data, error } = await supabase.rpc('admin_list_tokens_masked');
  if (error) throw new Error(normalizeVaultError(error, 'Không thể tải danh sách token.'));
  return Array.isArray(data) ? data : [];
}

export async function saveVaultToken({
  tokenName,
  tokenType,
  plainToken,
  regionCode = 'ALL',
  priority = 1,
  refreshAction = 'keep',
  plainRefreshToken = null,
  expiresAt = null,
  note = ''
}) {
  const supabase = assertClient();
  const cleanName = String(tokenName || '').trim().toUpperCase();
  const cleanToken = String(plainToken || '').trim();
  const cleanAction = String(refreshAction || 'keep').trim().toLowerCase();

  if (!cleanName || !cleanToken) {
    throw new Error('Tên định danh token và giá trị token không được để trống.');
  }
  if (!VAULT_POLICY.allowedTokenTypes.includes(tokenType)) {
    throw new Error('Loại token không hợp lệ.');
  }
  if (!VAULT_POLICY.allowedRefreshActions.includes(cleanAction)) {
    throw new Error('Hành động refresh token không hợp lệ.');
  }

  const { data, error } = await supabase.rpc('admin_save_token', {
    p_token_name: cleanName,
    p_token_type: tokenType,
    p_plain_token: cleanToken,
    p_region_code: String(regionCode || 'ALL').trim().toUpperCase(),
    p_priority: Number(priority) || 1,
    p_refresh_action: tokenType === 'feishu_oauth' ? cleanAction : 'clear',
    p_plain_refresh_token:
      tokenType === 'feishu_oauth' && cleanAction === 'replace' && plainRefreshToken
        ? String(plainRefreshToken).trim()
        : null,
    p_expires_at: tokenType === 'feishu_oauth' && expiresAt ? expiresAt : null,
    p_note: String(note || '').trim()
  });

  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể lưu token vào Kho Bảo Mật.'));
  }
  return data;
}

export async function toggleVaultToken(tokenId, nextStatus) {
  const supabase = assertClient();
  const { error } = await supabase.rpc('admin_toggle_token', {
    p_token_id: Number(tokenId),
    p_status: nextStatus
  });
  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể đổi trạng thái token.'));
  }
}

export async function deleteVaultToken(tokenId) {
  const supabase = assertClient();
  const { error } = await supabase.rpc('admin_delete_token', {
    p_token_id: Number(tokenId)
  });
  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể xóa token.'));
  }
}

export async function fetchMaskedJmsCredentials() {
  const supabase = assertClient();
  const { data, error } = await supabase.rpc('admin_list_jms_credentials_masked');
  if (error) throw new Error(normalizeVaultError(error, 'Không thể tải danh sách tài khoản JMS.'));
  return Array.isArray(data) ? data : [];
}

export async function saveJmsCredential({
  credName,
  plainUsername,
  plainPassword,
  regionCode = 'ALL',
  priority = 1,
  note = ''
}) {
  const supabase = assertClient();
  const cleanName = String(credName || '').trim().toUpperCase();
  const cleanUser = String(plainUsername || '').trim();
  const cleanPass = String(plainPassword || '').trim();

  if (!cleanName || !cleanUser || !cleanPass) {
    throw new Error('Tên định danh, tài khoản JMS và mật khẩu JMS không được để trống.');
  }

  const { data, error } = await supabase.rpc('admin_save_jms_credentials', {
    p_cred_name: cleanName,
    p_plain_username: cleanUser,
    p_plain_password: cleanPass,
    p_region_code: String(regionCode || 'ALL').trim().toUpperCase(),
    p_priority: Number(priority) || 1,
    p_note: String(note || '').trim()
  });

  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể lưu tài khoản/mật khẩu JMS.'));
  }
  return data;
}

export async function toggleJmsCredential(credId, nextStatus) {
  const supabase = assertClient();
  const { error } = await supabase.rpc('admin_toggle_jms_credential', {
    p_cred_id: Number(credId),
    p_status: nextStatus
  });
  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể đổi trạng thái tài khoản JMS.'));
  }
}

export async function deleteJmsCredential(credId) {
  const supabase = assertClient();
  const { error } = await supabase.rpc('admin_delete_jms_credential', {
    p_cred_id: Number(credId)
  });
  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể xóa tài khoản JMS.'));
  }
}

export async function fetchAuditLogs(limit = 120) {
  const supabase = assertClient();
  const { data, error } = await supabase.rpc('admin_get_audit_logs', {
    p_limit: Number(limit) || 120
  });
  if (error) {
    throw new Error(normalizeVaultError(error, 'Không thể tải nhật ký bảo mật.'));
  }
  return Array.isArray(data) ? data : [];
}
