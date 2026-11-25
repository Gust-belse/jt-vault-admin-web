/**
 * 02-vault-admin-ui/js/auth-guard.js
 * Lớp bảo vệ xác thực 4 tầng dành riêng cho Kho Bảo Mật Admin.
 */

import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';
import {
  VAULT_POLICY,
  STRONG_PASSWORD_REGEX,
  getActiveSupabaseConfig
} from './config.js';

let _supabase = null;
let _supabaseCacheKey = '';

export function resetSupabaseClient() {
  _supabase = null;
  _supabaseCacheKey = '';
}

export function getSupabaseClient() {
  const cfg = getActiveSupabaseConfig();
  if (!cfg) return null;
  const cacheKey = `${cfg.url}|${cfg.anonKey}`;
  if (!_supabase || _supabaseCacheKey !== cacheKey) {
    _supabase = createClient(cfg.url, cfg.anonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: false
      }
    });
    _supabaseCacheKey = cacheKey;
  }
  return _supabase;
}

export async function requireAdminAal2() {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return { ok: false, reason: 'unconfigured' };
  }

  const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
  const authUser = sessionData?.session?.user || null;
  if (sessionErr || !authUser) {
    return { ok: false, reason: 'unauthenticated' };
  }

  const [userRes, regionsRes, aalRes, factorsRes] = await Promise.all([
    supabase
      .from('users')
      .select('id, email, full_name, is_active, must_change_password, mfa_required, roles(code)')
      .eq('id', authUser.id)
      .single(),
    supabase
      .from('regions')
      .select('id, code, name, hub_codes')
      .order('id', { ascending: true }),
    supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
    supabase.auth.mfa.listFactors()
  ]);

  if (userRes.error || !userRes.data) {
    return {
      ok: false,
      reason: 'error',
      message: 'Không tìm thấy hồ sơ người dùng trong hệ thống.'
    };
  }

  const roleCode = userRes.data.roles?.code || 'regional';
  const profile = {
    id: userRes.data.id,
    email: userRes.data.email,
    full_name: userRes.data.full_name || userRes.data.email,
    role_code: roleCode,
    is_active: Boolean(userRes.data.is_active),
    must_change_password: Boolean(userRes.data.must_change_password),
    mfa_required: Boolean(userRes.data.mfa_required)
  };

  if (!profile.is_active) {
    return { ok: false, reason: 'locked', user: authUser, profile };
  }

  if (profile.role_code !== VAULT_POLICY.requiredRole) {
    return { ok: false, reason: 'forbidden', user: authUser, profile };
  }

  if (profile.must_change_password) {
    return { ok: false, reason: 'must_change_password', user: authUser, profile };
  }

  const currentAal = aalRes.data?.currentLevel || 'aal1';
  const verifiedTotp = (factorsRes.data?.totp || []).find((f) => f.status === 'verified');

  if (currentAal !== VAULT_POLICY.requiredAal) {
    return {
      ok: false,
      reason: verifiedTotp ? 'mfa_verify_required' : 'mfa_enroll_required',
      user: authUser,
      profile,
      totpFactorId: verifiedTotp?.id || null
    };
  }

  return {
    ok: true,
    user: authUser,
    profile,
    regions: regionsRes.data || [],
    aal: currentAal
  };
}

export async function signInAdmin(email, password) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    throw new Error('Chưa cấu hình SUPABASE_URL và SUPABASE_ANON_KEY trong js/config.js.');
  }
  const cleanEmail = String(email || '').trim().toLowerCase();
  if (!cleanEmail || !password) {
    throw new Error('Vui lòng nhập đầy đủ email và mật khẩu.');
  }

  const { data, error } = await supabase.auth.signInWithPassword({
    email: cleanEmail,
    password: String(password)
  });
  if (error) {
    throw new Error(error.message || 'Đăng nhập thất bại.');
  }
  return data;
}

export async function changeFirstPassword(newPassword, confirmPassword) {
  const supabase = getSupabaseClient();
  if (!supabase) throw new Error('Chưa cấu hình Supabase.');

  if (newPassword !== confirmPassword) {
    throw new Error('Mật khẩu xác nhận không khớp.');
  }
  if (!STRONG_PASSWORD_REGEX.test(newPassword)) {
    throw new Error('Mật khẩu mới phải từ 12–72 ký tự, gồm chữ hoa, chữ thường, chữ số và ký tự đặc biệt.');
  }

  const { error: updateErr } = await supabase.auth.updateUser({ password: newPassword });
  if (updateErr) {
    throw new Error(updateErr.message || 'Không thể cập nhật mật khẩu mới.');
  }

  const { error: rpcErr } = await supabase.rpc('complete_first_password_change');
  if (rpcErr) {
    throw new Error(rpcErr.message || 'Không thể xác nhận hoàn tất đổi mật khẩu.');
  }
}

export async function enrollTotpMfa(friendlyName = 'JT-Vault-Authenticator') {
  const supabase = getSupabaseClient();
  if (!supabase) throw new Error('Chưa cấu hình Supabase.');

  const { data: existing } = await supabase.auth.mfa.listFactors();
  const unverified = (existing?.all || []).filter((f) => f.factor_type === 'totp' && f.status !== 'verified');
  for (const factor of unverified) {
    await supabase.auth.mfa.unenroll({ factorId: factor.id });
  }

  const { data, error } = await supabase.auth.mfa.enroll({
    factorType: 'totp',
    friendlyName
  });
  if (error || !data) {
    throw new Error(error?.message || 'Không thể khởi tạo mã QR MFA.');
  }

  return {
    factorId: data.id,
    qrCode: data.totp.qr_code,
    secret: data.totp.secret
  };
}

export async function verifyTotpMfa(factorId, otpCode) {
  const supabase = getSupabaseClient();
  if (!supabase) throw new Error('Chưa cấu hình Supabase.');

  const cleanCode = String(otpCode || '').trim();
  if (!/^\d{6}$/.test(cleanCode)) {
    throw new Error('Mã OTP phải gồm đúng 6 chữ số.');
  }

  const { data, error } = await supabase.auth.mfa.challengeAndVerify({
    factorId,
    code: cleanCode
  });
  if (error) {
    throw new Error(error.message || 'Mã OTP không đúng hoặc đã hết hạn.');
  }
  return data;
}

export async function signOutVault() {
  const supabase = getSupabaseClient();
  if (supabase) {
    await supabase.auth.signOut();
  }
}
