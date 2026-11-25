/**
 * 02-vault-admin-ui/js/config.js
 * Cấu hình kết nối công khai & tiện ích bảo mật dùng chung cho Kho Bảo Mật Admin.
 * BẢO MẬT: Chỉ khai báo SUPABASE_URL và SUPABASE_ANON_KEY công khai.
 */

export const SUPABASE_CONFIG = Object.freeze({
  url: 'https://YOUR_PROJECT_REF.supabase.co',
  anonKey: 'YOUR_SUPABASE_ANON_KEY'
});

const RUNTIME_CONFIG_STORAGE_KEY = 'jt_vault_supabase_public_config_v1';

export const VAULT_POLICY = Object.freeze({
  minPasswordLength: 12,
  maxPasswordLength: 72,
  requiredRole: 'admin',
  requiredAal: 'aal2',
  allowedTokenTypes: ['jms_auth', 'feishu_oauth'],
  allowedRefreshActions: ['keep', 'replace', 'clear']
});

export const STRONG_PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,72}$/;

function isStaticSupabaseConfigured() {
  return (
    Boolean(SUPABASE_CONFIG.url) &&
    Boolean(SUPABASE_CONFIG.anonKey) &&
    !SUPABASE_CONFIG.url.includes('YOUR_PROJECT_REF') &&
    !SUPABASE_CONFIG.anonKey.includes('YOUR_SUPABASE_ANON_KEY')
  );
}

function decodeJwtPayloadSafe(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

export function assertSafePublicAnonKey(url, anonKey) {
  const cleanUrl = String(url || '').trim().replace(/\/+$/, '');
  const cleanKey = String(anonKey || '').trim();

  if (!cleanUrl || !cleanKey) {
    throw new Error('Vui lòng nhập đầy đủ SUPABASE_URL và SUPABASE_ANON_KEY.');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(cleanUrl);
  } catch {
    throw new Error('SUPABASE_URL không đúng định dạng URL hợp lệ.');
  }

  const isHttpsSupabase =
    parsedUrl.protocol === 'https:' &&
    (parsedUrl.hostname.endsWith('.supabase.co') || parsedUrl.hostname.endsWith('.supabase.in'));
  const isLocalDev =
    (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') &&
    (parsedUrl.hostname === 'localhost' || parsedUrl.hostname === '127.0.0.1');

  if (!isHttpsSupabase && !isLocalDev) {
    throw new Error(
      'SUPABASE_URL phải là tên miền HTTPS Supabase Cloud (*.supabase.co) hoặc máy chủ cục bộ localhost/127.0.0.1.'
    );
  }

  // Chặn tuyệt đối việc nhập nhầm khóa bí mật service_role vào trình duyệt
  if (cleanKey.startsWith('sb_secret_')) {
    throw new Error('CẢNH BÁO BẢO MẬT: Phát hiện Secret Key (sb_secret_*). Tuyệt đối chỉ dùng Anon/Publishable Key công khai!');
  }
  const jwtPayload = decodeJwtPayloadSafe(cleanKey);
  if (jwtPayload && ['service_role', 'supabase_admin'].includes(String(jwtPayload.role || '').toLowerCase())) {
    throw new Error('CẢNH BÁO BẢO MẬT: Phát hiện service_role JWT! Tuyệt đối không dán khóa bí mật này vào trình duyệt.');
  }

  return { url: cleanUrl, anonKey: cleanKey };
}

function readRuntimeSupabaseConfig() {
  if (isStaticSupabaseConfigured()) return null;
  try {
    const raw = window.localStorage?.getItem(RUNTIME_CONFIG_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return assertSafePublicAnonKey(parsed?.url, parsed?.anonKey);
  } catch {
    return null;
  }
}

export function getActiveSupabaseConfig() {
  if (isStaticSupabaseConfigured()) {
    return { url: SUPABASE_CONFIG.url, anonKey: SUPABASE_CONFIG.anonKey, source: 'static' };
  }
  const runtime = readRuntimeSupabaseConfig();
  if (runtime) {
    return { ...runtime, source: 'runtime' };
  }
  return null;
}

export function isUsingRuntimeConfig() {
  return !isStaticSupabaseConfigured() && Boolean(readRuntimeSupabaseConfig());
}

export function saveRuntimeSupabaseConfig(url, anonKey) {
  if (isStaticSupabaseConfigured()) {
    throw new Error('Cấu hình Supabase đã được khóa tĩnh trong js/config.js.');
  }
  const safe = assertSafePublicAnonKey(url, anonKey);
  window.localStorage.setItem(RUNTIME_CONFIG_STORAGE_KEY, JSON.stringify(safe));
  return safe;
}

export function clearRuntimeSupabaseConfig() {
  try {
    window.localStorage?.removeItem(RUNTIME_CONFIG_STORAGE_KEY);
  } catch {
    // ignore storage errors
  }
}

export function isSupabaseConfigured() {
  return Boolean(getActiveSupabaseConfig());
}

export function escHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]));
}

export function fmtTime(isoString) {
  if (!isoString) return '--';
  const str = String(isoString);
  return str.includes('T') ? str.replace('T', ' ').slice(0, 19) : str.slice(0, 19);
}

export function showToast(message, type = 'info', containerId = 'toastBox') {
  const container = document.getElementById(containerId);
  if (!container) return;

  const palette = {
    info: 'bg-slate-900 text-white border-slate-700',
    success: 'bg-emerald-700 text-white border-emerald-500',
    warning: 'bg-amber-700 text-white border-amber-500',
    error: 'bg-rose-700 text-white border-rose-500'
  };

  const toast = document.createElement('div');
  toast.className = `px-4 py-3 rounded-xl border text-xs font-bold shadow-lg transition-opacity duration-200 ${palette[type] || palette.info}`;
  toast.textContent = String(message || '');
  container.appendChild(toast);

  window.setTimeout(() => {
    toast.style.opacity = '0';
    window.setTimeout(() => toast.remove(), 220);
  }, 4200);
}

export function generateStrongPassword(length = 16) {
  const safeLen = Math.min(Math.max(Number(length) || 16, 12), 64);
  const groups = [
    'ABCDEFGHJKLMNPQRSTUVWXYZ',
    'abcdefghijkmnopqrstuvwxyz',
    '23456789',
    '!@#$%^&*-_=+?'
  ];
  const pool = groups.join('');

  const randomUint32 = (maxExclusive) => {
    const arr = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    let val = 0;
    do {
      crypto.getRandomValues(arr);
      val = arr[0];
    } while (val >= limit);
    return val % maxExclusive;
  };

  const chars = groups.map((charset) => charset[randomUint32(charset.length)]);
  while (chars.length < safeLen) {
    chars.push(pool[randomUint32(pool.length)]);
  }

  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomUint32(i + 1);
    const tmp = chars[i];
    chars[i] = chars[j];
    chars[j] = tmp;
  }

  return chars.join('');
}
