/**
 * 02-vault-admin-ui/js/vault-app.js
 * Bộ điều phối chính cho Kho Bảo Mật Admin:
 *   Đăng nhập -> Đổi mật khẩu lần đầu -> Xác thực MFA (AAL2) -> 4 Tab quản trị tách biệt.
 */

import {
  isSupabaseConfigured,
  isUsingRuntimeConfig,
  saveRuntimeSupabaseConfig,
  clearRuntimeSupabaseConfig,
  showToast
} from './config.js';
import {
  requireAdminAal2,
  signInAdmin,
  changeFirstPassword,
  enrollTotpMfa,
  verifyTotpMfa,
  signOutVault,
  resetSupabaseClient
} from './auth-guard.js';
import { initUsersTab, loadUsersTab } from './ui-users.js';
import { initTokensTab, loadTokensTab } from './ui-tokens.js';
import { initJmsCredsTab, loadJmsCredsTab } from './ui-jms-creds.js';
import { initAuditTab, loadAuditTab } from './ui-audit.js';

const appState = {
  activeTab: 'users',
  profile: null,
  regions: [],
  pendingMfaFactorId: null
};

const GATE_BOX_IDS = [
  'unconfiguredBox',
  'lockedBox',
  'forbiddenBox',
  'errorBox',
  'loginFormWrap',
  'forcePassBox',
  'mfaBox'
];

function syncRuntimeConfigControls() {
  const runtimeBanner = document.getElementById('runtimeConfigBanner');
  runtimeBanner?.classList.toggle('hidden', !isUsingRuntimeConfig());
}

function showGatePanel(boxId) {
  document.getElementById('vaultShell')?.classList.add('hidden');
  document.getElementById('gateScreen')?.classList.remove('hidden');
  GATE_BOX_IDS.forEach((id) => {
    document.getElementById(id)?.classList.toggle('hidden', id !== boxId);
  });
  syncRuntimeConfigControls();
}

async function openMfaStep(reason, existingFactorId) {
  showGatePanel('mfaBox');
  const titleEl = document.getElementById('mfaTitle');
  const qrWrap = document.getElementById('mfaQrWrap');
  const qrImg = document.getElementById('mfaQrImg');
  const secretText = document.getElementById('mfaManualSecret');

  if (reason === 'mfa_enroll_required') {
    if (titleEl) titleEl.textContent = 'Thiết Lập Bảo Mật 2 Lớp (Bắt Buộc Cho Admin)';
    try {
      const enrolled = await enrollTotpMfa('JT-Vault-Authenticator');
      appState.pendingMfaFactorId = enrolled.factorId;
      if (qrImg) qrImg.src = enrolled.qrCode;
      if (secretText) secretText.textContent = enrolled.secret || '';
      qrWrap?.classList.remove('hidden');
    } catch (err) {
      showToast(err.message || 'Không thể khởi tạo MFA.', 'error');
    }
  } else {
    if (titleEl) titleEl.textContent = 'Nhập Mã OTP 6 Số (Google Authenticator / Authy)';
    appState.pendingMfaFactorId = existingFactorId;
    qrWrap?.classList.add('hidden');
  }
}

async function loadActiveTab() {
  if (appState.activeTab === 'users') await loadUsersTab();
  else if (appState.activeTab === 'tokens') await loadTokensTab();
  else if (appState.activeTab === 'creds') await loadJmsCredsTab();
  else if (appState.activeTab === 'audit') await loadAuditTab();
}

function switchTab(tabName) {
  appState.activeTab = tabName;
  document.querySelectorAll('.vault-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  ['users', 'tokens', 'creds', 'audit'].forEach((name) => {
    document.getElementById(`panel-${name}`)?.classList.toggle('hidden', name !== tabName);
  });
  loadActiveTab();
}

async function bootVaultApp() {
  if (!isSupabaseConfigured()) {
    showGatePanel('unconfiguredBox');
    return;
  }

  const check = await requireAdminAal2();
  if (!check.ok) {
    if (check.reason === 'unconfigured') {
      showGatePanel('unconfiguredBox');
    } else if (check.reason === 'unauthenticated') {
      showGatePanel('loginFormWrap');
    } else if (check.reason === 'locked') {
      document.getElementById('lockedEmail').textContent = check.profile?.email || '--';
      showGatePanel('lockedBox');
    } else if (check.reason === 'forbidden') {
      document.getElementById('forbiddenEmail').textContent = check.profile?.email || '--';
      document.getElementById('forbiddenRole').textContent = check.profile?.role_code || '--';
      showGatePanel('forbiddenBox');
    } else if (check.reason === 'must_change_password') {
      showGatePanel('forcePassBox');
    } else if (check.reason === 'mfa_enroll_required' || check.reason === 'mfa_verify_required') {
      await openMfaStep(check.reason, check.totpFactorId);
    } else {
      document.getElementById('errorMessageText').textContent = check.message || 'Lỗi xác thực hệ thống.';
      showGatePanel('errorBox');
    }
    return;
  }

  appState.profile = check.profile;
  appState.regions = check.regions;

  document.getElementById('adminNameLabel').textContent = appState.profile.full_name;
  document.getElementById('adminEmailLabel').textContent = appState.profile.email;

  const getRegions = () => appState.regions;
  initUsersTab({ getRegions });
  initTokensTab({ getRegions });
  initJmsCredsTab({ getRegions });
  initAuditTab();

  document.getElementById('gateScreen')?.classList.add('hidden');
  document.getElementById('vaultShell')?.classList.remove('hidden');
  await loadActiveTab();
}

function bindGlobalEvents() {
  const runtimeForm = document.getElementById('runtimeConfigForm');
  runtimeForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const urlInput = document.getElementById('cfgSupabaseUrl');
    const keyInput = document.getElementById('cfgSupabaseAnonKey');
    try {
      saveRuntimeSupabaseConfig(urlInput.value, keyInput.value);
      resetSupabaseClient();
      keyInput.value = '';
      showToast('Đã lưu cấu hình kết nối Supabase Cloud công khai trên trình duyệt.', 'success');
      await bootVaultApp();
    } catch (err) {
      showToast(err.message || 'Cấu hình Supabase không hợp lệ.', 'error');
    }
  });

  document.getElementById('btnResetRuntimeConfig')?.addEventListener('click', async () => {
    await signOutVault();
    clearRuntimeSupabaseConfig();
    resetSupabaseClient();
    showToast('Đã xóa cấu hình kết nối tạm trên trình duyệt.', 'info');
    showGatePanel('unconfiguredBox');
  });

  const loginForm = document.getElementById('loginForm');
  loginForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const passInput = document.getElementById('loginPassword');
    try {
      await signInAdmin(document.getElementById('loginEmail').value, passInput.value);
      passInput.value = '';
      await bootVaultApp();
    } catch (err) {
      showToast(err.message || 'Đăng nhập thất bại.', 'error');
    }
  });

  const forcePassForm = document.getElementById('forcePassForm');
  forcePassForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const p1 = document.getElementById('newStrongPass');
    const p2 = document.getElementById('confirmStrongPass');
    try {
      await changeFirstPassword(p1.value, p2.value);
      p1.value = '';
      p2.value = '';
      showToast('Đổi mật khẩu lần đầu thành công.', 'success');
      await bootVaultApp();
    } catch (err) {
      showToast(err.message || 'Đổi mật khẩu thất bại.', 'error');
    }
  });

  const mfaForm = document.getElementById('mfaVerifyForm');
  mfaForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const codeInput = document.getElementById('mfaCodeInput');
    try {
      await verifyTotpMfa(appState.pendingMfaFactorId, codeInput.value);
      codeInput.value = '';
      showToast('Xác thực 2 lớp MFA (AAL2) thành công.', 'success');
      await bootVaultApp();
    } catch (err) {
      showToast(err.message || 'Mã OTP không chính xác.', 'error');
    }
  });

  const handleSignOut = async () => {
    await signOutVault();
    appState.profile = null;
    appState.pendingMfaFactorId = null;
    showGatePanel('loginFormWrap');
  };

  ['btnSignOut', 'btnLockedOut', 'btnForbiddenOut', 'btnMfaSignOut', 'btnForcePassOut', 'btnErrorOut'].forEach((id) => {
    document.getElementById(id)?.addEventListener('click', handleSignOut);
  });

  document.querySelectorAll('.vault-tab').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  document.getElementById('btnRefreshCurrentTab')?.addEventListener('click', loadActiveTab);
}

bindGlobalEvents();
bootVaultApp();
