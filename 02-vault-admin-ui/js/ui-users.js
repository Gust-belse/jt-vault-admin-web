/**
 * 02-vault-admin-ui/js/ui-users.js
 * Module giao diện Tab 1: Cấp tài khoản nội bộ (Admin AAL2) & Duyệt/Thu hồi quyền 7 khu vực.
 */

import { escHtml, generateStrongPassword, showToast } from './config.js';
import {
  fetchVaultUsers,
  createInternalUser,
  reviewUserPermission
} from './vault-api.js';

let _getRegions = () => [];
let _initialized = false;

function populateRegionDropdown() {
  const select = document.getElementById('cuRegion');
  if (!select) return;
  const regions = _getRegions();
  select.innerHTML = regions
    .map((r) => `<option value="${r.id}">${escHtml(r.code)} — ${escHtml(r.name)}</option>`)
    .join('');
}

export function initUsersTab({ getRegions }) {
  _getRegions = getRegions;
  populateRegionDropdown();

  if (_initialized) return;
  _initialized = true;

  const roleSelect = document.getElementById('cuRole');
  const regionWrap = document.getElementById('cuRegionWrap');
  const tempPassInput = document.getElementById('cuTempPass');
  const genBtn = document.getElementById('btnGenStrongPass');
  const createForm = document.getElementById('adminCreateUserForm');
  const tbody = document.getElementById('usersTableBody');

  roleSelect?.addEventListener('change', () => {
    const isRegional = roleSelect.value === 'regional';
    regionWrap?.classList.toggle('hidden', !isRegional);
  });

  genBtn?.addEventListener('click', () => {
    if (tempPassInput) {
      tempPassInput.value = generateStrongPassword(16);
    }
  });

  createForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submitBtn = createForm.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;

    try {
      const email = document.getElementById('cuEmail').value.trim().toLowerCase();
      const fullName = document.getElementById('cuFullName').value.trim();
      const roleCode = roleSelect.value;
      const regionId = roleCode === 'regional' ? Number(document.getElementById('cuRegion').value) : null;
      const tempPassword = tempPassInput.value;
      const note = document.getElementById('cuNote').value.trim();

      await createInternalUser({
        email,
        fullName,
        tempPassword,
        roleCode,
        regionId,
        note
      });

      // Xóa ngay mật khẩu tạm khỏi DOM sau khi gửi thành công
      tempPassInput.value = '';
      createForm.reset();
      regionWrap?.classList.remove('hidden');

      let copied = false;
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(
            `Email: ${email}\nMật khẩu tạm (bắt buộc đổi ngay lần đầu đăng nhập): ${tempPassword}`
          );
          copied = true;
        }
      } catch {
        copied = false;
      }

      showToast(
        copied
          ? `Đã tạo tài khoản ${email} (${roleCode.toUpperCase()}) và sao chép mật khẩu tạm vào clipboard.`
          : `Đã tạo tài khoản ${email} (${roleCode.toUpperCase()}) thành công.`,
        'success'
      );

      await loadUsersTab();
    } catch (err) {
      showToast(err.message || 'Tạo tài khoản thất bại.', 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  tbody?.addEventListener('change', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLSelectElement) || !target.classList.contains('js-role-select')) {
      return;
    }
    const row = target.closest('tr');
    const regSel = row?.querySelector('.js-region-select');
    if (regSel instanceof HTMLSelectElement) {
      regSel.disabled = target.value !== 'regional';
    }
  });

  tbody?.addEventListener('click', async (event) => {
    const btn = event.target instanceof Element ? event.target.closest('button[data-action]') : null;
    if (!btn) return;

    const row = btn.closest('tr');
    const targetUserId = btn.dataset.uid;
    const roleCode = row?.querySelector('.js-role-select')?.value || 'regional';
    const regionVal = row?.querySelector('.js-region-select')?.value || '';
    const isApprove = btn.dataset.action === 'approve-user';

    btn.disabled = true;
    try {
      await reviewUserPermission({
        targetUserId,
        regionId: roleCode === 'regional' && regionVal ? Number(regionVal) : null,
        status: isApprove ? 'approved' : 'revoked',
        roleCode,
        activateUser: isApprove,
        note: isApprove
          ? 'Admin AAL2 phê duyệt tại Kho Bảo Mật'
          : 'Admin AAL2 thu hồi quyền tại Kho Bảo Mật'
      });

      showToast(
        isApprove ? 'Đã duyệt kích hoạt và cập nhật phân quyền.' : 'Đã thu hồi quyền và khóa tài khoản.',
        'success'
      );
      await loadUsersTab();
    } catch (err) {
      showToast(err.message || 'Cập nhật phân quyền thất bại.', 'error');
    } finally {
      btn.disabled = false;
    }
  });
}

export async function loadUsersTab() {
  populateRegionDropdown();
  const tbody = document.getElementById('usersTableBody');
  if (!tbody) return;

  try {
    const users = await fetchVaultUsers();
    const regions = _getRegions();

    const statTotal = document.getElementById('statTotalUsers');
    const statPending = document.getElementById('statPendingUsers');
    if (statTotal) statTotal.textContent = String(users.length);
    if (statPending) statPending.textContent = String(users.filter((u) => !u.is_active).length);

    if (users.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="py-8 text-center text-slate-400">Chưa có tài khoản nào trong hệ thống.</td></tr>';
      return;
    }

    tbody.innerHTML = users
      .map((u) => {
        const perms = Array.isArray(u.permissions) ? u.permissions : [];
        const activePerm = perms.find((p) => p.status === 'approved') || perms[0];
        const selectedRegId = activePerm ? String(activePerm.region_id) : String(regions[0]?.id || '');

        const regionOptsHtml = regions
          .map((r) => {
            const sel = String(r.id) === selectedRegId ? ' selected' : '';
            return `<option value="${r.id}"${sel}>${escHtml(r.code)} — ${escHtml(r.name)}</option>`;
          })
          .join('');

        const permSummary =
          u.role_code === 'regional'
            ? perms.length
              ? perms.map((p) => `${p.region_code || p.region_name} (${p.status})`).join(', ')
              : 'Chưa gán khu vực'
            : 'Toàn quốc 7 KV';

        const badges = [
          u.is_active
            ? '<span class="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-bold text-[10px]">Đang hoạt động</span>'
            : '<span class="px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-bold text-[10px]">Khóa / Chờ duyệt</span>',
          u.mfa_required
            ? '<span class="px-2 py-0.5 rounded bg-cyan-100 text-cyan-800 font-bold text-[10px]">Bắt buộc MFA</span>'
            : '',
          u.must_change_password
            ? '<span class="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-bold text-[10px]">Chưa đổi MK đầu</span>'
            : ''
        ]
          .filter(Boolean)
          .join(' ');

        return `<tr class="hover:bg-slate-50" data-user-row="${escHtml(u.id)}">
          <td class="py-3 px-3.5">
            <div class="font-bold text-slate-900">${escHtml(u.full_name)}</div>
            <div class="text-[11px] text-slate-500 font-mono-num">${escHtml(u.email)}</div>
          </td>
          <td class="py-3 px-3.5"><div class="flex flex-wrap gap-1">${badges}</div></td>
          <td class="py-3 px-3.5">
            <select class="js-role-select px-2 py-1 rounded-lg border border-slate-300 text-xs font-bold bg-white">
              <option value="regional"${u.role_code === 'regional' ? ' selected' : ''}>regional</option>
              <option value="hq"${u.role_code === 'hq' ? ' selected' : ''}>hq</option>
              <option value="admin"${u.role_code === 'admin' ? ' selected' : ''}>admin</option>
            </select>
          </td>
          <td class="py-3 px-3.5">
            <select class="js-region-select px-2 py-1 rounded-lg border border-slate-300 text-xs font-semibold bg-white"${u.role_code !== 'regional' ? ' disabled' : ''}>
              ${regionOptsHtml}
            </select>
          </td>
          <td class="py-3 px-3.5 text-[11px] text-slate-600">${escHtml(permSummary)}</td>
          <td class="py-3 px-3.5 text-right space-x-1 whitespace-nowrap">
            <button type="button" data-action="approve-user" data-uid="${escHtml(u.id)}" class="px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] font-bold">Lưu / Duyệt</button>
            <button type="button" data-action="revoke-user" data-uid="${escHtml(u.id)}" class="px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-[11px] font-bold">Thu hồi</button>
          </td>
        </tr>`;
      })
      .join('');
  } catch (err) {
    showToast(err.message || 'Lỗi tải danh sách tài khoản.', 'error');
  }
}
