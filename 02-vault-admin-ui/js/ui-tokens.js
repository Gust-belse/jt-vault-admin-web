/**
 * 02-vault-admin-ui/js/ui-tokens.js
 * Module giao diện Tab 2: Quản lý tập trung JMS authToken & Feishu OAuth View-Only (Write-Only).
 */

import { escHtml, fmtTime, showToast } from './config.js';
import {
  fetchMaskedTokens,
  saveVaultToken,
  toggleVaultToken,
  deleteVaultToken
} from './vault-api.js';

let _getRegions = () => [];
let _initialized = false;

function populateTokenRegions() {
  const select = document.getElementById('tkRegion');
  if (!select) return;
  const regions = _getRegions();
  select.innerHTML =
    '<option value="ALL">ALL — Toàn quốc (7 KV)</option>' +
    regions.map((r) => `<option value="${escHtml(r.code)}">${escHtml(r.code)} — ${escHtml(r.name)}</option>`).join('');
}

function syncFeishuFieldState() {
  const typeEl = document.getElementById('tkType');
  const extraWrap = document.getElementById('feishuExtraFields');
  const actionEl = document.getElementById('tkRefreshAction');
  const refreshInput = document.getElementById('tkRefreshVal');
  if (!typeEl || !extraWrap) return;

  const isFeishu = typeEl.value === 'feishu_oauth';
  extraWrap.classList.toggle('hidden', !isFeishu);

  if (refreshInput && actionEl) {
    const needRefreshInput = isFeishu && actionEl.value === 'replace';
    refreshInput.disabled = !needRefreshInput;
    refreshInput.required = needRefreshInput;
    if (!needRefreshInput) {
      refreshInput.value = '';
    }
  }
}

export function initTokensTab({ getRegions }) {
  _getRegions = getRegions;
  populateTokenRegions();
  syncFeishuFieldState();

  if (_initialized) return;
  _initialized = true;

  const typeEl = document.getElementById('tkType');
  const actionEl = document.getElementById('tkRefreshAction');
  const form = document.getElementById('tokenForm');
  const tbody = document.getElementById('tokensTableBody');

  typeEl?.addEventListener('change', syncFeishuFieldState);
  actionEl?.addEventListener('change', syncFeishuFieldState);

  form?.addEventListener('reset', () => {
    window.setTimeout(syncFeishuFieldState, 0);
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;

    const plainTokenEl = document.getElementById('tkPlainVal');
    const plainRefreshEl = document.getElementById('tkRefreshVal');

    try {
      const tokenType = typeEl.value;
      const expRaw = document.getElementById('tkExpiresAt').value;
      const expiresAtIso = tokenType === 'feishu_oauth' && expRaw ? new Date(expRaw).toISOString() : null;
      const refreshAction = tokenType === 'feishu_oauth' ? actionEl.value : 'clear';

      const saved = await saveVaultToken({
        tokenName: document.getElementById('tkName').value,
        tokenType,
        plainToken: plainTokenEl.value,
        regionCode: document.getElementById('tkRegion').value,
        priority: Number(document.getElementById('tkPriority').value || 1),
        refreshAction,
        plainRefreshToken: refreshAction === 'replace' ? plainRefreshEl.value : null,
        expiresAt: expiresAtIso,
        note: document.getElementById('tkNote').value
      });

      // Cơ chế Write-Only: xóa sạch giá trị bí mật khỏi ô input DOM ngay sau khi lưu
      plainTokenEl.value = '';
      plainRefreshEl.value = '';

      showToast(`Đã mã hóa & lưu ${saved.token_name} (${saved.masked_preview}) vào Supabase Vault.`, 'success');
      await loadTokensTab();
    } catch (err) {
      showToast(err.message || 'Lưu token thất bại.', 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  tbody?.addEventListener('click', async (event) => {
    const btn = event.target instanceof Element ? event.target.closest('button[data-action]') : null;
    if (!btn) return;

    const act = btn.dataset.action;
    if (act === 'rotate-token') {
      document.getElementById('tkName').value = btn.dataset.name || '';
      document.getElementById('tkType').value = btn.dataset.type || 'jms_auth';
      document.getElementById('tkRegion').value = btn.dataset.region || 'ALL';
      document.getElementById('tkPriority').value = btn.dataset.priority || '1';
      document.getElementById('tkNote').value = btn.dataset.note || '';
      if (actionEl) actionEl.value = 'keep';
      syncFeishuFieldState();
      document.getElementById('tkPlainVal')?.focus();
      showToast(`Đang xoay vòng ${btn.dataset.name}: nhập giá trị token mới rồi bấm Lưu.`, 'info');
      return;
    }

    if (act === 'toggle-token') {
      btn.disabled = true;
      try {
        await toggleVaultToken(Number(btn.dataset.id), btn.dataset.next);
        showToast(`Đã chuyển trạng thái token sang ${btn.dataset.next}.`, 'success');
        await loadTokensTab();
      } catch (err) {
        showToast(err.message || 'Đổi trạng thái token thất bại.', 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (act === 'delete-token') {
      const name = btn.dataset.name || '';
      if (!window.confirm(`Xác nhận xóa vĩnh viễn token "${name}" khỏi Supabase Vault?`)) return;
      btn.disabled = true;
      try {
        await deleteVaultToken(Number(btn.dataset.id));
        showToast(`Đã xóa vĩnh viễn token ${name}.`, 'success');
        await loadTokensTab();
      } catch (err) {
        showToast(err.message || 'Xóa token thất bại.', 'error');
      } finally {
        btn.disabled = false;
      }
    }
  });
}

export async function loadTokensTab() {
  populateTokenRegions();
  const tbody = document.getElementById('tokensTableBody');
  if (!tbody) return;

  try {
    const list = await fetchMaskedTokens();
    const statCount = document.getElementById('statTokenCount');
    if (statCount) statCount.textContent = `${list.length} token`;

    if (list.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="7" class="py-8 text-center text-slate-400 font-sans">Chưa có token nào trong Kho Bảo Mật.</td></tr>';
      return;
    }

    const typeBadge = {
      jms_auth: '<span class="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-bold text-[10px]">JMS AUTH</span>',
      feishu_oauth: '<span class="px-2 py-0.5 rounded bg-sky-100 text-sky-800 font-bold text-[10px]">FEISHU VIEW-ONLY</span>'
    };
    const statusBadge = {
      active: 'bg-emerald-100 text-emerald-800',
      expired: 'bg-rose-100 text-rose-800',
      disabled: 'bg-slate-200 text-slate-700'
    };

    tbody.innerHTML = list
      .map((t) => `
        <tr class="hover:bg-slate-50">
          <td class="py-3 px-3">
            <div class="font-bold text-slate-900">${escHtml(t.token_name)}</div>
            <div class="text-[10px] font-sans text-slate-500">${escHtml(t.note || '--')}</div>
          </td>
          <td class="py-3 px-3 font-sans">${typeBadge[t.token_type] || escHtml(t.token_type)}</td>
          <td class="py-3 px-3">${escHtml(t.region_code)} · P${escHtml(t.priority)}</td>
          <td class="py-3 px-3">
            <div class="font-bold text-slate-800">${escHtml(t.masked_preview)}</div>
            ${t.masked_refresh_preview ? `<div class="text-[10px] text-sky-700">Refresh: ${escHtml(t.masked_refresh_preview)}</div>` : ''}
          </td>
          <td class="py-3 px-3 text-[11px]">
            <div>Cập nhật: ${fmtTime(t.updated_at)}</div>
            ${t.expires_at ? `<div class="text-sky-700">Hết hạn: ${fmtTime(t.expires_at)}</div>` : ''}
          </td>
          <td class="py-3 px-3">
            <span class="px-2 py-0.5 rounded font-bold text-[10px] uppercase ${statusBadge[t.status] || 'bg-slate-100'}">${escHtml(t.status)}</span>
            ${t.last_error ? `<div class="text-[10px] text-rose-600 font-sans mt-1 max-w-[210px] truncate" title="${escHtml(t.last_error)}">${escHtml(t.last_error)}</div>` : ''}
          </td>
          <td class="py-3 px-3 text-right space-x-1 whitespace-nowrap font-sans">
            <button type="button" data-action="rotate-token" data-name="${escHtml(t.token_name)}" data-type="${escHtml(t.token_type)}" data-region="${escHtml(t.region_code)}" data-priority="${escHtml(t.priority)}" data-note="${escHtml(t.note || '')}" class="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 text-[11px] font-bold">Xoay giá trị</button>
            <button type="button" data-action="toggle-token" data-id="${escHtml(t.id)}" data-next="${t.status === 'active' ? 'disabled' : 'active'}" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-bold">${t.status === 'active' ? 'Tắt' : 'Bật'}</button>
            <button type="button" data-action="delete-token" data-id="${escHtml(t.id)}" data-name="${escHtml(t.token_name)}" class="px-2.5 py-1 rounded-lg bg-rose-100 hover:bg-rose-600 text-rose-700 hover:text-white text-[11px] font-bold">Xóa</button>
          </td>
        </tr>
      `)
      .join('');
  } catch (err) {
    showToast(err.message || 'Lỗi tải danh sách token.', 'error');
  }
}
