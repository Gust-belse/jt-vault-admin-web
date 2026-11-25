/**
 * 02-vault-admin-ui/js/ui-jms-creds.js
 * Module giao diện Tab 3: Quản lý riêng cặp tài khoản/mật khẩu đăng nhập JMS (Write-Only).
 */

import { escHtml, fmtTime, showToast } from './config.js';
import {
  fetchMaskedJmsCredentials,
  saveJmsCredential,
  toggleJmsCredential,
  deleteJmsCredential
} from './vault-api.js';

let _getRegions = () => [];
let _initialized = false;

function populateCredRegions() {
  const select = document.getElementById('credRegion');
  if (!select) return;
  const regions = _getRegions();
  select.innerHTML =
    '<option value="ALL">ALL — Toàn quốc (7 KV)</option>' +
    regions.map((r) => `<option value="${escHtml(r.code)}">${escHtml(r.code)} — ${escHtml(r.name)}</option>`).join('');
}

export function initJmsCredsTab({ getRegions }) {
  _getRegions = getRegions;
  populateCredRegions();

  if (_initialized) return;
  _initialized = true;

  const form = document.getElementById('jmsCredForm');
  const tbody = document.getElementById('jmsCredsTableBody');

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;

    const userInput = document.getElementById('credUsername');
    const passInput = document.getElementById('credPassword');

    try {
      const saved = await saveJmsCredential({
        credName: document.getElementById('credName').value,
        plainUsername: userInput.value,
        plainPassword: passInput.value,
        regionCode: document.getElementById('credRegion').value,
        priority: Number(document.getElementById('credPriority').value || 1),
        note: document.getElementById('credNote').value
      });

      // Xóa ngay tài khoản & mật khẩu khỏi DOM sau khi lưu thành công
      userInput.value = '';
      passInput.value = '';

      showToast(`Đã mã hóa & lưu tài khoản JMS ${saved.cred_name} (${saved.masked_username}).`, 'success');
      await loadJmsCredsTab();
    } catch (err) {
      showToast(err.message || 'Lưu tài khoản JMS thất bại.', 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  tbody?.addEventListener('click', async (event) => {
    const btn = event.target instanceof Element ? event.target.closest('button[data-action]') : null;
    if (!btn) return;

    const act = btn.dataset.action;
    if (act === 'rotate-cred') {
      document.getElementById('credName').value = btn.dataset.name || '';
      document.getElementById('credRegion').value = btn.dataset.region || 'ALL';
      document.getElementById('credPriority').value = btn.dataset.priority || '1';
      document.getElementById('credNote').value = btn.dataset.note || '';
      document.getElementById('credUsername')?.focus();
      showToast(`Nhập lại tài khoản và mật khẩu mới cho ${btn.dataset.name} rồi bấm Lưu.`, 'info');
      return;
    }

    if (act === 'toggle-cred') {
      btn.disabled = true;
      try {
        await toggleJmsCredential(Number(btn.dataset.id), btn.dataset.next);
        showToast(`Đã chuyển trạng thái tài khoản JMS sang ${btn.dataset.next}.`, 'success');
        await loadJmsCredsTab();
      } catch (err) {
        showToast(err.message || 'Đổi trạng thái thất bại.', 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (act === 'delete-cred') {
      const name = btn.dataset.name || '';
      if (!window.confirm(`Xác nhận xóa vĩnh viễn bộ tài khoản JMS "${name}" khỏi Supabase Vault?`)) return;
      btn.disabled = true;
      try {
        await deleteJmsCredential(Number(btn.dataset.id));
        showToast(`Đã xóa vĩnh viễn tài khoản JMS ${name}.`, 'success');
        await loadJmsCredsTab();
      } catch (err) {
        showToast(err.message || 'Xóa tài khoản JMS thất bại.', 'error');
      } finally {
        btn.disabled = false;
      }
    }
  });
}

export async function loadJmsCredsTab() {
  populateCredRegions();
  const tbody = document.getElementById('jmsCredsTableBody');
  if (!tbody) return;

  try {
    const list = await fetchMaskedJmsCredentials();
    const statEl = document.getElementById('statCredCount');
    if (statEl) statEl.textContent = `${list.length} tài khoản JMS`;

    if (list.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="py-8 text-center text-slate-400 font-sans">Chưa có tài khoản đăng nhập JMS nào được lưu.</td></tr>';
      return;
    }

    tbody.innerHTML = list
      .map((c) => `
        <tr class="hover:bg-slate-50">
          <td class="py-3 px-3">
            <div class="font-bold text-slate-900">${escHtml(c.cred_name)}</div>
            <div class="text-[10px] font-sans text-slate-500">${escHtml(c.note || '--')}</div>
          </td>
          <td class="py-3 px-3">${escHtml(c.region_code)} · P${escHtml(c.priority)}</td>
          <td class="py-3 px-3">
            <div class="font-bold text-slate-800">${escHtml(c.masked_username)}</div>
            <div class="text-[10px] text-slate-400">Mật khẩu: •••••••••••• (Write-Only)</div>
          </td>
          <td class="py-3 px-3 text-[11px]">
            <div>Cập nhật: ${fmtTime(c.updated_at)}</div>
            <div class="text-slate-500">Login cuối: ${fmtTime(c.last_login_at)}</div>
          </td>
          <td class="py-3 px-3">
            <span class="px-2 py-0.5 rounded font-bold text-[10px] uppercase ${c.status === 'active' ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-slate-700'}">${escHtml(c.status)}</span>
            ${c.last_error ? `<div class="text-[10px] text-rose-600 font-sans mt-1 max-w-[200px] truncate" title="${escHtml(c.last_error)}">${escHtml(c.last_error)}</div>` : ''}
          </td>
          <td class="py-3 px-3 text-right space-x-1 whitespace-nowrap font-sans">
            <button type="button" data-action="rotate-cred" data-name="${escHtml(c.cred_name)}" data-region="${escHtml(c.region_code)}" data-priority="${escHtml(c.priority)}" data-note="${escHtml(c.note || '')}" class="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 text-[11px] font-bold">Đổi MK</button>
            <button type="button" data-action="toggle-cred" data-id="${escHtml(c.id)}" data-next="${c.status === 'active' ? 'disabled' : 'active'}" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-bold">${c.status === 'active' ? 'Tắt' : 'Bật'}</button>
            <button type="button" data-action="delete-cred" data-id="${escHtml(c.id)}" data-name="${escHtml(c.cred_name)}" class="px-2.5 py-1 rounded-lg bg-rose-100 hover:bg-rose-600 text-rose-700 hover:text-white text-[11px] font-bold">Xóa</button>
          </td>
        </tr>
      `)
      .join('');
  } catch (err) {
    showToast(err.message || 'Lỗi tải danh sách tài khoản JMS.', 'error');
  }
}
