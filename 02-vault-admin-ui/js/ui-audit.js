/**
 * 02-vault-admin-ui/js/ui-audit.js
 * Module giao diện Tab 4: Nhật ký bảo mật bất biến (Audit Logs — Chỉ đọc).
 */

import { escHtml, fmtTime, showToast } from './config.js';
import { fetchAuditLogs } from './vault-api.js';

let _cachedLogs = [];
let _initialized = false;

function renderAuditRows() {
  const tbody = document.getElementById('auditTableBody');
  const filterSelect = document.getElementById('auditActionFilter');
  if (!tbody) return;

  const actionFilter = filterSelect?.value || 'ALL';
  const rows = actionFilter === 'ALL'
    ? _cachedLogs
    : _cachedLogs.filter((item) => item.action === actionFilter);

  if (rows.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="py-8 text-center text-slate-400 font-sans">Chưa có bản ghi nhật ký phù hợp.</td></tr>';
    return;
  }

  tbody.innerHTML = rows
    .map((a) => `
      <tr class="hover:bg-slate-50">
        <td class="py-2.5 px-3 whitespace-nowrap">${fmtTime(a.created_at)}</td>
        <td class="py-2.5 px-3">${escHtml(a.actor_email || 'SYSTEM')}</td>
        <td class="py-2.5 px-3 font-bold text-slate-900">${escHtml(a.action)}</td>
        <td class="py-2.5 px-3 text-slate-600">${escHtml(a.target_email || '--')}</td>
        <td class="py-2.5 px-3 text-[11px] text-slate-600 break-all">${escHtml(JSON.stringify(a.metadata || {}))}</td>
      </tr>
    `)
    .join('');
}

export function initAuditTab() {
  if (_initialized) return;
  _initialized = true;

  const filterSelect = document.getElementById('auditActionFilter');
  filterSelect?.addEventListener('change', renderAuditRows);
}

export async function loadAuditTab() {
  try {
    _cachedLogs = await fetchAuditLogs(150);
    renderAuditRows();
  } catch (err) {
    showToast(err.message || 'Lỗi tải nhật ký bảo mật.', 'error');
  }
}
