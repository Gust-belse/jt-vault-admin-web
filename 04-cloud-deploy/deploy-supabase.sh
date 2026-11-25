#!/usr/bin/env bash
# 04-cloud-deploy/deploy-supabase.sh
# Kịch bản đẩy toàn bộ Database Migration (Vault/RLS/RPC) & Edge Function lên Supabase Cloud.
#
# Yêu cầu trước khi chạy:
#   1. Đã cài Supabase CLI: https://supabase.com/docs/guides/cli
#   2. Đã đăng nhập: supabase login
#   3. Đã thiết lập biến môi trường SUPABASE_PROJECT_REF (hoặc truyền qua tham số $1)
#
# Cách chạy từ thư mục gốc repository:
#   bash 04-cloud-deploy/deploy-supabase.sh <YOUR_PROJECT_REF>

set -euo pipefail

PROJECT_REF="${1:-${SUPABASE_PROJECT_REF:-}}"

if [[ -z "${PROJECT_REF}" ]]; then
  echo "Lỗi: Thiếu SUPABASE_PROJECT_REF."
  echo "Cách dùng: bash 04-cloud-deploy/deploy-supabase.sh <YOUR_PROJECT_REF>"
  exit 1
fi

if ! command -v supabase >/dev/null 2>&1; then
  echo "Lỗi: Chưa cài Supabase CLI. Cài bằng: npm install -g supabase"
  exit 1
fi

echo "==> [1/3] Liên kết Supabase Cloud Project: ${PROJECT_REF}"
supabase link --project-ref "${PROJECT_REF}"

echo "==> [2/3] Đẩy Database Schema, RLS, Supabase Vault & 12 hàm RPC..."
supabase db push

echo "==> [3/3] Triển khai Edge Function admin-create-user..."
supabase functions deploy admin-create-user

echo ""
echo "✅ Hoàn tất triển khai Backend lên Supabase Cloud (${PROJECT_REF})!"
echo "Bước tiếp theo:"
echo "  1. Vào Supabase Dashboard -> Authentication -> Providers -> Email -> TẮT 'Allow new users to sign up'."
echo "  2. Vào Authentication -> Users -> Add user để tạo tài khoản Admin đầu tiên."
echo "  3. Chạy câu lệnh trong 01-supabase-db/004_bootstrap_first_admin.sql tại SQL Editor để gán quyền Super Admin."
echo "  4. Điền SUPABASE_URL và SUPABASE_ANON_KEY vào 02-vault-admin-ui/js/config.js (hoặc nhập trực tiếp trên giao diện GitHub Pages)."
