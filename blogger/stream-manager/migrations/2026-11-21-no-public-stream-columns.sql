-- =============================================================================
-- 2026-11-21: stop exposing stream mappings through the public (anon) API
--
-- Before: anon could read every column of match_settings, including channel and r2_slug,
-- with the publishable key printed in the dashboard page (e.g. match 6386073 -> b2 + slug).
-- px-league.site no longer uses those columns: the Worker reads only match_id, is_visible.
--
-- After:
--   anon           -> SELECT (match_id, is_visible) only. "select=*" or channel/r2_slug
--                     now fails with 42501 permission denied.
--   authenticated  -> rows only for stream admins (is_stream_admin()); other signed-up
--                     accounts see nothing.
--   existing channel / r2_slug values are cleared.
--
-- Run once in Supabase: SQL Editor > New query > paste > Run. Safe to run again.
-- =============================================================================

-- 1. Column-level read access for anon
revoke select on public.match_settings from anon;
grant select (match_id, is_visible) on public.match_settings to anon;

-- 2. Row access: anon keeps reading every row (show/hide filter), authenticated = admins only
drop policy if exists "anyone reads match settings" on public.match_settings;
drop policy if exists "anon reads visibility" on public.match_settings;
create policy "anon reads visibility" on public.match_settings
  for select to anon using (true);
drop policy if exists "admins read match settings" on public.match_settings;
create policy "admins read match settings" on public.match_settings
  for select to authenticated using (public.is_stream_admin());

-- 3. No stream data left in the table
update public.match_settings set channel = null, r2_slug = null
  where channel is not null or r2_slug is not null;

-- Check (should list only match_id / is_visible privileges for anon):
--   select grantee, column_name, privilege_type from information_schema.column_privileges
--    where table_name = 'match_settings' and grantee = 'anon';
