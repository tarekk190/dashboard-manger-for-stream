-- =============================================================================
-- 2026-11-25: streams back on the sites that embed our player
--
-- The Worker (blogger/worker/src/index.js) reads match_settings with the anon key. Since
-- 2026-11-21-no-public-stream-columns.sql anon could read only (match_id, is_visible), so a
-- Worker request for channel / r2_slug failed with 42501 and no stream reached the site.
--
-- After:
--   anon           -> SELECT (match_id, is_visible, channel, r2_slug). The Worker attaches the
--                     stream only for its STREAM_ORIGINS (px-league.site, www.px-league.site,
--                     tariq-live.blogspot.com); other origins get no stream data.
--   authenticated  -> unchanged (stream admins read and write every column).
--
-- Note: the mapping match -> channel / slug becomes readable by anyone holding the publishable
-- key (it is in the dashboard page). That is the same information every viewer of a stream page
-- sees in the player iframe URL, so nothing new is exposed.
-- The 2026-11-21 migration CLEARED every channel / r2_slug value: re-attach the streams in the
-- dashboard after running this.
--
-- Run once in Supabase: SQL Editor > New query > paste > Run. Safe to run again.
-- =============================================================================

grant select (match_id, is_visible, channel, r2_slug) on public.match_settings to anon;

-- Check (should list match_id, is_visible, channel and r2_slug for anon):
--   select grantee, column_name, privilege_type from information_schema.column_privileges
--    where table_name = 'match_settings' and grantee = 'anon';
