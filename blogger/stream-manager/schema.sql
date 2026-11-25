-- =============================================================================
-- PX League - Master Match Controller: Supabase schema (run once in the SQL editor;
-- safe to run again).
--
-- match_settings: one row per match the admin touched.
--   is_visible = false  -> the Worker removes the match from matches_date_get (site lists)
--   channel / r2_slug   -> the Worker injects "stream": { channel, r2_slug } into the match
-- No row = default (visible, no stream). The dashboard deletes rows that are back to default.
--
-- Access: anon (the Worker) can READ; only users in stream_admins can write.
-- Turn off public sign-ups (Authentication -> Providers -> Email), create your admin user,
-- then add it with the INSERT at the end of this file.
-- =============================================================================

create table if not exists public.match_settings (
  match_id   bigint primary key,
  is_visible boolean not null default true,
  channel    text check (channel ~ '^[A-Za-z0-9_-]{1,64}$'),
  r2_slug    text check (r2_slug ~ '^[A-Za-z0-9_-]{1,64}$'),
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);

-- Admins ---------------------------------------------------------------------------------
create table if not exists public.stream_admins (
  user_id uuid primary key references auth.users (id) on delete cascade
);
alter table public.stream_admins enable row level security;   -- no policies: hidden from clients

create or replace function public.is_stream_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.stream_admins where user_id = auth.uid());
$$;
revoke execute on function public.is_stream_admin() from public, anon;
grant execute on function public.is_stream_admin() to authenticated;

-- updated_at / updated_by on every write --------------------------------------------------
create or replace function public.touch_match_settings()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists match_settings_touch on public.match_settings;
create trigger match_settings_touch before insert or update on public.match_settings
  for each row execute function public.touch_match_settings();

-- Table privileges ------------------------------------------------------------------------
-- Newer Supabase projects do not grant table access to the API roles automatically.
-- Without these, every request fails with "permission denied for table match_settings"
-- (42501) before RLS is even checked. RLS below still decides which rows/actions pass.
grant usage on schema public to anon, authenticated;
-- anon (the Worker) reads the show/hide columns and the stream columns. The Worker attaches
-- streams only for its STREAM_ORIGINS (px-league.site, www.px-league.site, tariq-live.blogspot.com).
grant select (match_id, is_visible, channel, r2_slug) on public.match_settings to anon;
grant select on public.match_settings to authenticated;
grant insert, update, delete on public.match_settings to authenticated;
revoke all on public.stream_admins from anon, authenticated;   -- read only via is_stream_admin()

-- Row level security ----------------------------------------------------------------------
alter table public.match_settings enable row level security;

drop policy if exists "anyone reads match settings" on public.match_settings;
drop policy if exists "anon reads visibility" on public.match_settings;
create policy "anon reads visibility" on public.match_settings
  for select to anon using (true);
drop policy if exists "admins read match settings" on public.match_settings;
create policy "admins read match settings" on public.match_settings
  for select to authenticated using (public.is_stream_admin());

drop policy if exists "admins insert match settings" on public.match_settings;
create policy "admins insert match settings" on public.match_settings
  for insert to authenticated with check (public.is_stream_admin());

drop policy if exists "admins update match settings" on public.match_settings;
create policy "admins update match settings" on public.match_settings
  for update to authenticated using (public.is_stream_admin()) with check (public.is_stream_admin());

drop policy if exists "admins delete match settings" on public.match_settings;
create policy "admins delete match settings" on public.match_settings
  for delete to authenticated using (public.is_stream_admin());

-- Migration from the previous version (active_streams), if it exists ---------------------
do $$
begin
  if to_regclass('public.active_streams') is not null then
    insert into public.match_settings (match_id, channel, r2_slug)
    select match_id, channel, r2_slug from public.active_streams where is_active
    on conflict (match_id) do nothing;
  end if;
end $$;
-- After checking the migrated rows you can remove the old table:
-- drop table public.active_streams;

-- Add your admin (the column is user_id). By e-mail, no UUID copying needed:
-- insert into public.stream_admins (user_id)
--   select id from auth.users where email = 'you@example.com'
--   on conflict (user_id) do nothing;
