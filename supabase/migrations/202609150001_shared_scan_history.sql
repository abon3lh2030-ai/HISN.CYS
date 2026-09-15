-- Private, capability-key-owned scan records. Never expose the service key to clients.
create table if not exists public.scan_history (
  owner_hash text not null check (owner_hash ~ '^[0-9a-f]{64}$'),
  id uuid not null,
  scanned_at timestamptz not null,
  record jsonb not null check (octet_length(record::text) <= 24000),
  deleted_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (owner_hash, id)
);
create index if not exists scan_history_owner_date on public.scan_history(owner_hash, scanned_at desc) where deleted_at is null;
alter table public.scan_history enable row level security;
revoke all on public.scan_history from anon, authenticated;
grant select, insert, update on public.scan_history to service_role;
-- Every API query includes SHA256 of the 256-bit vault key; no cross-vault read route.
