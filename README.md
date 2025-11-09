
---

## ⚙️ Setup Guide

### 1. Create your Supabase tables
Go to **Supabase → SQL Editor**, and run this SQL code once:

```sql
create table if not exists pairing (
  id text primary key default 'main',
  code text not null,
  updated_at timestamptz default now()
);

create table if not exists latest_message (
  id text primary key default 'latest',
  text text,
  updated_at timestamptz default now(),
  sender text
);

insert into pairing (id, code) values ('main', '') on conflict (id) do nothing;
insert into latest_message (id, text) values ('latest', '') on conflict (id) do nothing;
