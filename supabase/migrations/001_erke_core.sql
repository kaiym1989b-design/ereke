-- ERKE экожүйесі: ERKE MD (клиент) + ERKE PAY (сатушы) ортақ backend
create extension if not exists pgcrypto;

create type public.app_role as enum ('CUSTOMER','ADMIN');
create type public.store_role as enum ('OWNER','MANAGER','ACCOUNTANT','STORE_MANAGER');
create type public.order_status as enum ('NEW','ACCEPTED','PREPARING','READY','COMPLETED','CANCELLED');
create type public.payment_status as enum ('PENDING','PAID','FAILED','REFUNDED');
create type public.delivery_status as enum ('PENDING','IN_TRANSIT','DELIVERED');

-- profiles
create table public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text, phone text,
  role public.app_role not null default 'CUSTOMER',
  created_at timestamptz not null default now());

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles(id, full_name) values (new.id, coalesce(new.raw_user_meta_data->>'full_name',''))
  on conflict (id) do nothing;
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- stores
create table public.stores(
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  owner_id uuid references auth.users(id) on delete set null,
  name text not null, business_name text, bin text, phone text, address text, city text, logo_url text,
  open_time time default '09:00', close_time time default '21:00',
  is_active boolean not null default true,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());

create table public.store_members(
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null references public.stores(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.store_role not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','DISABLED')),
  created_at timestamptz not null default now(),
  unique(store_id,user_id));

create table public.store_invites(
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null references public.stores(id) on delete cascade,
  email text not null,
  role public.store_role not null,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique(store_id,email));

-- products
create table public.products(
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null references public.stores(id) on delete cascade,
  slug text not null,
  category text, name text not null, description text, composition text, size text,
  price integer not null check (price >= 0),
  image_url text,
  is_available boolean not null default true,
  sort integer not null default 0,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique(store_id,slug));
create index on public.products(store_id);

-- orders
create sequence public.erke_order_seq;
create table public.orders(
  id uuid primary key default gen_random_uuid(),
  order_number text unique not null default ('ERKE-'||lpad(nextval('public.erke_order_seq')::text,6,'0')),
  customer_id uuid references auth.users(id) on delete set null,
  customer_key uuid,
  store_id uuid not null references public.stores(id),
  status public.order_status not null default 'NEW',
  subtotal integer not null default 0, delivery_fee integer not null default 0, total integer not null default 0,
  payment_method text, payment_status public.payment_status not null default 'PENDING',
  customer_name text, customer_phone text,
  delivery_method text, delivery_address text, delivery_details jsonb not null default '{}'::jsonb,
  delivery_time text, delivery_status public.delivery_status not null default 'PENDING',
  cancel_reason text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create index on public.orders(store_id, created_at desc);
create index on public.orders(customer_key);

create table public.order_items(
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_slug text, product_name text not null,
  price integer not null, quantity integer not null check (quantity > 0), subtotal integer not null,
  created_at timestamptz not null default now());
create index on public.order_items(order_id);

create table public.order_status_history(
  id bigint generated always as identity primary key,
  order_id uuid not null references public.orders(id) on delete cascade,
  status public.order_status not null,
  changed_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now());
create index on public.order_status_history(order_id);

create or replace function public.touch_updated_at() returns trigger language plpgsql set search_path=public as $$
begin new.updated_at = now(); return new; end $$;
create trigger t_stores_upd before update on public.stores for each row execute function public.touch_updated_at();
create trigger t_products_upd before update on public.products for each row execute function public.touch_updated_at();
create trigger t_orders_upd before update on public.orders for each row execute function public.touch_updated_at();

-- helpers
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'ADMIN') $$;
create or replace function public.has_store_role(p_store uuid, p_roles public.store_role[] default null) returns boolean
language sql stable security definer set search_path=public as $$
  select public.is_admin() or exists(select 1 from public.store_members m where m.store_id = p_store and m.user_id = auth.uid()
    and m.status = 'ACTIVE' and (p_roles is null or m.role = any(p_roles))) $$;

-- RLS
alter table public.profiles enable row level security;
alter table public.stores enable row level security;
alter table public.store_members enable row level security;
alter table public.store_invites enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.order_status_history enable row level security;

create policy "own profile read" on public.profiles for select to authenticated using (id = auth.uid() or public.is_admin());
create policy "own profile update" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
revoke update on public.profiles from anon, authenticated;
grant update (full_name, phone) on public.profiles to authenticated;
create policy "store members see colleagues" on public.profiles for select to authenticated using (exists(select 1 from public.store_members a join public.store_members b on a.store_id=b.store_id where a.user_id=auth.uid() and b.user_id=profiles.id));

create policy "stores public read" on public.stores for select to anon, authenticated using (is_active or public.has_store_role(id));
create policy "owner updates store" on public.stores for update to authenticated using (public.has_store_role(id, array['OWNER']::public.store_role[])) with check (public.has_store_role(id, array['OWNER']::public.store_role[]));

create policy "members read" on public.store_members for select to authenticated using (user_id = auth.uid() or public.has_store_role(store_id));
create policy "owner manages members" on public.store_members for all to authenticated using (public.has_store_role(store_id, array['OWNER']::public.store_role[])) with check (public.has_store_role(store_id, array['OWNER']::public.store_role[]));
create policy "owner manages invites" on public.store_invites for all to authenticated using (public.has_store_role(store_id, array['OWNER']::public.store_role[])) with check (public.has_store_role(store_id, array['OWNER']::public.store_role[]));

create policy "products public read" on public.products for select to anon, authenticated using (true);
create policy "managers insert products" on public.products for insert to authenticated with check (public.has_store_role(store_id, array['OWNER','MANAGER']::public.store_role[]));
create policy "managers update products" on public.products for update to authenticated using (public.has_store_role(store_id, array['OWNER','MANAGER']::public.store_role[])) with check (public.has_store_role(store_id, array['OWNER','MANAGER']::public.store_role[]));
create policy "owner deletes products" on public.products for delete to authenticated using (public.has_store_role(store_id, array['OWNER']::public.store_role[]));

create policy "store staff read orders" on public.orders for select to authenticated using (public.has_store_role(store_id) or customer_id = auth.uid());
create policy "read items of visible orders" on public.order_items for select to authenticated using (exists(select 1 from public.orders o where o.id = order_id and (public.has_store_role(o.store_id) or o.customer_id = auth.uid())));
create policy "read history of visible orders" on public.order_status_history for select to authenticated using (exists(select 1 from public.orders o where o.id = order_id and (public.has_store_role(o.store_id) or o.customer_id = auth.uid())));

-- RPC: клиент тапсырыс береді (ERKE MD)
create or replace function public.place_order(
  p_customer_key uuid, p_store_slug text, p_items jsonb,
  p_customer_name text, p_customer_phone text,
  p_delivery_method text, p_delivery_address text, p_delivery_details jsonb,
  p_delivery_time text, p_payment_method text)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v_store uuid; v_order public.orders; v_sub int := 0; v_fee int; it jsonb; pr public.products; q int; n int := 0;
begin
  if p_customer_key is null then raise exception 'customer_key required'; end if;
  select id into v_store from public.stores where slug = p_store_slug and is_active;
  if v_store is null then raise exception 'Дүкен табылмады'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 or jsonb_array_length(p_items) > 50 then raise exception 'Себет бос'; end if;
  if p_delivery_method not in ('post','taxi','taxi2') then raise exception 'Жеткізу тәсілі қате'; end if;
  v_fee := case p_delivery_method when 'post' then 1000 when 'taxi' then 500 else 0 end;
  -- тексеру
  for it in select * from jsonb_array_elements(p_items) loop
    q := (it->>'qty')::int;
    if q is null or q < 1 or q > 99 then raise exception 'Саны қате'; end if;
    select * into pr from public.products where store_id = v_store and slug = it->>'slug';
    if pr.id is null then raise exception 'Тауар табылмады: %', it->>'slug'; end if;
    if not pr.is_available then raise exception 'Қолжетімсіз тауар: %', pr.name; end if;
    v_sub := v_sub + pr.price * q;
  end loop;
  insert into public.orders(customer_id, customer_key, store_id, subtotal, delivery_fee, total, payment_method,
    customer_name, customer_phone, delivery_method, delivery_address, delivery_details, delivery_time)
  values (auth.uid(), p_customer_key, v_store, v_sub, v_fee, v_sub + v_fee, left(p_payment_method,40),
    left(p_customer_name,120), left(p_customer_phone,40), p_delivery_method, left(p_delivery_address,300), coalesce(p_delivery_details,'{}'::jsonb), left(p_delivery_time,60))
  returning * into v_order;
  for it in select * from jsonb_array_elements(p_items) loop
    q := (it->>'qty')::int;
    select * into pr from public.products where store_id = v_store and slug = it->>'slug';
    insert into public.order_items(order_id, product_id, product_slug, product_name, price, quantity, subtotal)
    values (v_order.id, pr.id, pr.slug, pr.name, pr.price, q, pr.price * q);
  end loop;
  insert into public.order_status_history(order_id, status) values (v_order.id, 'NEW');
  return jsonb_build_object('id', v_order.id, 'order_number', v_order.order_number, 'total', v_order.total, 'status', v_order.status);
end $$;

-- RPC: клиент өз тапсырыстарын көреді (customer_key арқылы)
create or replace function public.get_customer_orders(p_customer_key uuid)
returns jsonb language sql stable security definer set search_path=public as $$
  select coalesce(jsonb_agg(x order by x.created_at desc), '[]'::jsonb) from (
    select o.id, o.order_number, o.status, o.payment_status, o.subtotal, o.delivery_fee, o.total, o.delivery_method,
      o.delivery_address, o.payment_method, o.created_at, o.updated_at, o.cancel_reason,
      (select coalesce(jsonb_agg(jsonb_build_object('slug',i.product_slug,'name',i.product_name,'price',i.price,'qty',i.quantity,'subtotal',i.subtotal)),'[]'::jsonb) from public.order_items i where i.order_id=o.id) as items
    from public.orders o where p_customer_key is not null and o.customer_key = p_customer_key
    order by o.created_at desc limit 50) x $$;

-- RPC: сатушы статусты өзгертеді (ERKE PAY)
create or replace function public.set_order_status(p_order_id uuid, p_status public.order_status, p_reason text default null)
returns public.orders language plpgsql security definer set search_path=public as $$
declare o public.orders; ok boolean;
begin
  select * into o from public.orders where id = p_order_id for update;
  if o.id is null then raise exception 'Заказ табылмады'; end if;
  if not public.has_store_role(o.store_id, array['OWNER','MANAGER','STORE_MANAGER']::public.store_role[]) then raise exception 'Құқық жоқ'; end if;
  ok := (o.status='NEW' and p_status in ('ACCEPTED','CANCELLED')) or (o.status='ACCEPTED' and p_status in ('PREPARING','CANCELLED'))
     or (o.status='PREPARING' and p_status='READY') or (o.status='READY' and p_status='COMPLETED');
  if not ok then raise exception 'Статусты % → % ауыстыруға болмайды', o.status, p_status; end if;
  update public.orders set status = p_status,
    cancel_reason = case when p_status='CANCELLED' then left(p_reason,300) else cancel_reason end,
    delivery_status = case when p_status='COMPLETED' then 'DELIVERED'::public.delivery_status when p_status='READY' then 'IN_TRANSIT'::public.delivery_status else delivery_status end,
    payment_status = case when p_status='COMPLETED' and payment_method ilike '%қолма-қол%' then 'PAID'::public.payment_status else payment_status end
  where id = p_order_id returning * into o;
  insert into public.order_status_history(order_id, status, changed_by) values (o.id, p_status, auth.uid());
  return o;
end $$;

-- RPC: қолжетімділік (STORE_MANAGER да өзгерте алады)
create or replace function public.set_product_availability(p_product_id uuid, p_available boolean)
returns public.products language plpgsql security definer set search_path=public as $$
declare pr public.products;
begin
  select * into pr from public.products where id = p_product_id;
  if pr.id is null then raise exception 'Тауар табылмады'; end if;
  if not public.has_store_role(pr.store_id, array['OWNER','MANAGER','STORE_MANAGER']::public.store_role[]) then raise exception 'Құқық жоқ'; end if;
  update public.products set is_available = p_available where id = p_product_id returning * into pr;
  return pr;
end $$;

-- RPC: кірген қызметкер өз шақыруларын қабылдайды
create or replace function public.accept_invites() returns integer
language plpgsql security definer set search_path=public as $$
declare v_email text; n int := 0; inv record;
begin
  if auth.uid() is null then return 0; end if;
  select lower(email) into v_email from auth.users where id = auth.uid() and email_confirmed_at is not null;
  if v_email is null then return 0; end if;
  for inv in select * from public.store_invites where lower(email) = v_email loop
    insert into public.store_members(store_id, user_id, role) values (inv.store_id, auth.uid(), inv.role)
      on conflict (store_id, user_id) do update set role = excluded.role, status = 'ACTIVE';
    if inv.role = 'OWNER' then update public.stores set owner_id = auth.uid() where id = inv.store_id and owner_id is null; end if;
    delete from public.store_invites where id = inv.id; n := n + 1;
  end loop;
  return n;
end $$;

revoke all on function public.place_order(uuid,text,jsonb,text,text,text,text,jsonb,text,text) from public;
revoke all on function public.get_customer_orders(uuid) from public;
revoke all on function public.set_order_status(uuid,public.order_status,text) from public, anon;
revoke all on function public.set_product_availability(uuid,boolean) from public, anon;
revoke all on function public.accept_invites() from public, anon;
grant execute on function public.place_order(uuid,text,jsonb,text,text,text,text,jsonb,text,text) to anon, authenticated;
grant execute on function public.get_customer_orders(uuid) to anon, authenticated;
grant execute on function public.set_order_status(uuid,public.order_status,text) to authenticated;
grant execute on function public.set_product_availability(uuid,boolean) to authenticated;
grant execute on function public.accept_invites() to authenticated;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

-- Realtime
alter publication supabase_realtime add table public.orders;
alter publication supabase_realtime add table public.products;

-- tighten_helper_grants
revoke execute on function public.is_admin() from public, anon;
revoke execute on function public.has_store_role(uuid, public.store_role[]) from public, anon;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.has_store_role(uuid, public.store_role[]) to authenticated;
-- split_store_read_policy
drop policy "stores public read" on public.stores;
create policy "stores anon read" on public.stores for select to anon using (is_active);
create policy "stores auth read" on public.stores for select to authenticated using (is_active or public.has_store_role(id));
