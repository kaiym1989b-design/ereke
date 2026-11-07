alter table public.profiles add column if not exists email text;
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles(id, full_name, email) values (new.id, coalesce(new.raw_user_meta_data->>'full_name',''), lower(new.email))
  on conflict (id) do update set email = excluded.email;
  return new;
end $$;
update public.profiles p set email = lower(u.email) from auth.users u where u.id = p.id and p.email is null;

insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('product-images','product-images', true, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

create policy "managers upload product images" on storage.objects for insert to authenticated
  with check (bucket_id = 'product-images' and public.has_store_role(((storage.foldername(name))[1])::uuid, array['OWNER','MANAGER']::public.store_role[]));
create policy "managers update product images" on storage.objects for update to authenticated
  using (bucket_id = 'product-images' and public.has_store_role(((storage.foldername(name))[1])::uuid, array['OWNER','MANAGER']::public.store_role[]));
create policy "managers delete product images" on storage.objects for delete to authenticated
  using (bucket_id = 'product-images' and public.has_store_role(((storage.foldername(name))[1])::uuid, array['OWNER','MANAGER']::public.store_role[]));

-- autoconfirm_invited_staff: шақырылған email тіркелгенде бірден расталады
create or replace function public.autoconfirm_invited() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  if new.email_confirmed_at is null and exists(select 1 from public.store_invites i where lower(i.email) = lower(new.email)) then
    new.email_confirmed_at := now();
  end if;
  return new;
end $$;
revoke execute on function public.autoconfirm_invited() from public, anon, authenticated;
drop trigger if exists before_auth_user_created on auth.users;
create trigger before_auth_user_created before insert on auth.users for each row execute function public.autoconfirm_invited();
