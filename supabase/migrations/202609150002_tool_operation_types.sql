alter table public.ai_operations drop constraint if exists ai_operations_operation_type_check;
alter table public.ai_operations add constraint ai_operations_operation_type_check
  check (operation_type in ('text_chat', 'image_chat', 'ip_lookup', 'dns_lookup'));
