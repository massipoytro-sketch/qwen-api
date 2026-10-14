create index if not exists graph_subject_edges_tenant_relationship_idx
  on security.graph_edges (tenant_id, relationship, confidence desc, last_seen_at desc)
  where left_type = 'subject' or right_type = 'subject';

create index if not exists graph_resource_edges_tenant_idx
  on security.graph_edges (tenant_id, left_type, left_id, confidence desc)
  where left_type <> 'subject';

create index if not exists graph_resource_edges_tenant_right_idx
  on security.graph_edges (tenant_id, right_type, right_id, confidence desc)
  where right_type <> 'subject';

create index if not exists fraud_clusters_subject_ids_gin_idx
  on security.fraud_clusters using gin (subject_ids);
