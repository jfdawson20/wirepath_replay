#c source files, if adding new features add c file to this list 
srcs = files(
  'main.c',
  'wpr_control_server.c',
  'wpr_stats.c',
  'wpr_stats_rpc.c',
  'wpr_ports.c',
  'wpr_port_rpc.c',
  'wpr_pcap_loader.c',
  'wpr_pcap_loader_rpc.c',
  'wpr_tx_worker.c',
  'wpr_mbuf_fields.c',
  'wpr_log.c',
  'wpr_qsbr.c',
  'wpr_acl.c',
  'wpr_acl_db.c',
  'wpr_acl_rpc.c',
  'wpr_acl_yaml.c',
  'wpr_header_extract.c',
  'wpr_config.c'
)

executable(
  'pcap_replay_dataplane',
  srcs,
  dependencies: [dpdk,jansson,pthread,pcap, cyaml],
  include_directories: include_directories('../include'))

