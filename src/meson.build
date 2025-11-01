#c source files, if adding new features add c file to this list 
srcs = files(
  'main.c',
  'control_server.c',
  'stats.c',
  'ports.c',
  'pcap_loader.c',
  'buff_worker.c',
  'tx_worker.c',
  'mbuf_fields.c',
  'flowtable.c',
  'ft_manager.c'
)

executable(
  'pcap_replay_dataplane',
  srcs,
  dependencies: [dpdk,jansson,pthread,pcap],
  include_directories: include_directories('../include'))

