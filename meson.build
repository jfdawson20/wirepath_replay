project('pcap_replay_dataplane', 'c',
  version: '0.1',
  default_options: [
    'c_std=gnu11',
    'buildtype=debugoptimized',
    'b_lto=false',
    ])


add_project_arguments(
  '-fno-omit-frame-pointer',
  '-fno-optimize-sibling-calls',
  '-DALLOW_EXPERIMENTAL_API',
  language: 'c',
)

dpdk = dependency('libdpdk', required: true)
jansson = dependency('jansson', required: true)
pthread = dependency('threads', required: true)
pcap    = dependency('libpcap', required: true)

subdir('src')
