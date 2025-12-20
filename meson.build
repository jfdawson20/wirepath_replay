project('pcap_replay_dataplane', 'c',
  version: '0.1',
  default_options: [
    'c_std=gnu11',
    'warning_level=3',
    'buildtype=debugoptimized',  # default, can be overridden via -Dbuildtype=...
    'b_lto=false',
  ]
)


dpdk = dependency('libdpdk', required: true)
jansson = dependency('jansson', required: true)
pthread = dependency('threads', required: true)
pcap    = dependency('libpcap', required: true)
cyaml   = dependency('libcyaml', required: true)

# Conditional flags based on buildtype
bt = get_option('buildtype')

if bt == 'debug' or bt == 'debugoptimized'
  add_project_arguments(
    '-fno-omit-frame-pointer',
    '-fno-optimize-sibling-calls',
    '-DALLOW_EXPERIMENTAL_API',
    '-g',
    language: 'c',
  )
else
  # In release, we still want experimental APIs but no debug/profiling flags
  add_project_arguments(
    '-DALLOW_EXPERIMENTAL_API',
    '-Werror=implicit-function-declaration',
    '-Wmissing-prototypes',
    '-Wextra',
    language: 'c',
  )
endif

subdir('src')
