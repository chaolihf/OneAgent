module com.chinatelecom.oneops.exporter/OneAgent

go 1.21.0

toolchain go1.22.2

require (
	github.com/chaolihf/udpgo v0.0.14
	//github.com/elastic/beats/v7 v8.10.2
	github.com/containerd/cgroups/v3 v3.0.1
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/prometheus/client_golang v1.16.0
	go.uber.org/zap v1.23.0
	google.golang.org/protobuf v1.30.0
)

require (
	github.com/chaolihf/node_exporter v1.8.5-beta4
	github.com/go-kit/log v0.2.1
)

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/Shopify/sarama v1.37.2 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/alecthomas/kingpin/v2 v2.3.2 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/beevik/ntp v1.3.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bramvdbogaerde/go-scp v1.4.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chaolihf/goja v0.9.1 // indirect
	github.com/chaolihf/gopsutil v0.0.7 // indirect
	github.com/cilium/ebpf v0.13.0 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dennwc/btrfs v0.0.0-20230312211831-a1f570bd01a1 // indirect
	github.com/dennwc/ioctl v1.0.0 // indirect
	github.com/dlclark/regexp2 v1.10.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dop251/goja v0.0.0-20240220182346-e401ed450204 // indirect
	github.com/eapache/go-resiliency v1.3.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/ema/qdisc v1.0.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-resty/resty/v2 v2.13.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20230926050212-f7f687d19a98 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-envparse v0.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hodgesds/perf-utils v0.7.0 // indirect
	github.com/illumos/go-kstat v0.0.0-20210513183136-173c9b0a9973 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.3 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/jsimonetti/rtnetlink v1.3.5 // indirect
	github.com/klauspost/compress v1.15.11 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lufia/iostat v1.2.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-xmlrpc v0.0.3 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mdlayher/ethtool v0.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mdlayher/wifi v0.1.0 // indirect
	github.com/miekg/dns v1.1.61 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect
	github.com/natefinch/lumberjack v2.0.0+incompatible // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.17 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus-community/go-runit v0.1.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/exporter-toolkit v0.10.0 // indirect
	github.com/prometheus/procfs v0.11.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shirou/gopsutil/v3 v3.23.11 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/arch v0.7.0 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1 // indirect
	golang.org/x/exp/typeparams v0.0.0-20221212164502-fae10dda9338 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/oauth2 v0.8.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/telemetry v0.0.0-20240521205824-bda55230c457 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	golang.org/x/tools/gopls v0.14.2 // indirect
	golang.org/x/vuln v1.0.1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/tools v0.4.5 // indirect
	howett.net/plist v1.0.0 // indirect
	mvdan.cc/gofumpt v0.4.0 // indirect
	mvdan.cc/xurls/v2 v2.4.0 // indirect
)
