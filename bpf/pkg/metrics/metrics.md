# Metrics
- [bpf.tcp.connlatency](#bpftcpconnlatency) : TCP connection latency
- [bpf.tcp.rx](#bpftcprx) : TCP received bytes
- [bpf.tcp.tx](#bpftcptx) : TCP transmitted bytes


## bpf.tcp.connlatency

TCP connection latency



| Prometheus name | Unit | Metric Type | ValueType |
| --------------- |  ---- | ------------ | --------- |
| bpf_tcp_connlatency_milliseconds | ms | Histogram | float64|

### Attributes

| Name | Prometheus label | Description | Type | Required |
|------| ---------------- |-------------|------| ------- |
| net.af | net_af | Address family of the network packet. | string | ✅ |
| net.daddr | net_daddr | Destination address of the network packet. | string | ✅ |
| net.saddr | net_saddr | Source address of the network packet. | string | ✅ |
| pid.comm | pid_comm | Name of the process. | string | ✅ |
| pid.tgid | pid_tgid | Thread group ID of the process. | int64 | ✅ |


## bpf.tcp.rx

TCP received bytes



| Prometheus name | Unit | Metric Type | ValueType |
| --------------- |  ---- | ------------ | --------- |
| bpf_tcp_rx_bytes_total | By | Counter | int64|

### Attributes

| Name | Prometheus label | Description | Type | Required |
|------| ---------------- |-------------|------| ------- |
| net.daddr | net_daddr | Destination address of the network packet. | string | ✅ |
| net.saddr | net_saddr | Source address of the network packet. | string | ✅ |
| pid.comm | pid_comm | Name of the process. | string | ✅ |
| pid.id | pid_id | Process ID. | int64 | ✅ |


## bpf.tcp.tx

TCP transmitted bytes



| Prometheus name | Unit | Metric Type | ValueType |
| --------------- |  ---- | ------------ | --------- |
| bpf_tcp_tx_bytes_total | By | Counter | int64|

### Attributes

| Name | Prometheus label | Description | Type | Required |
|------| ---------------- |-------------|------| ------- |
| net.daddr | net_daddr | Destination address of the network packet. | string | ✅ |
| net.saddr | net_saddr | Source address of the network packet. | string | ✅ |
| pid.comm | pid_comm | Name of the process. | string | ✅ |
| pid.id | pid_id | Process ID. | int64 | ✅ |

