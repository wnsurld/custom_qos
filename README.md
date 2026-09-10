# OpenWrt 트래픽 분류 기반 적응형 지연 보호

## 🚀 프로젝트 소개

대용량 다운로드와 실시간 트래픽이 동시에 발생하는 환경에서 **실시간 트래픽을 보호하기 위해 다운로드 속도를 동적으로 조절**하는 OpenWrt 기반 프로젝트입니다.

대용량 다운로드가 대역폭을 많이 사용하면 실시간 트래픽의 지연이 증가할 수 있습니다. IP나 애플리케이션별로 고정된 속도 제한을 설정하는 방식과 달리, **트래픽 특성을 분석해 실시간 트래픽과 대용량 다운로드를 자동으로 구분하고, 두 트래픽의 동시 사용 여부에 따라 다운로드 대역폭을 낮추거나 복구**하도록 구현했습니다. 이를 통해 실시간 트래픽의 응답성을 보호하면서도 가용 대역폭을 효율적으로 활용하는 것을 목표로 합니다.


## ✨ 주요 기능

- **플로우 통계 수집**: WAN ingress 경로에서 TC eBPF로 패킷 수, 바이트 수, 패킷 크기 분포와 활동 시간을 수집합니다.
- **점수 기반 분류**: 프로토콜, 처리량, 초당 패킷 수와 크기를 조합해 REALTIME·BULK·UNKNOWN으로 분류합니다.
- **클래스별 트래픽 처리**: 분류 결과를 BPF 정책 map에 저장하고, 패킷을 IFB의 HTB 클래스로 연결합니다.
- **적응형 속도 제어**: 실시간·벌크 트래픽의 동시 사용이 지속되면 벌크 클래스의 전송 속도를 제한합니다.
- **단계적 복구**: 보호 유지 시간과 점진적인 속도 복구를 적용해 잦은 상태 전환을 줄입니다.


## ⚙️ 기능 구현 및 처리 흐름

### 1. TC eBPF 기반 수신 트래픽 관찰

WAN 인터페이스의 `clsact ingress`에 eBPF 프로그램을 연결해 유입되는 패킷을 관찰합니다. **Ethernet 헤더 다음에 IPv4가 오는 TCP·UDP 패킷**을 대상으로 합니다.

출발지·목적지 IP, 출발지·목적지 포트, 프로토콜로 플로우를 구분하고 `flow_stats_map`에 통계를 누적합니다.

| 수집 항목 | 용도 |
| --- | --- |
| 패킷 수·바이트 수 | 초당 패킷 수와 처리량 계산 |
| 작은 패킷 수 | 300바이트 이하 패킷의 비율 계산 |
| 큰 패킷 수 | 1,000바이트 이상 패킷의 비율 계산 |
| 최초·최근 관측 시각 | 플로우 활동 시간과 비활성 여부 확인 |

통계 맵은 최대 8,192개 항목을 저장하는 LRU 해시 맵입니다. 사용자 공간 데몬은 기본 500ms 간격으로 통계를 읽고, 이전 값과의 차이를 이용해 관측 구간의 특성을 계산합니다.

### 2. 점수 기반 트래픽 분류

`classify_flow()`는 실시간 점수와 벌크 점수를 각각 계산합니다.

| 분류 | 주요 판단 요소 | 의도한 트래픽 특성 |
| --- | --- | --- |
| REALTIME | 작은 평균 패킷 크기, 높은 작은 패킷 비율, 낮은 처리량, 설정 범위 내의 초당 패킷 수 | 작고 주기적인 패킷을 주고받는 통신 |
| BULK | 높은 처리량, 높은 큰 패킷 비율, 큰 평균 패킷 크기, 지속적인 전송 | 대용량 다운로드와 유사한 통신 |
| UNKNOWN | 점수 기준 미달 또는 두 점수의 동점 | 분류 근거가 부족한 통신 |

UDP에는 실시간 점수를, TCP에는 벌크 점수를 일부 부여하되, **처리량과 패킷 크기 등 여러 특성을 종합해 분류**합니다. 따라서 UDP 트래픽도 대용량 전송의 특성을 보이면 BULK로 분류될 수 있습니다. 실시간·벌크 점수 중 기본 임계값인 6점 이상이면서 상대 점수보다 높은 쪽으로 분류하며, 두 점수가 같거나 모두 임계값에 미달하면 UNKNOWN으로 처리합니다.

### 3. 분류 결과를 HTB 클래스에 연결

데몬은 플로우별 분류 결과를 `flow_policy_map`에 기록합니다. eBPF 프로그램은 이후 패킷에서 해당 정책을 조회해 `skb->priority`에 클래스 ID를 설정합니다.

```c
policy = bpf_map_lookup_elem(&flow_policy_map, &key);
if (policy && policy->class_id) {
    skb->priority = policy->class_id;
}
```

패킷은 eBPF 관찰·정책 적용 후 `ifb0`로 리다이렉트되며, IFB 송신 경로의 HTB와 클래스별 `fq_codel` 큐에서 처리됩니다.

| 분류 | HTB 클래스 | HTB 우선순위 | 처리 방식 |
| --- | --- | --- | --- |
| REALTIME | `1:10` | 0 | 기본 rate 1mbit, 설정한 회선 속도까지 대역폭 차용 가능 |
| UNKNOWN / 기본 경로 | `1:20` | 1 | 기본 클래스에서 처리 |
| BULK | `1:30` | 2 | 보호 상태에 따라 rate와 ceil을 동적으로 변경 |

**보호 상태에서 속도를 낮추는 대상은 BULK 클래스 `1:30`**이며, 모든 클래스는 상위 클래스에 설정된 전체 속도 한도를 공유합니다.

### 4. 동시 사용 감지와 보호 상태 전환

데몬은 실시간 플로우와 벌크 플로우가 동시에 관측되면 충돌 상황으로 판단합니다. 

| 상태 | 동작 및 전환 조건 |
| --- | --- |
| `IDLE` | 대기하다가 동시 사용이 감지되면 `WATCH`로 전환 |
| `WATCH` | 동시 사용이 기본 2초 동안 지속되면 `PROTECT`로 전환. 그 전에 해소되면 `IDLE`로 복귀 |
| `PROTECT` | 벌크 속도를 제한. 진입 후 최소 5초가 지나고 동시 사용이 해소되면 `RECOVER`로 전환 |
| `RECOVER` | 매 제어 주기마다 벌크 속도를 복구. 동시 사용이 재발하면 즉시 `PROTECT`로 전환 |

### 5. 벌크 속도 제한과 단계적 복구

기본 설정에서는 보호 상태에 진입할 때 벌크 클래스의 속도를 **300mbit에서 80mbit로 변경**합니다.

```sh
tc class change dev ifb0 parent 1:1 classid 1:30 \
  htb rate 80mbit ceil 80mbit prio 2
```

복구 상태에서는 매 제어 주기마다 20mbit씩 올려 설정한 회선 속도까지 복구합니다. 기본 제어 주기는 500ms입니다.

```text
WAN 수신 트래픽
    ↓
TC eBPF로 플로우 통계 수집 및 기존 정책 적용
    ↓
IFB로 리다이렉트 → HTB 클래스별 처리 → fq_codel → LAN / Wi-Fi

플로우 통계 맵
    ↓
사용자 공간 데몬이 주기적으로 통계 조회
    ↓
REALTIME / BULK / UNKNOWN 분류
    ├─ 정책 맵 갱신 → 이후 패킷의 클래스 선택에 반영
    └─ 실시간·벌크 동시 사용 확인
           ↓
       IDLE → WATCH → PROTECT → RECOVER
                         ↓          ↓
                    벌크 속도 제한  단계적 복구
```

## 🛠 기술 스택

| 구분 | 기술 및 역할 |
| --- | --- |
| 언어 | C — eBPF 프로그램과 사용자 공간 데몬 구현 |
| 실행 환경 | OpenWrt / Linux |
| 트래픽 관찰 | TC eBPF — 플로우 통계 수집 및 클래스 ID 적용 |
| BPF 연동 | libbpf — 프로그램 로드·연결 및 맵 조회·갱신 |
| 다운로드 제어 | IFB, Linux tc, HTB — 수신 트래픽을 송신 큐로 전환해 클래스별 셰이핑 |
| 빌드 및 운영 | Make, Clang/LLVM, Shell Script |



## 📂 프로젝트 구조

```text
bpf/
  flowmon.bpf.c       # 패킷 관찰, 통계 수집, 정책 적용
  flow_stats.h       # 커널·사용자 공간 공유 자료구조
daemon/
  main.c             # 실행 옵션과 주기적 제어 루프
  bpf_runtime.c      # BPF 로드·연결, 통계 조회, 정책 맵 갱신
  classifier.c       # 점수 기반 플로우 분류
  detector.c         # 보호 상태 머신
  controller.c       # tc를 통한 벌크 속도 변경
  config.h           # 기본 설정값
  util.c             # 인터페이스 이름 검증
scripts/             # IFB·TC 설정, 상태 확인, 정리, 패키지 스테이징
openwrt/             # OpenWrt 패키지 정의 및 UCI·서비스 설정
Makefile             # 데몬 및 BPF 빌드
```

## ▶️ 빌드 및 실행

### 1. 빌드

Linux 빌드 환경에서 C 컴파일러, Make, BPF 타깃을 지원하는 Clang/LLVM, Linux 헤더 및 libbpf·libelf·zlib 개발 파일이 필요합니다.

```sh
make
```

생성 파일은 `build/adaptive-latencyd`와 `build/flowmon.bpf.o`입니다. 실제 트래픽 제어에는 관리자 권한과 커널의 TC BPF·IFB·HTB·fq_codel 지원이 필요합니다.

### 2. mock 입력으로 제어 흐름 확인

```sh
./build/adaptive-latencyd --mock
```

내장된 가상 플로우로 분류와 상태 전환을 확인합니다. 기본 dry-run 모드에서는 속도 변경 명령을 로그로 출력합니다. 종료하려면 `Ctrl+C`를 누릅니다.

### 3. 실제 인터페이스에 연결

아래의 `wan`은 장비에서 사용하는 실제 WAN 네트워크 장치 이름으로 변경합니다. 초기화 스크립트는 해당 WAN의 기존 `clsact`와 IFB의 루트 qdisc를 삭제한 뒤 새로 구성합니다.

```sh
sh scripts/init_ifb_tc.sh wan ifb0 300mbit 80mbit

./build/adaptive-latencyd --wan wan --ifb ifb0 \
  --bpf build/flowmon.bpf.o
```

**dry-run은 동적 속도 변경 명령에만 적용됩니다.** 초기화 스크립트는 실제 TC 설정을 변경하며, 데몬도 mock 모드가 아니면 BPF 연결과 정책 맵 갱신을 수행합니다.

속도 변경까지 적용하려면 실행 중인 데몬을 종료한 뒤 `--apply`로 실행합니다.

```sh
./build/adaptive-latencyd --apply --wan wan --ifb ifb0 \
  --bpf build/flowmon.bpf.o \
  --line-rate 300 --protect-rate 80 --recover-step 20 \
  --trigger-delay 2000 --hold-time 5000 \
  --poll-interval 500 --log-interval 2000
```

### 4. 상태 확인 및 정리

```sh
sh scripts/show_tc_state.sh wan ifb0
```

데몬 종료 후 TC 설정을 제거하려면 다음을 실행합니다.

```sh
sh scripts/cleanup_tc.sh wan ifb0
```

## 🔧 기본 설정

| 옵션 | 기본값 | 의미 |
| --- | --- | --- |
| `--line-rate` | 300mbit | 전체 셰이핑 한도 및 벌크 복구 목표 |
| `--protect-rate` | 80mbit | 보호 상태의 벌크 속도 |
| `--recover-step` | 20mbit | 제어 주기당 복구 증가량 |
| `--trigger-delay` | 2,000ms | 보호 진입 전 동시 사용 지속 시간 |
| `--hold-time` | 5,000ms | 보호 상태 진입 후 최소 유지 시간 |
| `--poll-interval` | 500ms | 통계 조회 및 제어 주기 |
| `--log-interval` | 2,000ms | 상태 로그 출력 주기 |
| `--realtime-score` / `--bulk-score` | 각 6점 | 분류 임계 점수 |

명령행에는 단위 없이 숫자를 전달합니다. 이 값들은 제어 루프를 시험하기 위한 시작값이며, 회선과 사용 패턴에 맞춰 조정해야 합니다.

분류에는 `--realtime-max-kbps`, `--bulk-min-kbps`, `--realtime-min-pps`, `--realtime-max-pps` 옵션도 사용할 수 있습니다. 현재 코드에서 이름이 `kbps`인 두 옵션은 **입력값 × 1024를 바이트/초와 비교**하므로, 설정 시 비트/초 단위와 혼동하지 않아야 합니다.

## 📦 OpenWrt 패키지

저장소를 OpenWrt SDK 또는 소스 트리에 스테이징하고 패키지를 빌드합니다.

```sh
sh scripts/stage_openwrt_package.sh /path/to/openwrt-sdk
cd /path/to/openwrt-sdk
make package/adaptive-latency/compile V=s
```

패키지 설치 후 설정 파일은 `/etc/config/adaptive_latency`에 위치합니다. 서비스는 기본적으로 비활성화되어 있으며, dry-run이 기본값입니다.

```sh
uci set adaptive_latency.main.enabled='1'
uci set adaptive_latency.main.dry_run='1'
uci set adaptive_latency.main.wan_if='wan'
uci set adaptive_latency.main.line_rate_mbit='300'
uci set adaptive_latency.main.protect_rate_mbit='80'
uci commit adaptive_latency
/etc/init.d/adaptive_latency enable
/etc/init.d/adaptive_latency start
```

서비스 시작 시 dry-run에서도 IFB·TC 초기화가 실행됩니다. 동적 속도 변경을 적용하려면 `dry_run`을 `0`으로 설정하고 서비스를 재시작합니다.



기반 기술: OpenWrt, Linux Traffic Control, eBPF, libbpf.
