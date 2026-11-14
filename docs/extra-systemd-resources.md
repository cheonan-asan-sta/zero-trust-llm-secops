# 실제 systemd 작업자 자원 계측·로컬 제한 검증 — v79

2026-11-15 · 기준 aitest `5e1410af2bb3509141a8fd60b3e7e209bb310cb9` · [v76 부하/미측정 기록](extra-capture-load.md)과 [v78 진단](extra-execution-maintenance.md)의 후속 인프라 작업이다.

## 완료 결과

| 범위 | 확인한 결과 |
|---|---|
| 집중/전체 로컬 | 집중118개·전체5,563개 통과·0skip, Ruff+RUF100 통과 |
| 실제 systemd 기능 | 기존67개와 측정 완전성1개, 총68조건 통과 |
| 실제 작업자 측정 | 수집·보관·health 각각25/25회, 계측 출처와 현재 invocation 결속 |
| 부하 관측 | 목표60초·실제60.435초, 캡처35건 원본 해시 일치 |
| 실제 작업자 제한 읽기 | 각 작업자의 memory limit256MiB·pids limit16을 커널 파일에서 확인 |
| 별도 CPU 압력 fixture | 25% quota 활성값과 nr_throttled 증가 확인 |
| 별도 메모리 압력 fixture | 64MiB 한도 확인 후128MiB 할당 시도, 근거 `kernel_memory_limit_reclaim_counter` |
| 기존 판정 | 1,681,815건 SHA 동일·새 FP0·기존 TP 손실0·정답 재열람0 |
| 비용·정리 | AWS·유료 API0, 소유 unit/drop-in/state/socket/credentials와 WSL 소스·단위 컨테이너 정리 |

집중118개는 전체의 부분집합이다. 실제 systemd68조건과 별도 압력 fixture2조건도 목적·결과 파일을 구분한다.
이전 v76의 CPU/메모리는 각각0/63회 **미측정**이었으며 사용량0이 아니었다. 이전 기록을 새 값으로 덮어쓰지 않는다.
초기 후보는 native68조건이 통과했지만 전체 pytest에서5,561통과·복구 fixture 준비 오류1건이 있었다. 사건 전이의 updated_at이 created_at보다 앞서던 오류를 보존했다. 정확한 OS 시각 보정 원인까지 확정하지 않는다.
복구용 모형 사건의 시간만 한 번 고정하고 종료 시 원래 clock을 복구했다. 운영 사건 처리·시간 순서 검증·탐지 기준은 바꾸지 않았다. 회귀 시험과 새 고정 소스의 집중/전체/native를 다시 실행한 최종 결과를 위 표에 사용했다.

| 실제 작업자 | CPU/메모리 측정 회수 | CPU 합계(초) | 관측 cgroup 메모리 peak(MiB) |
|---|---:|---:|---:|
| collector | 25/25 | 14.423301 | 40.676 |
| archive | 25/25 | 13.656879 | 37.934 |
| health | 25/25 | 13.234156 | 38.016 |

합계 CPU는 각 실행의 관측 값을 합한 수치다. 메모리 peak는 실행별 cgroup peak 중 최대값이며 프로세스 RSS·호스트 메모리·작업자 전체 합계가 아니다.
동일 프로세스 계측 wrapper와 기존 하위 프로세스 비용이 포함되고, 최종 측정 뒤 출력/인터프리터 종료 비용 전체를 측정한 것은 아니다.
v76과 기간·계측 방식이 달라 지연/처리율의 직접적인 성능 우열 비교로 사용하지 않는다. 장기 메모리 누수나 운영 최대 용량도 증명하지 않는다.

## 무엇을 변경했는가

현재 WSL은 v1/v2 혼합 구성이다. CPUUsageNSec/MemoryPeak의 systemd 속성이 unset이어도, 해당 실행의 v2 cpu.stat과 v1 memory.max_usage_in_bytes에서 값이 조회되는 것을 확인했다.
짧은 작업이 끝나면 cgroup 경로가 사라지는 현상도 관측했다. 따라서 루트 cgroup.controllers 부재만으로 전체 지원 여부를 판단하거나 종료 후 조회만으로 수치를 확보할 수 있다고 가정하지 않는다.
이것은 현재 관측과 코드 개선의 근거이며, 과거 모든 WSL 환경의 실패 원인을 소급 확정한 것은 아니다.

[measure_systemd_worker](../scripts/measure_systemd_worker.py)는 기존3개 모듈만 동일 Python 프로세스에서 실행한다. 원래 stdout·종료 코드/예외를 유지하고 종료 직전 안전한 자원 영수증을 별도 prefix로 남긴다.
[systemd_resources](../scripts/systemd_resources.py)는 /proc/self/cgroup에 있는 비루트 그룹만 읽는다. v2 CPU/메모리와 v1 cpuacct·memory를 구분하고 숫자 단위를 보존한다. 0은 유효한 관측, 누락·무제한·잘못된 수는 null이다.
CPUacct가 루트에 묶여 있다면 그 합계를 작업자 사용량으로 빌려오지 않는다. 경로 traversal·외부 symlink·초과 파일·중복 stat 키를 거부하며 cgroup에 쓰거나 카운터를 reset하지 않는다.

부하 인수 도구는 현재 systemd InvocationID·journald의 _SYSTEMD_INVOCATION_ID·영수증의 invocation_id와 작업 종류가 모두 일치하는 영수증 하나만 받는다.
기존 systemd 속성이 유효하면 출처를 남겨 사용하고, unset일 때만 검증된 kernel snapshot을 사용한다. 과거 실행·중복·실패한 작업·출처 없는 수·허위 boolean·추가 필드는 거부한다.
실제 작업자의 모든 측정이 확보되지 않으면 측정 인수를 실패로 처리한다. 관측 누락을0이나 성공으로 바꾸지 않는다.
계측 실패가 원래 작업자의 종료 결과를 바꾸지는 않는다. 영수증이 없으면 부모 인수는 실패한다. 원래 signed 캡처·신선도·보관·인가 판단은 변경하지 않았다.

계측은 **소유 부하 fixture의 임시 drop-in/대체 unit에만** 적용했다. 운영 템플릿이나 전역 WSL/systemd 설정 파일을 바꾸거나 설치·활성화하지 않았다.
argv·환경 전체·키/토큰·본문·원문 오류 텍스트는 영수증에 넣지 않는다. 서명키는 기존 RAM→systemd credential 경로를 유지하며 사용자 키 파일은 읽지 않았다.
자원 관측은 신원 증명이나 접근 허용/자동 차단 권한이 아니며, 독립 외부 감사를 완료한 것도 아니다.

## 제한 검증의 범위

[run_systemd_resource_limits](../scripts/run_systemd_resource_limits.py)는 UUID 소유의 비root service에 CPU25%·Memory64MiB·Tasks8·PrivateNetwork·read-only·cap drop을 적용한다.
부하 코드는 커널의 실제 제한값을 먼저 확인하고, 불일치·미지원이면77로 종료해 압력을 가하지 않는다. CPU는 약1.5초, 메모리는 최대128MiB 할당/페이지 접촉으로 제한했다. 시작/종료 시간 제한도 적용했다.
CPU는 quota 선언만이 아니라 실제 throttling 카운터 증가를 확인한다. 메모리는 이번 실행에서 한도 도달·회수 카운터 증가로 확인했다. OOM 종료나 swap 비활성화의 성공으로 기록하지 않는다.
실제 수집/보관/health의256MiB·Tasks16은 커널 값 읽기 검증이고, Tasks16을 소진시키는 fork 시험은 하지 않았다. 별도64MiB fixture 결과를 실제 운영의 적정 quota 선정으로 확대하지 않는다.
ExecStopPost에서는 cgroup이 재생성돼 카운터가 낮아질 수 있으므로 CPU/회수 판정은 부하 완료 시점의 영수증을 사용한다. 과거 cgroup의 카운터를 새 실행에 합산하지 않는다.

## 재현과 남은 작업

```text
# Linux PID1=systemd·root, /run/zt-resource-v79-*의 검증된 공개 소스와 기존 의존성 필요
python -m scripts.run_systemd_resource_limits --directory runtime/새-제한-시험
python -m scripts.run_capture_load_runtime --directory runtime/새-실제-systemd --seconds 60
python -m pytest tests/test_systemd_resources.py tests/test_capture_load.py tests/test_collector_schedule.py -q
```

네이티브·Docker 단위 시험은 동일 소스 아카이브/파일 SHA를 사용했다. 네이티브 의존성은 기존 캐시 이미지의 아카이브 SHA와 변경 없는 test.lock을 확인해 재사용했다.
이 소규모60초 관측은8~12시간 장기 시험·운영 SLO/RTO/RPO·실제 운영 부하/한도 선정의 대체물이 아니다. 다음은 장기 실행·운영 경보/백업·키/외부 pin·최종 인수다.
과거 PR71 선택 실패와 PR72 실행 보관 실패의 정확한 원인은 여전히 미확인이다.
공유 감사 F1 0%·FP24/FN6, 웹 감사70.77%·FP37/FN1, 인증95.08%·FP0/FN3는 그대로다. 탐지·LLM·라벨·PDP/PEP를 변경하지 않았고 새 독립 성능 평가가 아니다.

- [공개 결과·소스/판정 지문](infrastructure-results/extra-systemd-resources-v79-20261115.json)
- [systemd255 자원 제어](https://www.freedesktop.org/software/systemd/man/255/systemd.resource-control.html): 버전에 맞는 속성·제한 의미의 근거.
- [Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html): CPU 사용량·제한과 혼합 계층 의미의 근거.
- [Linux v1 memory 인터페이스](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/memory.html): peak·limit·failcnt 필드의 근거. 이 문서는 오래된 설명이라는 자체 경고가 있어 실제 커널 readback·압력 결과도 함께 검증했다.

채희주 요청에 따른 Codex 보조 구현·실행이며 팀원 독립 검토/운영 승인으로 기록하지 않는다.
