# 캡처 수집·상태·보관 부하 및 장애 검증 — v76

2026-11-14 · 기준 aitest `a85fa309b1d501223183c36f08bf74f560c71d50` · 기준 CI16개 성공/단위5,436통과.
인프라 담당 범위에서 비용 없는 로컬 검증을 수행했다. 탐지·LLM·정답·PDP/PEP를 변경하지 않았다.

## 이번에 완료한 범위

서명된 모형 캡처의 저장·health·보관 경로를 연속 실행하는 도구와 실제 systemd 작업자 반복 실행·회계 측정을 추가했다.
자격 공급자가 연결 한도를 소진하면 listener를 닫아 새 요청이 읽는 사람 없는 소켓에서 대기하지 않도록 수정했다. UID·키 크기·최대 연결 수 제한은 유지했다.
관련 영역만이 아니라 **전체 pytest 5,454통과·0skip**, Ruff+RUF100 통과다.
실제 systemd는 기존63조건+부하4조건 **67조건**을 통과했다. 동일1,048개 소스 스냅샷을 사용했다.

| 시험 | 실제 결과 |
|---|---|
| 연속 저장 | 512건, 143.778초, 3.561건/초 |
| 간격 저장 | 181건·2초 목표 간격, 360.658초 |
| 실제 systemd | 63회, 189.078초, 기존/신규73건 원본 해시 보존 |
| systemd 수집 호출 지연 | p50 1116.296ms / p95 1427.817ms / 최대 2578.889ms |
| systemd 보관 호출 지연 | p50 845.129ms / p95 1307.148ms / 최대 2577.155ms |
| systemd health 호출 지연 | p50 801.982ms / p95 1094.843ms / 최대 3886.547ms |
| 정상 기능 제어 | 직접/부하68건+timer 선택4건, 추가 탐지 경보0 |
| 기존 판정 비교 | 1,681,815행 동일, 새 FP0·TP 손실0·정답 재열람0 |
| 비용·정리 | 유료 API/AWS0, 소유 container/unit/accounting override/state/socket/WSL 소스 정리 |

단계별 호출 지연에는 systemctl 시작·journal 조회·계측/종료 등 시험 오버헤드가 포함된다. 순수 내부 함수 지연이나 실제 timer 수집 간격으로 해석하지 않는다.
모형 처리율은 저장 API의 결과이며 실제 프로세스 수집 처리율·최대 동시 사용자 수가 아니다. 분위수는 nearest-rank이며 원시 샘플 수와 최대값을 보존한다.

## 자원 측정

| 실제 systemd 작업자 | 측정 CPU 합계(초) | 회계 샘플 | 관측 메모리 peak(MiB) | 메모리 샘플 |
|---|---:|---:|---:|---:|
| collector | 미측정 | 0/63 | 미측정 | 0/63 |
| archive | 미측정 | 0/63 | 미측정 | 0/63 |
| health | 미측정 | 0/63 | 미측정 | 0/63 |

계측은 소유 fixture에만 CPUAccounting/MemoryAccounting·RemainAfterExit를 추가해 종료 직전 값을 읽고 매 호출 뒤 stop했다. 기존 보안 제한을 유지하고 종료 시 override를 제거했다.
이번 native63회에서 작업자 CPU/메모리 회계값은 모두 조회되지 않아 **미측정**이다. 유효하지 않은 회계값은 null로 남기며0으로 환산하지 않는다. 회계 활성화 설정만으로 수치 확보를 주장하지 않는다.
읽기 전용 환경 확인에서도 기존 journald 서비스의 CPUUsageNSec/MemoryPeak가 not set이고 unified controller 파일이 없음을 기록했다. 호스트 설정은 바꾸지 않았고 모든 WSL 환경의 지원 여부로 일반화하지 않는다.
추후 수치가 확보되더라도 메모리 peak는 관측된 작업자 최대값이며 모든 작업자의 합이나 호스트 전체 메모리가 아니다. 실제 작업자 CPU/메모리 재측정은 미완료다.
MemoryMax/TasksMax 등 템플릿 선언과 실제 커널 cgroup 자원 집행 확인을 구분한다. 이 native 시험으로 자원 한도 집행까지 인수하지 않았다.

| 모형 저장 경로 | 연속 처리 | 간격 처리 |
|---|---:|---:|
| 시험 프로세스 CPU(초) | 22.594 | 12.638 |
| 프로세스 peak RSS(MiB) | 64.25 | 64.44 |
| 첫→마지막 저장 파일 논리 바이트 | 6860→569404 | 2744→217148 |
| 첫→마지막 저장 파일 할당 바이트 | 20480→593920 | 8192→241664 |
| cycle 지연 p95(ms) | 1169.072 | 583.167 |
| 실제 cycle 시작 간격 p95(ms) | 1340.495 | 2000.21 |

논리/할당 바이트는 store의 정규 파일만 포함한다. 디렉터리 메타데이터·시험 결과·공개 설정·별도 health ledger·호스트 VHDX를 합친 디스크 사용량이나 물리 쿼터를 증명하지 않는다.
모형 저장 경로는 Docker Desktop의 Windows bind mount인 /results 아래에 있다. 실제 systemd 저장 경로는 별도 WSL /var/lib fixture다. 서로 다른 backing 경로의 속도를 직접 성능 우열로 비교하지 않는다.
CPU/RSS는 모형 시험 프로세스이며 native cgroup 지표와 다르다. 관측 기간의 증가는 파일 보관·검증 자료의 증가를 포함하며 메모리 누수 유무의 장기 판정으로 사용하지 않는다.
프로세스 CPU 차이에는 뒤의 장애 검증이 포함된다. pipeline_elapsed_seconds는 반복 처리 구간이며 peak RSS는 프로세스 시작부터의 최고값이다. 두 구간을 나눠 CPU 비율을 추정하지 않는다.

## 장애와 복구 근거

- **실제 공간 부족**: 이 컨테이너만 사용하는2MiB tmpfs를 채워 ENOSPC를 발생시켰다. atomic_capture의 교체 실패 뒤 이전 latest 바이트와 임시 파일 정리를 확인했다. 일반 디렉터리/4MiB 초과/비어 있지 않은 mount는 채우지 않는다. 운영 DB·파일시스템 전체의 ENOSPC 복구를 증명하지 않는다.
- **보관 용량 한도**: 전용 모형 archive의 max_records를 현재 보관 수로 제한해 신규 보관을 거부시켰다. hot/cold 모든 원본과 latest가 유지됐다. 한도는 무손실 정지이며 무한 보관이나 자동 삭제 정책이 아니다.
- **실제 잠금 경합**: 별도 프로세스가 동일 잠금을 보유하면 기본5초 한도 후 실패한다. 원본은 변하지 않았고 소유 작업자 종료 후 진행됐다.
- **실제 프로세스 종료**: SQLite 커밋 직후 정리 전에 os._exit(73)으로 종료했다. hot/cold 중복의 바이트 일치를 확인하고 새 작업자가 남은 정리를 완료했다. 프로세스 종료 검증이며 전원 차단/fsync 하드웨어 내구성 시험은 아니다.
- **상태 저장 실패**: 비root 작업자의 monitor DB를 읽기 전용으로 바꿔 unavailable을 확인했다. 권한 복구·작업자 재생성 뒤 fresh로 회복하고 기존 캡처를 덮어쓰지 않았다. 실제 DB ENOSPC 주입과는 구분한다.
- **실제 systemd 재시작**: 반복 실행 중 소유 target을 restart하고 새 invocation의 정상 서명 캡처를 확인했다. 최초 캡처부터 종료까지 모든 원본을 대조했다. 기존 자격 공급자 장애·30초 경과 stale·재개 시험도 함께 통과했다.

서명키는 별도 RAM 난수이며 사용자 키 파일을 읽지 않는다. 상태 확인은 접속 인가·자동 차단을 수행하지 않는다.

첫 실행에서는 새 잠금 시험의 오류 코드 비교1건이 실패했고 pytest는963통과 시점에 중단했다. 별도 native 반복 실행은 기본32회 자격 소켓 한도 소진 후 시작 timeout으로 중단됐다.
오류 코드 비교를 바로잡고, 자격 adapter의 listener 종료와 네 가지 성공/거부 경로의 한도 소진 후 ConnectionRefused 검증을 추가했다. 제한이나 서비스 timeout을 완화해 통과시키지 않았다.
최종 native fixture는28회 사용 시 전용 공급자를 명시적으로 교체해 후속 검증 여유를 남겼다. 실제 교체2회이며32회 한도는 유지했다. 운영 vault/자동 HA를 구현한 것으로 보지 않는다.
실패 소스와 최종 소스의 결과를 분리하고 최종 스냅샷에서 전체 pytest·부하/장애·native를 다시 검증했다. 최초 진단 지문도 공개 결과에 남긴다.

## 재현과 장기 시험

Linux local/test의 전용 비root 작업자에서 실행한다. 출력은 새 경로만 허용한다. 모형 수집임을 분명히 구분하고 운영 원본 경로를 인수로 받지 않는다.

```text
python -m scripts.run_capture_load --directory /전용/새출력 --cycles 128 --batch 4
python -m scripts.run_capture_load --directory /전용/새출력 --cycles 181 --batch 1 --interval 2
python -m scripts.run_capture_load --directory /전용/새출력 --cycles 1921 --batch 1 --interval 15
```

세 번째 명령은 최소8시간 목표의 **모형 저장 경로 장기 시험 절차**다. 이번에는 실행하지 않았다. 진행 파일은 완료 전 completed=false이고, 완료 run.json과 그 SHA가 있는 최종 progress를 확인한다. 중단한 결과를 재개·덮어쓰거나 완료로 간주하지 않는다. 실행 키는 복구/재사용하지 않는다.
최대4,096cycle/4,096개 pipeline 캡처·interval60초, cold4,096개로 제한하며 마지막 장애 probe1건이 별도로 생긴다. 서명/registry 유효기간은12시간이며 만료 후 fresh를 만들지 않는다.

실제 systemd 전체 인수+최대600초 측정은 /run의 공개 소스·의존성과 root 시험 관리자 환경에서 다음을 실행한다. 기본180초다.

```text
python -m scripts.run_capture_load_runtime --directory /전용/새결과 --seconds 180
```

관리자는 기존 daemon UID1과 치환 경로로만 fixture를 만들고 운영 계정·timer를 설치하지 않는다. 실제 작업자 CPU/메모리 측정·timer 간격·8~12시간 native soak·호스트/데몬 재부팅·다중 호스트·혼합 경쟁 부하·운영 키 만료/회전 중 부하 시험은 별도다.
이번 장기 시험 완료값은 **false**이며 화요일 계획3번 전체를 완료 처리하지 않았다. 목표 부하·허용 지연·RTO/RPO·물리 쿼터는 운영 조건 합의 후 검증해야 한다.

## 기존 탐지 성능과 다음 순서

| 항목 | F1 이전→이후 | FP 이전→이후 | FN 이전→이후 |
|---|---:|---:|---:|
| 공유 서버 감사 | 0%→0% | 24→24 | 6→6 |
| 웹 서버 감사 | 70.77%→70.77% | 37→37 | 1→1 |
| 인증 | 95.08%→95.08% | 0→0 | 3→3 |

고정 개발 기준선이며 새 독립 평가가 아니다. 정상 제어·저장 무결성·부하 결과를 P/R/F1 목표 충족으로 환산하지 않는다.
다음은 장기 soak와 측정 조건 확정, 운영 키/최종 pin 보관·백업 timer/경보·원격 저장, 지속 mTLS mount/lock 활성화와 최종 인수 정리다.
kernel 실행 이력·조직 SSO/앱 연동·새 독립 성능 평가는 별도 미완료 범위로 유지한다.

- [공개 결과·소스/판정 지문](infrastructure-results/extra-capture-load-v76-20261114.json)
- [저장 부하·장애 구현](../scripts/f1_lab/capture_load.py), [실제 systemd 계측](../scripts/f1_lab/capture_load_runtime.py), [회귀 시험](../tests/test_capture_load.py)
- [systemd 자원 회계](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html), [Python resource](https://docs.python.org/3.12/library/resource.html), [Linux tmpfs](https://docs.kernel.org/filesystems/tmpfs.html): 회계 범위·프로세스 자원·격리된 공간 부족 주입의 선정 근거다. 시험 호스트는 systemd255.4이며 최신 문서에만 있는 옵션을 요구하지 않는다.

채희주 요청에 따른 Codex 보조 구현·실행·측정이며 팀원의 독립 검토로 기록하지 않는다.

후속 선택 검증 오류 보존·실제 mTLS 인수는 [v77](extra-selection-diagnostics.md)을 따른다. 과거 CI 원인 확정과 장기/systemd 회계 검증은 별도로 남는다.
