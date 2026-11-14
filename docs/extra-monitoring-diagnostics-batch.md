# 로컬 mTLS 장애 진단 수집 보완 — v54

2026-11-14 · 실제 exporter 중단 시 진단 API를 네 번의 별도 `docker exec`로 호출하던 경로를
한 번의 operator 프로세스로 묶었다. 고정된 읽기 전용 mTLS 요청 네 개를 내부에서 동시에 실행한다.
전체 진단 예산20초, 인증서 검증과 pin, 응답·표본 상한은 유지했다.

## 발견한 문제와 변경

PR60의 재시작 관측 수정 후 GitHub CI의16개 검사는 모두 통과했다(run43472686718).
그러나 Windows에서 조율한 별도 로컬 전체 실행은26개 조건 확인 뒤
`monitoring_diagnostics_missing_live_fault`로 실패했다. 이 실패를 CI 성공으로 덮지 않았다.

분리 재현에서는 exporter가 실제 중단됐고 경보도 발생했지만, 기존 진단의 `up`, `alerts`, `rules`는
미수집 상태였으며 경보 표본 시각만 수집됐다. 총17.406초로 전체 예산은 남아 있었다.
각 별도 실행의4초 제한과 시작 비용이 영향을 주는 것으로 보고 실행 횟수를 줄였다.
이 관측만으로 모든 누락이 동일한 원인이라고 단정하지 않는다.

- 부모는 자기 프로젝트의 컨테이너만 조회하고 operator에서 진단 프로세스 한 번을 실행한다.
- 자식은 고정된 Prometheus 조회 세 개와 alert rule 조회 한 개만 보낸다. 외부 입력으로 경로·메서드를 바꾸지 않는다.
- 네 요청은 각각 새로운 pinned mTLS 연결을 사용한다. 하나가 실패해도 다른 실제 응답을 남긴다.
- 자식과 부모 모두 허용된 라벨·경보·유한 숫자만 공개한다. 임의 오류 본문·자격 증명·원문 토큰을 전달하지 않는다.
- 표본·규칙은 각각32개로 제한한다. 조회 실패는 `available=false`로 남기며 정상 상태로 대체하지 않는다.
- 기존 전체20초 안에서 단일 실행에 최대14초를 배정한다. 실패 시 추가 조회를 반복하지 않는다.
- 전체 인수 시험의 실제 장애 snapshot은 assertion 전에 저장해 실패 원인을 보존한다.

## 검증 상태

Windows 관련72개, network none Linux 관련95개가 통과했다. Linux에서 전체 Ruff+RUF100,
스냅샷919파일 불변과 소유 컨테이너 제거를 확인했다. 첫 Linux 시도는 존재하지 않는 시험 파일을
실행 목록에 넣어 시험 수집 전에 실패했고, 목록을 바로잡아 재실행했다. 실패 기록은 보존했다.

실제 exporter 중단 재현에서 새 진단은5.907초에 `up=0`, `C01ExporterDown=firing`, 경보 표본 시각,
규칙 상태 및 중단된 exporter의 상태를 모두 수집했다. 실제 소요 시간은 이 로컬 환경의 한 실행 결과다.
동일한 부하에서 반복 측정한 성능 벤치마크로 해석하지 않는다.

전체 monitored mTLS 재검증도 **75개 조건 통과**로 완료했다.
실제 장애 진단과 중복 관측·재시작 검사를 포함하며 소유 컨테이너·볼륨·네트워크 잔여0을 확인했다.
첫 전체 재실행은 진단 검사 이후 별개의 이력 개수 조건에서 실패했다.
[만료와 회수 검증 보완](extra-outage-expiry-validation.md)을 함께 적용한 최종 실행이다.
[공개 근거](infrastructure-results/extra-monitoring-diagnostics-batch-v54-20261114.json)에
허용된 진단 필드·검사명·지문을 보존했다. 앞선 실패 기록도 유지했다.

로컬 근거는 `runtime/c02/monitoring-diagnostics-probe-v53-20261114-02/verification.json`,
`runtime/c02/monitoring-diagnostics-batch-v54-20261114/verification.json`,
`runtime/c02/diagnostic-batch-tests-v54-20261114-02/tests.json`이다.
유료 LLM·AWS 호출은0이다. 탐지 규칙·모델·정답이나 F1 지표를 바꾸는 변경이 아니다.
