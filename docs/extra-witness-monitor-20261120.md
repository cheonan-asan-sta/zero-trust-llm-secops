# 감사 관측의 신선도와 수집 실패를 경보로 연결

> 최신 기본 주기/TTL·지연 경보는 [후속 수정45f1b93](extra-witness-monitor-cadence-20261120.md)을 따른다. 아래는 beb7144 시점의 구현·시험 기록이다.

2026-11-20 · `extra` · 구현 `beb7144`. [08:00까지의 지속 목표](extra-until-0800-20261120.md)는 계속 진행 중이다. 기존 수집기의 상태를 opt-in 집계 파일과 기존 인증 exporter에 연결했다. 개인키·원본 이벤트·사용자 신원·명령·경로·pin을 metric label로 내보내지 않는다. 기존 모델/탐지/정답은 변경하지 않았다.

## 무엇이 달라졌나

수집기가 `--status-file`로 공개 집계를 게시하고 exporter는 `--witness-observer-profile`을 지정한 경우에만 읽는다. metric 조회 중 감사 DB·개인키에 접근하지 않는다. 상태 파일에는 외부 프로필/최소 영수증 pin과 확인 시각을 고정하며, 관측 시각은 서명 영수증의 원래 시각이다. 상태 파일 TTL은30초다. TTL이 남아도 관측 자체가 만료되면 stale로 표시한다. 누락·손상·다른 pin·미래/만료된 상태 파일은 status_success0/healthy0으로 내보내고 예전 counter를 재사용하지 않는다.

관측 snapshot이 healthy인지와 **최근 수집 cycle이 성공했는지**를 별도로 표시한다. 단순 상태 조회에는 cycle 성공을 주장하지 않는다. 수집이 실패했을 때 읽기가 성공했다고 실패를 지우지 않는다. watch는 원래 pending ID와 기준 pin을 유지하고 실패 상태를 게시한다. 같은 호스트의 신뢰된 구성요소가 쓰는 unsigned 집계이며 원격 attestation이나 사람의 인증 증명은 아니다.

POSIX 게시 경로는 소유자/모드·부모 symlink·hardlink·크기를 확인하고 별도 `flock`으로 동시 게시를 막는다. 과거 시각/다른 프로필·최소 pin으로 덮어쓰기를 거부한다. 임시 파일 fsync → replace → 디렉터리 fsync 순서로 게시한다. 정상 파일이 손상되면 자동 초기화하지 않는다. 관리자가 원래 확인한 파일/별도 새 경로로 복구해야 한다. 최소 pin 변경도 자동 갱신하지 않고 별도 파일/관리자 검토가 필요하다.

**Windows의 안전한 공개 파일 게시/권한 인수는 지원하지 않는다.** 플랫폼 검사로 변경 전에 거부한다. 상태 데이터 검증/렌더링은 양 OS에서 시험하지만 실제 POSIX 소유권·잠금·내구성/공개 파일 HTTP 경로는 Linux에서 검증했다. Windows 초기 시험4건 실패는 기존 공개 파일 reader가 POSIX 모드 계약을 거부한 결과다. 권한 검사를 완화하지 않고 순수 검증과 native 파일 시험을 분리했다. 최초 원본을 보존했다.

## 연결 방법

```powershell
python -m scripts.audit_witness_observer watch --directory <control> --profile-sha256 <외부-profile-pin> --minimum-receipt <외부-minimum-pin> --status-file <별도-공개-status.json> --cycles 2
python -m scripts.audit_witness_observer export-status --directory <control> --profile-sha256 <외부-profile-pin> --minimum-receipt <외부-minimum-pin> --status-file <별도-공개-status.json>
python -m scripts.signal_metrics_exporter --upstream <기존-inbox-URL> --token-file <scrape-token> --witness-observer-profile <metrics-profile.json>
```

위 게시 명령은 Linux/POSIX에서 실행한다. 기존 exporter의 별도 `C01_UPSTREAM_API_KEY`, scrape 인증, TLS 선택 계약을 유지한다. 이번 통합 시나리오는 격리된 로컬 loopback HTTP이며 운영 mTLS 배포나 실제 기업 인수로 표시하지 않는다. metrics 프로필 예시의 placeholder를 실제 외부 고정 값으로 채워 사용한다.

```json
{
  "schema": "zt-witness-observer-metrics-profile-1",
  "profile_sha256": "<64자리-profile-pin>",
  "minimum_receipt": "<64자리-minimum-pin>",
  "status_file": "/absolute/public/status.json"
}
```

기존 `infra/observability/alerts.yaml`에 status 미검증, 관측 비정상, 용량 압박, 수집 실패 경보4종을 추가했다. 두 시각/실패의 구분은 metric에서도 유지한다. 용량 압박 상태는 관측 healthy가 아니므로 관측 비정상과 용량 경보가 함께 발생한다. 기본 설정에 프로필이 없으면 witness metric/경보를 생성하지 않는다.

## 실제 무료 로컬 검증

관련 묶음 **Windows114통과·81제외, Linux195통과·제외0**. 이번 상태 시험33건 중 순수 검증은 양 OS에서 실행하고 POSIX 게시/HTTP/실제 watch5건은 Windows에서 제외했다. 나머지 제외는 기존 witness 권한2건과 기존 Linux 전용 백업74건이다. 이 수치를 전체 프로젝트 회귀 결과와 더하지 않는다. 같은 사례의 양 OS 실행은 독립 탐지 사례가 아니다.

로컬에 내려받은 기존 lock의 Prometheus/Alertmanager 릴리스 archive SHA256을 확인해 필요한 바이너리만 추출했다. Prometheus3.15.1·Alertmanager0.34.2를 사용했고 바이너리 지문도 raw 보고서에 남겼다. `promtool check rules`와 제어된 집계8시나리오의 rule unit test가 통과했다. 초기 용량 규칙2건은 기대 라벨에 `state`가 누락돼 실패했으며 기대값만 보완했다. 실제 탐지 라벨을 고친 것이 아니다.

`scripts/run_witness_alert_flow.py`의 실제 수집기 → 기존 인증 exporter → Prometheus → Alertmanager → 인증 loopback receiver 흐름은 **14조건·장애3회**를 통과했다.

| 실제 장애 | 확인한 상태 | 경보와 복구 |
|---|---|---|
| 수집 일시 정지·실제 시간 만료 | signed observation의 stale | 새 firing 이후 동일 fingerprint/starts_at의 resolved |
| 임시 서명키 파일 제거 | pending·cycle 실패 | 수집 실패 firing, 원래 키 복원 뒤 같은 pending 복구·resolved |
| 공개 상태 파일 손상 | status_success0 | 상태 불가 firing, 보관한 정확한 파일을 명시적으로 복원한 뒤 resolved |

각 회차는 새 이벤트 offset과 job을 제한해 과거 알림을 성공으로 세지 않았다. 장애 metric도 실제 query로 확인했다. 기본 exporter에는 witness가 없고 원본 감사 DB byte가 그대로이며 미확인 pending이 남지 않았다. 실험 프로세스·서버·임시 개인키/DB는 종료·정리했다. 최초 실행의 변수 개수 오타 실패도 숨기지 않고 원본으로 남겼다. 실제8시간 soak는 아니다.

```bash
promtool test rules infra/observability/witness-alerts.test.yaml
python -m scripts.run_witness_alert_flow --directory <새-결과-폴더> --tools-directory <검증한-로컬-바이너리-폴더>
```

원본과 소스 pin은 [manifest](infrastructure-results/extra-witness-monitor-20261120.json)에 있다. 이전 동결 재생에서 LLM F1 93.41%·재현율90.56%가 유지됐으며 이번 변경은 지표를 개선하거나 독립95% 목표를 달성한 작업이 아니다. 유료/API/AWS/Docker/push/CI/병합0. 다음은 수집기 확인 기록의 암호화 백업·복원과 외부 최소 기준 보존 검증이다.
