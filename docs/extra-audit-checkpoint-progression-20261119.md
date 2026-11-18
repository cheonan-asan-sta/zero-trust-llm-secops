# Checkpoint 단조 갱신과 운영 상태 비교

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 기준을 낮추지 않는 갱신

새 `checkpoint-advance`는 이전 checkpoint 파일과 그 외부 pin을 필수로 받는다. 기존 `checkpoint`는 초기 baseline 수집이고 단조 증가를 검증했다고 표시하지 않는다. 갱신 명령에서 이전 기준이 빠지면 baseline으로 우회하지 않고 exit2다.

```sh
python -m scripts.audit_storage checkpoint-advance --database <현재_DB> --destination <새_checkpoint.json> --previous-checkpoint <이전_checkpoint.json> --previous-checkpoint-sha256 <기록한_이전pin>
```

이전 파일의 외부 pin/형식을 확인한 뒤, 현재 DB를 검증하는 **동일 read transaction**에서 이전 seq/digest가 그대로 포함됐는지 확인한다. 더 오래된 정상 DB나 동일/더 높은 seq의 다른 정상 체인으로는 갱신 파일을 게시하지 않는다. 동일 head의 재수집은 허용하되 `advanced_rows=0`이다. 현재 DB·이전 파일은 변경하지 않고 새 파일만 게시한다.

반환 `progression_check`에는 이전 file pin/head·history 존재 여부·단조 head 확인 여부·증가 행 수가 들어간다. checkpoint 파일 형식은 v1 그대로이고 이 관계 정보는 명령 receipt다. receipt를 기록했다고 원격 실행 attestation이나 별도 저장소 보관이 증명되는 것은 아니다. 비어 있는 이전 head0은 모든 체인의 공통 prefix이므로 `previous_checkpoint_has_history=false`를 표시한다.

## 읽기 전용 비교

```sh
python -m scripts.audit_storage checkpoint-status --database <검사할_DB> --checkpoint <기준_checkpoint.json> --checkpoint-sha256 <기록한_pin>
```

| status | 의미 | exit |
|---|---|---:|
| `at_checkpoint` | 기준 head와 같고 같은 이력 | 0 |
| `checkpoint_lagging` | 같은 이력이고 DB에 추가 행이 있음; checkpoint 갱신 권장 | 0 |
| `behind_checkpoint` | DB가 기준 seq보다 낮음 | 3 |
| `history_conflict` | 기준 위치의 digest가 다름 | 3 |

unsafe 비교도 먼저 JSON 결과를 출력해 모니터가 읽을 수 있게 한다. 무결성/입력 실패는 기존 exit1, 잘못된 인자는 exit2다. 외부 알림을 전송하거나 DB를 복원/활성화하지 않는다.

결과는 관측한 head, 기준 head, seq 차이, minimum 충족, 갱신 권장, source locator 일치 여부를 포함한다. 일치하지 않는 chain에는 `uncheckpointed_rows=null`로 표시해 단순 seq 증가를 정상 진행이라고 해석하지 않는다. 다른 경로로 이동한 정상 복원 후보는 같은 prefix이면 허용하고 locator 차이만 알린다. 경로 hash는 인증 신원이나 data lineage 증명이 아니다.

## 신뢰 범위

검증하는 기준은 운영자가 선택해 pin을 제공한 **그 이전 checkpoint**다. 프로그램이 저장소 전체에서 가장 최신 신뢰 기준을 찾아 선택하는 것은 아니다. current/previous 모두의 파일과 pin을 공격자가 함께 되돌리거나 바꿀 수 있는 경우의 독립 rollback 방지는 미완료다. timestamp로 최신성을 판단하지 않고 `latest_live_state_verified=false`, `independent_storage_verified=false`를 유지한다. 비교 직후에도 DB가 추가될 수 있으므로 결과는 관측한 read snapshot이다.

## 검증

신규16개 사례로 정상 증가/동일 head·정상 구 DB/다른 체인의 갱신 거부·부분 reference의 DB 접근 전 거부·네 status·이동한 clone·baseline/빈 head의 과장 없는 출력·CLI exit0/2/3·이전 파일 변조를 확인했다. 모든 거부에서 출력 파일을 만들지 않고 source/이전 checkpoint를 보존한다.

**Windows 관련147건 통과·1건 제외, Linux 확대231건 통과·2건 제외**. Windows 제외는 기존 POSIX 권한 계약, Linux 제외는 기존 JSONL 전용 page 사례다. OS별 중복 사례를 합산하지 않는다.

실제 systemd/ptrace·공유 참조·HTTP worker 재기동·감사 백업/복원에 새2조건을 더해 **51조건 통과**. 복원 후보 head1을 baseline으로 보관하고 HTTP 검토 후 head2로 검증 갱신했다. 유효한 head1 원본 DB로 head2 기준을 낮추는 시도는 게시 전에 거부하고 status도 `behind_checkpoint`였다. 이 후보 비교를 live 전체 시스템 최신 상태의 증명으로 표현하지 않는다. 원래 권한/실행 이력·감사 DB 보존, 시험 소유 process/unit/private 상태/임시 의존성 정리를 확인했다.

[결과·XML/소스 지문](infrastructure-results/extra-audit-checkpoint-progression-20261119.json), [실제 systemd run](infrastructure-results/extra-audit-checkpoint-progression-20261119-systemd.json).

```sh
python -m pytest tests/test_audit_checkpoint_progression.py tests/test_audit_checkpoint.py tests/test_audit_transfer.py tests/test_native_analysis_http.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

다음은 선택적으로 설정한 checkpoint를 실행 중인 감사 저장소의 무결성/읽기/쓰기에 연결하는 guard다. 아직 이 명령이 앱 설정을 바꾸거나 자동으로 최신 pin을 승격하지 않는다. 원격 WORM·독립 보관·전원 단절/다중 호스트·연기한8시간 시험은 미완료다. 모델·판정·평가 원본·정답·예측·F1·오탐/미탐을 변경하지 않았다.
