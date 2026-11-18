# 응답할 SQLite 분석 행의 실제 보존 확인

2026-11-19 · extra · 무료 로컬 개발. paid API/AWS/push/CI/병합 없음.

## 문제와 수정

최소 checkpoint 검증은 과거 기준보다 낮은 DB를 거부하지만, 기준 이후 방금 저장한 분석만 사라지는 경우까지 증명하지 않는다. 새 분석을 커밋한 뒤 checkpoint 자체는 만족하는 이전 DB로 되돌리는 시험에서 guarded/일반 SQLite 모두 성공 응답이 나갔다. **변경 전2실패**를 XML로 남겼다.

SQLite에 `verify_saved(expected)`를 추가하고 성공 응답 전 검증으로 연결했다. 현재 DB의 전체 체인·모델·검토 전이를 compact mode로 확인하는 **같은 read transaction**에서 응답할 `AnalysisResult`와 정확히 같은 행이 존재하는지 확인한다. 비교 기준은 실제 저장/응답의 JSON 계약이다. trace의 tuple→array·정수 mapping key→문자열 변환을 정상화하고, 정렬된 JSON 값으로 비교해 `true`와 숫자`1`은 구분한다. Python 모델/딕셔너리 동등성만 사용하지 않는다. analysis ID만 같거나 event/tenant/latency 등이 다른 행은 인정하지 않는다. 일치하는 행을 발견해도 즉시 반환하지 않고 뒤의 전체 체인과 durable head까지 검증한다. guard를 선택한 store는 기존 checkpoint 전후 검증도 함께 적용된다.

마지막 event 조회만 비교하지 않는다. 같은 event의 더 새 분석이나 이후 검토가 있어도 원래 행이 보존됐다면 정상이다. 따라서 정상 동시 분석·검토 때문에 과거의 유효한 응답을 거부하지 않는다. 행이 없거나 전체 검증이 실패하면 성공 응답을 주지 않고 기존 일반 `/analysis` 계약의502로 끝난다. 추가된 다른 정상 이력이나 이미 커밋한 이력을 자동 삭제하지 않는다.

이 검사는 직전 단계의 성공 응답 전 전체 scan을 **대체**한다. 전체 scan을 한 번 더 추가한 것이 아니다. 한 행 일치 여부만 추가로 유지하고 기존 compact 검증의 행 위치 map을 사용한다. I/O는 `settled_io`와 원래 분석 슬롯 안에서 완료/실패까지 기다린다. 검증 전후 serving store 동일성, 이어지는 실행 근거 재검증 순서도 유지한다.

## 시험과 자료

신규13건: guarded/일반 DB의 checkpoint 이상 구 DB로 신규행 제거2건, 동일 event 최신 분석과 공존1건, 이후 검토와 원래 행 공존1건, event/tenant/latency/ID 불일치4건, 일치 행 뒤 손상 거부1건, 검증 중 checkpoint 철회1건, 보존 확인 중 store 교체와 이미 커밋한 이력 유지1건, trace JSON 정상 변환1건, boolean/number 구분1건이다. 기존 scan 취소·source 순서 시험은 새 성공 경로의 `verify_saved` 경계에서 같은 계약을 확인하도록 갱신했다.

첫 확대 회귀에서 SDK trace의 tuple/array 차이로 Windows/Linux에서 각1건 오거부를 발견해 JSON 정상화로 수정했다. 별도 타입 비교 시험은 수정 전1실패를 재현한 뒤 strict JSON 비교로 해결했다. 이 실패를 숨기거나 탐지 오탐/F1 표본에 합산하지 않는다.

최신 관련 묶음은 **Windows289건 통과·3건 제외, Linux290건 통과·2건 제외**다. 제외는 기존 POSIX 권한(Windows1)과 JSONL 전용 page2건이다. OS 중복을 합산하지 않는다. 원래2실패 XML·JSON 타입1실패·확대 회귀 중간 실패와 수정 후 소스 지문은 [기계 판독 결과](infrastructure-results/extra-analysis-row-preservation-20261119.json)에 기록한다. [실제 systemd54조건 인수](infrastructure-results/extra-analysis-row-preservation-20261119-systemd.json)는 새 SQLite 성공 경로로 native 분석·독립 HTTP worker kill/restart·감사 백업/복원을 재실행한 결과다. 신규 행 제거 fault는 로컬 ASGI 시험이고 실제 전원 단절이나 원격 DB rollback 시험으로 설명하지 않는다.

```sh
python -m pytest tests/test_analysis_row_preservation.py tests/test_analysis_audit_binding.py tests/test_runtime_audit_checkpoint.py tests/test_sqlite_audit.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 남은 범위

현재 새 보존 확인은 **SQLite 분석 응답**에 적용한다. JSONL/federated JSONL의 정확한 행 보존 확인은 다음 작업이고, DynamoDB의 원격 일관성 검증도 이번 무료 로컬 범위에서 수행하지 않았다. 모든 backend가 같은 수준으로 완료됐다고 주장하지 않는다.

확인하는 것은 관측한 SQLite snapshot에 그 행이 있다는 사실이다. 검사 후의 외부 변경을 영구 차단하거나 DB·checkpoint·source의 원자적 공동 시점을 제공하지 않는다. 동일 내용을 재작성한 특권 관리자의 행위를 원격 attestation으로 구분하지 않으며, 독립 WORM/witness·최신 상태 전체 증명·다중 호스트·8시간 soak는 미완료다. 모델 판정·평가 원본/정답·F1·오탐/미탐 수치는 변경/재측정하지 않았다.
