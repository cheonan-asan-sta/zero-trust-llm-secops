# JSONL 분석 응답의 디스크 보존 확인

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합 없음.

## 변경 내용

일반 JSONL은 메모리 이력에 새 분석이 남아 있어도 디스크가 이전 파일로 되돌아간 사실을 성공 응답 전에 확인하지 못했다. federation도 manifest의 이전 최소 prefix를 만족하는 구 writer 파일이면 새 분석의 손실을 구분하지 못했다. 두 API 사례에서 **수정 전2실패**를 재현했다.

`AuditStore.verify_saved`는 캐시가 아닌 해당 process writer의 파일을 새로 열어 검증한다. 동일한 bounded disk view에서 전체 hash chain·모델·검토 전이를 확인하고, 응답할 원래 행의 JSON 값이 정확히 존재하는지 확인한다. 뒤의 검토나 같은 event의 새 분석이 있어도 원래 행은 관측할 수 있게 reader에 observer를 추가했다. JSON wire 비교는 SQLite와 공통 함수이며 tuple/key 정상 변환과 bool/number 구분을 유지한다.

누락·잘림·변조·뒤쪽 손상·검증 도중 파일 변경·capacity 초과는 성공 응답을 거부한다. reader는 기존128MiB/10만 행/행2MiB 상한·regular file·symlink 거부·stat 안정성 검사를 유지하고, payload 검증 **후에도** 경로 상태를 재확인한다. 부분 검증에서 행을 찾았다고 즉시 성공하지 않는다. 모델 결과와 응답 schema는 바꾸지 않는다.

`FederatedAuditStore.verify_saved`는 먼저 기존 inventory/manifest와 shard 간 충돌을 검증하고, 다음으로 **자기 writer 파일의 원래 행**을 확인한다. 다른 shard의 같은 분석 복사본으로 자기 append 손실을 대신 인정하지 않는다. 다른 shard가 손상된 경우에도 자기 행만 보고 성공하지 않는다. 이것은 여러 파일에 걸친 원자적 snapshot은 아니다.

분석 성공 응답 전 공통 경계에서 이 함수를 호출하며 `settled_io`·분석 슬롯·store 동일성 확인·이후 실행 근거 재검증 순서를 유지한다. 일반 분석의 거부 응답은 기존502다. 이미 커밋된 정상 행을 제거하거나 캐시/파일을 자동 복구하지 않는다.

같은 store의 동기 append와 디스크 검증은 process 내부 `RLock`을 공유한다. 정상 배치의 자기 writer append 중 검증이 파일 변경으로 실패하지 않도록 완료를 기다린다. federation snapshot도 자기 writer에 대해 같은 lock을 사용한다. 이 lock은 다른 process/다른 shard까지 잠그는 분산 lock이 아니며 외부 파일 변경은 여전히 검출한다.

## 기존 파일 호환 범위

처음부터 있던 **무해시 legacy prefix**는 모델 형식을 검사해 기존 배포의 새 hash-chain append를 지원한다. legacy 행 자체는 보존 witness로 인정하지 않는다. hash 행이 시작된 뒤의 무해시 suffix는 거부한다. 이 경우 이력을 검토해 명시적 migration을 수행해야 하며 reader가 파일을 고치거나 버리지 않는다. legacy의 무결성을 새로 증명했다고 표시하지 않는다.

cursor paging은 기존의 **전체 hash-chain 필요** 조건을 그대로 유지한다. proof의 legacy prefix 호환을 paging 허용으로 확대하지 않았다. plain JSONL `integrity()`의 기존 캐시 상태 의미도 아직 바꾸지 않았다.

## 검증 근거

신규25건은 저장 후 row 제거2건, 캐시 없는 disk proof2건, 원래 행/검토/동일 event 최신 분석 공존2건, 파일 누락2건, 뒤쪽 손상2건, wire 정상화·타입 구분2건, 상한2건, 비교 중 파일 변경1건, legacy prefix/suffix2건, 타 shard 복사본 대체 거부1건, 타 shard 손상1건, 정상 ASGI2건, 실제 독립 HTTP process2건, 실제 own append 대기/완료 후 proof2건이다. 첫 확대 Linux 회귀에서 동시 batch1건이 파일 stat 변경으로 실패해 lock 경계를 추가했으며 기존 batch API도 재검증했다. 중간 실패는 결과 지문에 보존한다.

HTTP process 시험은 API key 인증을 거친 요청을 TCP로 보내고, JSONL/federated 각각 실제 작성 파일을 별도 reader로 열어 응답 analysis ID와 행을 검증한 뒤 소유 process를 kill/wait한다. provider는 stub이고 유료 호출은0이다. 초기 시험 stub이 일반 분석에 없는 native 근거를 인용해2건 거부됐으며, 요청의 실제 evidence catalog에 있는 근거를 선택하도록 시험 fixture를 수정했다. production grounding 검증을 변경하지 않았다. 시험 전용 진단은 오류 종류·함수/파일명/행번호만 기록하고 raw 요청/예외 내용/키를 기록하지 않는다.

최종 **Windows388건 통과·3건 제외, Linux389건 통과·2건 제외**다. 제외된 기존 platform/JSONL 전용 사례와 원래 실패 기록은 [묶음 시험·소스 지문](infrastructure-results/extra-jsonl-row-preservation-20261119.json) 및 원본 XML에서 확인한다. [최신 systemd 실제 인수](infrastructure-results/extra-jsonl-row-preservation-20261119-systemd.json)의54조건은 기존 SQLite native/worker/복원 경로의 최신 회귀이고, 새 JSONL HTTP2건은 별도 pytest 사례다. 서로 합쳐 다른 숫자의 systemd 인수로 표현하지 않는다. OS별 동일 사례도 합산하지 않는다.

```sh
python -m pytest tests/test_jsonl_row_preservation.py tests/test_http_worker_restart.py tests/test_analysis_row_preservation.py tests/test_federated_audit.py tests/test_audit_paging.py tests/test_api.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 남은 작업과 한계

plain JSONL의 preflight는 아직 캐시 integrity를 사용한다. 다음은 새 disk 검증을 모델 호출 전·실제 append 전의 writer head 일치 확인까지 연결해, 외부 rollback 후 오래된 캐시 head로 추가 쓰는 경우를 막는 작업이다. 이번 변경만으로 모든 변경을 모델 호출 전에 차단하거나 writer의 캐시를 복구했다고 주장하지 않는다.

JSONL 검증은 bounded file bytes와 최신 행 map을 메모리에 유지하며 SQLite compact scan과 같은 메모리 측정치를 적용하지 않는다. federation은 inventory scan 뒤 자기 writer를 다시 읽으므로 추가 I/O가 있다. SLA/RSS/처리량 측정은 별도다. 외부 변경 후 검사까지의 경쟁 조건, 독립 WORM/witness·최신 전체 상태·다중 호스트·실사용자 SSO·전원 단절·8시간 soak는 미완료다. DynamoDB 원격 검증과 새 F1·오탐/미탐 측정도 하지 않았다.
