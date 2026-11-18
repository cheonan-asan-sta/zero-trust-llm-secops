# JSONL 조회의 현재 디스크 근거와 JSON 값 비교

2026-11-19 · extra · 무료 로컬 검증. push·CI·병합·유료 API·AWS 없음.

## 캐시 조회의 빈 경계

기본 JSONL의 `get/recent/metrics`는 메모리에 적재한 행을 반환했다. API key·tenant·store 객체를 재확인해도 파일 삭제, 유효한 빈 과거 상태, 행 손상, 다른 writer의 예상하지 않은 append를 알지 못했다. 목록/상세/통계×4종 변경의12개 재현에서 변경 전 모두200이었다.

세 조회가 기존 bounded JSONL verifier와 process-local disk lock을 사용해 **현재 파일 전체 체인과 적재 당시의 정확한 writer prefix**를 확인하도록 바꿨다. 반환 객체도 검증한 디스크에서 새로 파싱한다. 따라서 cache의 Python 객체를 수정하거나 이전 조회의 반환 객체를 수정해도 다음 조회 결과에 영향을 주지 않는다. review·같은 event의 복수 분석에 대한 기존 순서·tenant 필터·통계 중복 제거는 유지한다.

변경/손상/읽기 실패는503이며 조각난 결과나 빈 통계로 숨기지 않는다. 기존 query slot·`settled_io`·현재 caller/store 전후 검증 안에서 실행한다. 취소 중에도 실제 읽기가 끝날 때까지 slot을 유지하며 liveness는 동작한다. 읽기 거부가 파일을 덮어쓰거나 자동 복구하지 않는다.

처음 시작해 아직 파일도 기록도 없는 상태는 정상 빈 조회다. **이미 알고 있던 파일을 잃은 상태와 다르다.** legacy raw prefix 읽기 호환은 유지하지만 그 raw 행을 해시 저장 증명으로 승격하지 않는다. process가 아는 prefix와 다른 외부 append도 거부한다. 다른 writer와 공동 쓰기를 하려면 SQLite/federated 모드를 사용해야 하며 plain JSONL이 동료 writer를 자동 채택하지 않는다.

## JSON 숫자와 불리언

직전 `543b3f7` Linux 전체 시험은8,388통과·1실패·4제외였다. 남은 compact 호환 시험은 검토하면서 중첩된 `true`를`1.0`으로 바꾸는 것을 허용하던 이전 계약이었다.

불변 core·review CAS·중복 이관에는 **typed JSON 값 비교**를 적용한다. 숫자`1`/`1.0`과 property 순서는 정상적으로 동등하지만 불리언`true`/숫자`1`은 다르다. 같은 JSON으로 직렬화되는 tuple/list·mapping key 변환도 유지한다. NaN/Infinity는 동등한 유효 JSON 숫자로 취급하지 않는다. 정확한 반환 행 증명과 strong ETag의 `analysis_wire`는 계속 직렬화된 표현을 엄격히 비교한다. 값의 동등성과 특정 응답 행의 증명은 별도 계약이다.

기존 compact positive fixture는 숫자/순서 호환만 검사하도록 정리했고, **기존의 동일한 중첩 불리언→숫자 입력을 별도 negative 사례로 남겨 저장 거부와 원본 보존을 확인**한다. 무결성 검증을 느슨하게 바꿔 전체 시험을 통과시키지 않는다.

## unit fixture와 읽기 실패 계약

기존 JSONL unit 시험에서 손상/uncertain fsync를 빈 조회나0건 통계로 기대하던 부분은 명시적인 무결성 예외로 바꿨다. 원본 바이트 보존·추가 append 거부 assert는 유지한다. 정상 검토 시험은 `NOT_REQUIRED → RESOLVED`라는 잘못된 입력 대신 검토가 필요한 PENDING 결과와 논리적으로 나중인 검토 시각을 사용한다. 운영 전이 규칙을 완화하지 않았고 모델 정답/평가 자료를 바꾸지 않았다.

## 검증과 남은 범위

신규24건은 JSONL source 변경12, 메모리 cache 변경3, 반환 객체 격리, 초기 빈 상태, legacy 호환/비증명, 오래된 분석의 후속 review, 알려진 prefix의 명시적 복원, 반복 취소 성공/실패2, 읽기 중 caller 철회, 중첩 불리언/숫자 거부다. [원본 XML·소스 지문](infrastructure-results/extra-jsonl-query-source-20261119.json)에 집중 시험과 직전 전체 결과를 기록한다. 최신 전체 Linux·Windows 확대·실제 systemd 인수는 이 변경을 저장한 뒤 다시 검증한다.

```sh
python -m pytest tests/test_jsonl_query_source.py tests/test_audit_review_wire_identity.py tests/test_compact_audit_integrity.py tests/test_audit_review_preconditions.py tests/test_analysis_row_preservation.py -q
```

JSONL은 계속 파일 크기/행 수 제한 안에서 전체를 읽는다. 대규모 반복 조회는 SQLite를 권장하며 성능이 공짜로 개선됐다고 주장하지 않는다. process 시작 전 전체 파일을 되돌리는 관리자, 외부 기업 SSO/online revocation, 독립 witness/WORM·다중 호스트·전원 단절·8시간 soak는 미완료다. 기존 합성360건 F1 93.41%와 native/독립 성능 목표도 갱신하거나 달성 처리하지 않았다.
