# 중단된 witness 작업의 정확한 재개

2026-11-20 · `extra` · [오전8시까지 지속 목표](extra-until-0800-20261120.md)의 첫 보강. 기존 로컬 witness는 서명을 저장한 직후 호출자가 종료되면 성공 여부를 모른 채 재시도할 수 없었다. 주기 수집기를 만들기 전에 이 경계를 보강했다. 실제 독립 호스트/권한이나 운영 인수를 완료한 것은 아니다.

## 작업 ID가 있는 명시적 복구

`observe(..., expected_receipt=..., observation_id=<소문자32자리hex>)`는 서명 본문에 작업 ID를 포함하는 v2 영수증을 만든다. 같은 ID가 **현재 마지막 영수증**에 있고 그 영수증의 이전 digest가 요청한 기준과 정확히 같을 때만 원래 서명·본문·관측 시각·digest를 돌려준다. 새 서명·시간 갱신·추가 journal 행은 없다. 다른 작업이 그 사이에 들어갔거나 이전 기준을 바꾸면 거부한다. ID는 인증 토큰이나 신원 증명이 아니다.

복구 요청도 현재 감사 DB가 서명된 최소 이력을 실제 포함하는지 확인한다. DB가 과거로 돌아가면 같은 ID라고 허용하지 않는다. 현재 DB에 새 행이 추가돼 있어도 재개 응답은 원래 작업의 과거 관측일 뿐이며 새 행을 증명하지 않는다. 이후 새 수집 주기에서 새로운 작업 ID와 정확한 다음 기준으로 관측해야 한다.

ID를 주지 않는 기존 수동 호출은 v1·정확한 현재 head 요구를 유지한다. 기본 동작을 자동 재시도로 바꾸지 않았다. v1/v2는 각각 다른 서명 domain prefix와 정확한 필드 집합을 사용하고, v2에서 ID 누락·다른 schema로의 바꾸기·ID 교체는 거부한다. v2의 관측 시각이 이전 영수증보다 뒤로 가면 새 서명 전에 거부한다. v1의 기존 과거 시각 계약을 소급 변경하지 않는다.

현재 reader는 혼합 이력을 검증하지만 예전 v1 전용 reader는 v2를 거부한다. 자동 수집을 연결하기 전에 읽는 쪽도 같은 버전으로 배포해야 하며, 필드를 버려 v1으로 강제 변환하거나 다른 pin으로 자동 재연결하지 않는다. 실제 운영 배포는 이번에 하지 않았다.

```powershell
python -m scripts.audit_witness observe --state-dir <로컬-witness> --database <audit.sqlite3> --public-key-sha256 <고정한-public-pin> --expected-receipt <관측-직전-receipt-pin> --observation-id <한-작업에-고정한-32자리hex>
```

호출자가 이 명령의 응답을 잃으면 같은 세 인자와 작업 ID를 보존한 상태로 재개한다. 서버가 돌려준 미확인 최신 head를 기준으로 자동 교체하는 복구가 아니다. 개인키와 외부 pin의 실제 보호는 여전히 별도 운영 절차다.

## 무료 로컬 검증

Windows80통과·2제외, Linux82통과·제외0. 기존 witness/checkpoint/progression과 신규 작업 검증을 묶었다. 새 작업 계약15건은 양쪽에서 통과했고, 기존 POSIX 권한2건은 Windows에서 제외된다. 별도 CLI 프로세스 두 번으로 첫 응답 유실 후 같은 서명/시각/파일 바이트가 유지되는지 확인했다. 동시에4회 같은 작업을 요청해도 새 서명은1회다.

ID 형식7종·잘못된 이전 기준·다른 writer·ID 재사용·schema/필드 변조·DB rollback·clock rollback·가득 찬 저장소에서의 재개를 검증했다. 저장소가 가득 차도 이미 커밋한 작업의 복구는 가능하지만 새 영수증 발급이나 오래된 이력 삭제는 하지 않는다. 잘못된 기준을 새로 발급해 맞추지 않는다.

원본·소스 지문은 [manifest](infrastructure-results/extra-witness-operations-20261120.json)를 따른다. 전체 저장소를 새로 재실행한 결과로 표시하지 않는다. 다음은 별도 로컬 확인 기록에 pending ID/이전 pin을 커밋한 뒤 관측하고, 이 복구 경로로 중단을 이어가는 수집기다. 수집 주기·신선도·경보 연결은 아직 미완료다.

```powershell
python -m pytest tests/test_audit_witness.py tests/test_audit_witness_operations.py tests/test_audit_checkpoint.py tests/test_audit_checkpoint_progression.py -q
```

새 유료/API/AWS/Docker/업로드/CI/병합0이다. 모델·정답·임계값·기존 예측을 바꾸지 않았다. 기존360건의 무료 동결 재생에서 원래 LLM F1 93.41%와 기존 규칙/혼합78.26%/78.09%가 유지됐으며 개선 후보를 채택하지 않았다. 이15개 기능 사례를 탐지 평가나 독립95% 인수에 합산하지 않는다.
