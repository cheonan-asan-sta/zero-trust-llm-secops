# 서버에서 조회 버전·호출 신원을 필수로 검증하는 선택 정책

2026-11-19 · 로컬 `extra` · 구현 `d461b5f`. [CLI의 서버 신원 연결](extra-cli-review-binding-20261119.md) 다음으로, 검토 client가 헤더를 생략해 서버의 신원 연결 검사를 우회하지 못하도록 선택 설정을 추가했다. 기본값과 실제 운영 설정은 바꾸지 않았고 push·CI·병합·유료 모델·AWS·Docker 실행은 하지 않았다.

## 이전과 달라진 점

기존 서버는 `AUDIT_REVIEW_REQUIRE_IF_MATCH=true`일 때 버전만 필수로 요구했다. `X-Review-Identity`는 보내는 client에 대해서만 검사했으므로, 올바른 ETag를 알아도 조회 신원과 다른 계정으로 저장하는 것을 모든 client에 막는 정책은 없었다. 기존 호환 동작을 결함이나 새로운 인증 우회로 표현하지 않는다.

기준 `904bc21`에서 새 설정을 전달하는 회귀1건을 먼저 실행했다. 이전 Settings는 알지 못하는 설정을 무시했고, caller header 없는 요청이200으로 저장되어 기대428과 달랐다. 새 시험을 추가한 작업 디렉터리에서 실행한 결과이며 clean baseline 전체 평가가 아니다. 첫 계측 시도는 worker 안의 pytest 실패가 teardown 오류를 유발하여, 읽기 횟수를 기록하는 방식으로 수정했다. [초기 계측 원본](infrastructure-results/review-policy-before-instrumentation-20261119.xml)과 [수정한 baseline 원본](infrastructure-results/review-policy-before-20261119.xml)을 함께 보존한다.

현재는 `AUDIT_REVIEW_REQUIRE_IDENTITY=true`를 설정하면 검토 PATCH의 두 헤더가 필수다. 요청 입구와 마지막 권한 I/O 뒤 저장 요청 직전에 같은 정책을 검사한다. 정책이 해당 I/O 중 강화되더라도 없는 caller binding을 묵인하지 않는다. 실제 계정·역할·tenant·만료 재검사와 SQLite CAS는 기존 경로를 계속 사용한다.

## 설정과 호환성

```dotenv
AUTH_MODE=api_key
# 실제 credential 설정은 별도로 관리한다. 평문 키를 문서/명령행에 넣지 않는다.
AUDIT_BACKEND=sqlite
AUDIT_REVIEW_REQUIRE_IF_MATCH=true
AUDIT_REVIEW_REQUIRE_IDENTITY=true
```

OIDC를 사용할 때는 `AUTH_MODE=oidc`와 기존 issuer·audience·JWKS 설정을 사용한다. 실제 운영 설정을 위 예시로 자동 변경한 작업은 아니다.

| 설정 조합 | 의미 |
|---|---|
| 두 필수 설정 false | 기존 선택 헤더 호환 모드. 보낸 헤더는 여전히 검사 |
| If-Match true, identity false | SQLite에서 버전 필수. 신원 헤더는 선택 |
| 둘 다 true | SQLite와 API key/OIDC 인증 필요. 두 헤더 모두 필수 |
| identity true, If-Match false | 기동 시 설정 오류로 거부 |
| identity true, JSONL/DynamoDB 또는 인증 disabled | 기동 시 설정 오류로 거부 |

기본값은 둘 다 false다. 설정 예시는 [.env.example](../.env.example)에 반영했다. 테스트가 실행 중 설정 객체를 불완전하게 바꾸더라도 identity 필수 상태에서는 ETag까지 요구하며, 비트랜잭션 backend로 바뀌면 조건부 검토를503으로 거부한다. 익명 principal의 binding도 검토 권한을 만들지 못한다.

## 검증 계약

| 상황 | 동작 |
|---|---|
| 필수 모드에서 헤더 하나 또는 둘 다 없음 | 428, 감사 결과 조회/추가 전에 거부 |
| 잘못된 형식·중복 헤더 | 기존400 유지. 유효하지 않은 헤더를 누락으로 바꾸지 않음 |
| 현재 인증된 caller와 binding 불일치 | 403, 저장하지 않음 |
| 다른 tenant의 결과 | 유효한 자기 binding으로 조회해도404 |
| 키 철회·역할 부족 | 기존401/403. binding이 인증/권한을 대신하지 않음 |
| 현재 두 값 일치 | 서버 caller로 검토 저장, 새 ETag 반환 |
| 오래된 버전·같은 스냅샷 재전송 | 412, 기존 검토 보존 |
| commit 이후 전달 실패 | 이미 저장된 이력은 보존. 자동 재시도/이력 삭제 없음 |

이 상태 코드는 인증·본문 검증·query admission을 통과한 검토 경로 기준이다. 예를 들어 인증이 먼저 거절되거나 슬롯이 포화되면401/403/503이 먼저 반환될 수 있다. ETag는 조회한 표현, caller binding은 subject·tenant·auth method의 공개 digest다. 서명·인증 토큰·실제 사람이 읽었다는 증거나 공유 계정 내 사람 구분 수단이 아니다.

## client 목록과 적용 순서

| client | 현재 상태/적용 전 확인 |
|---|---|
| 자체 대시보드 `dashboard.js`/`dashboard-operations.js` | 조회한 ETag/caller binding 전송. 이번 필수 모드 실제 브라우저 인수 포함 |
| 기존 워크벤치 `app.js` | 같은 두 값 전송. 이번 필수 모드 실제 브라우저 인수 포함 |
| `scripts/audit_review_client.py` | snapshot v2 사용. 필수/선택 모드 각각 실제 CLI subprocess와 TCP 전달 검증 |
| `scripts/f1_lab/audit_recovery_controls.py`, `http_worker_controls.py` | 기존 격리 검증 harness의 legacy 요청 포함. 운영 필수 모드 writer로 승인한 것이 아님 |
| 기타 외부 client·이전 배포본 | 저장소 검색만으로 목록 완전성을 보장할 수 없음. 운영자가 별도 확인 |

1. 실제 검토 writer와 호출 경로를 목록화하고 둘 다 보내는지 확인한다. CLI v1은 새 prepare/확인이 필요하다.
2. 테스트 환경에서 SQLite·인증·두 설정으로 기동하고 누락428·불일치403·stale412·정상 저장을 확인한다.
3. 동일 감사 서비스를 제공하는 **모든 worker/인스턴스**에 같은 설정을 배포하고 재시작한다. 선택 모드 worker가 남으면 그 경로에서 요구가 강제되지 않는다.
4. 경보/접근 로그로 거절을 확인한다. 전체 client 이관 없이 켜면 기존 writer는428로 중단된다. 서버가 헤더를 대신 채우거나 client가 자동 우회하지 않는다.

실제 조직 배포·모든 외부 client 목록화·정책의 분산 원자적 전환은 이번에 수행하지 않았다. 운영상 호환 모드로 복귀해야 하면 명시적으로 설정을 변경하고 같은 범위의 worker를 재시작한다. 이때 기존 감사 이력을 삭제하거나 v2 스냅샷을 v1으로 변환하지 않는다. 런타임 설정 검사 자체가 모든 OS 스레드·DB 트랜잭션과 분산된 정책 변경을 원자화하는 것은 아니다.

## 무료 로컬 검증

최종 수치와 소스/원본 지문은 [검증 manifest](infrastructure-results/extra-server-review-policy-20261119.json)에 보존한다. 신규 서버 정책28건은 양쪽 모두 통과했다. OS별 중복 사례나 브라우저 조건을 합산해 독립 사례 수로 표시하지 않는다.

| 최종 실행 | 결과 | 범위 |
|---|---|---|
| Windows pytest | 250통과·3제외 | 같은253개 사례 중 POSIX 전용3개 제외 |
| Linux pytest | 253통과·제외0 | POSIX 계약·실제 별도 worker/CLI 포함 |
| 대시보드 브라우저 | 29조건 통과 | caller binding 필수 모드 |
| 워크벤치 브라우저 | 34조건 통과 | caller binding 필수 모드, 익명 시연 거부 포함 |

- 새 서버 정책 시험: 누락·형식/중복·정상/재전송·subject/tenant/권한/키 변경·I/O 중 정책 강화·backend/auth 변경·설정 검증·로컬 서명 OIDC를 다룬다.
- CLI subprocess/TCP 시험은 기존2건을 필수/선택 모드로 각각 실행하는4건으로 확장했다. 실제 인증/SQLite ASGI로 전달하는 HTTP bridge이며, 별도 앱 프로세스 시험과 구분한다.
- 기존 실제 Linux HTTP worker/CLI·TLS/mTLS6건·review CAS/행 보존·API·계정·release 입력 회귀도 함께 실행한다.
- 대시보드/워크벤치의 실제 브라우저 인수는 필수 모드로 별도 실행한다. 다른 운영자의 동시 저장도 그 사람의 신원으로 상세를 다시 읽은 뒤 두 헤더를 보내도록 시험 fixture를 수정했다. 제품 UI 소스는 변경하지 않았다.

Playwright를 사용할 수 있는 Python 환경에서 다음과 같이 재현한다. 이번 Windows 실행은 새 패키지 설치 없이 기존 `tmp/main-demo-video-tools`의 Playwright와 설치된 Chrome을 재사용했다.

```powershell
python -m pytest tests/test_audit_review_policy.py tests/test_audit_review_client_binding_process.py -q
python -m scripts.test_dashboard_review_browser --caller-bound-reviews --browser-executable "C:/Program Files/Google/Chrome/Application/chrome.exe" --output-dir runtime/review-policy-dashboard
python -m scripts.test_workbench_review_browser --caller-bound-reviews --browser-executable "C:/Program Files/Google/Chrome/Application/chrome.exe" --output-dir runtime/review-policy-workbench
```

소유 시험 서버·브라우저·CLI process는 종료/회수한다. 전체 저장소 회귀·새 운영 TLS 배포·기업 SSO·다중 호스트 장애·실제8시간 soak는 이번 인수에 포함하지 않는다.

## 탐지 지표와 후속

모델·프롬프트·규칙·평가 원본·정답·기존 예측은 변경하지 않았다. 기존 실제 API 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33%를 유지하며, 이번 보강을 새 탐지 평가나 독립95% 목표 달성으로 집계하지 않는다.

검토 필수화 선택 기능은 구현했지만 실제 조직의 client 이관/배포 인수는 남아 있다. 워크벤치의 감사 페이지/전체 자유 검색, 외부 기업 신원·독립 witness/WORM·최신 전체 회귀·장기 운영 인수도 후속이다.
