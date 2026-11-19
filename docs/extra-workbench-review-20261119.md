# 기존 워크벤치 검토의 조회 버전·호출 신원 연결

> 후속: [CLI 서버 호출 신원 연결](extra-cli-review-binding-20261119.md)도 완료했다. 아래 CLI 미완료 표현과 시험 수치는 워크벤치 작업 당시 기록이다. [서버 필수화 선택 정책](extra-server-review-policy-20261119.md)도 추가했다. 실제 조직 client 이관/전체 worker 배포·워크벤치 페이지·기업 신원·독립 성능 인수는 남아 있다.

2026-11-19 · 로컬 `extra`. 구현은 `6c0100f`, 검토 영역의 대비·글자 보강은 `1b8233d`다. 서버·모델 코드는 변경하지 않았다. 유료 모델 API·AWS·Docker 자원 생성·GitHub push·CI·main/aitest 병합은 하지 않았다.

## 이전과 달라진 점

기존 `/static/workbench.html`은 목록에서 받은 결과를 그대로 표시하고 담당자 이름을 직접 입력해 조건 없는 PATCH로 검토를 저장했다. 이제 [자체 대시보드의 검토 보호](extra-dashboard-review-20261119.md)와 같은 서버 계약을 소비한다.

| 상황 | 기존 | 현재 |
|---|---|---|
| 호출자 연결 | 인증 입력 없이 요청, 검토자 이름 직접 입력 | API 키/OIDC Bearer 입력을 현재 화면 메모리에서만 사용. `/auth/me`의 subject·tenant·auth method 확인 |
| 목록에서 열기 | 최근8건의 캐시된 객체를 표시 | 해당 이벤트의 상세와 전후 신원을 다시 조회하고 그 결과를 표시 |
| 분석 직후 검토 | 분석 POST 응답에서 바로 검토 가능 | 결과 상세를 별도로 읽어 ETag·caller binding 확보 후 검토 가능 |
| 검토자 | 사용자가 입력한 이름 | 현재 조회 신원의 읽기 전용 표시. PATCH body에는 reviewer를 넣지 않음 |
| 저장 | 상태 버튼을 누르면 즉시 조건 없는 저장 | 상태 선택 → 관측한 분석·신원·상태·메모 확인 → 체크 → 저장. 관측한 `If-Match`와 `X-Review-Identity` 전송 |
| 다른 검토자의 선행 저장 | 오래된 화면이 최신 검토를 덮어쓸 수 있음 | 기존 SQLite CAS와 서버412로 거부. 새 버전 자동 조회 후 덮어쓰기 없음 |
| 입력·대상·연결 변경 | 이전 작업과 새 화면이 겹칠 수 있음 | revision·result sequence·connection epoch로 이전 확인 폐기. 연결 변경 시 이전 화면·세션 토큰·진행 요청 초기화 |
| 응답 유실 | 일반 저장 실패로 표시 | 저장 여부가 불확실하다고 안내하고 현재 기록 재조회 요구. 자동 재전송 없음 |

## 검토 흐름

1. 연결 및 인증에서 개별 자격 증명을 적용한다. 서버가 확인한 subject·tenant·역할을 표시한다. 입력창은 즉시 비우고 localStorage/sessionStorage·URL에 자격 증명을 저장하지 않는다.
2. 최근 분석 기록에서 열기를 누른다. `/auth/me` → `GET /results/{event_id}` → `/auth/me`를 읽고 연결 신원·tenant·event ID·analysis ID를 확인한다. 목록 배열은 검토 버전으로 쓰지 않는다.
3. 담당자 입력은 읽기 전용이다. 원하는 검토 상태와 메모를 선택하면 **조회 당시의 버전**과 호출 신원을 대상으로 확인 패널을 만든다. 이때 최신 결과를 새로 읽어 관측 버전을 바꾸지 않는다.
4. 확인 체크 후 저장하기 직전에도 현재 `/auth/me`와 responder 권한을 다시 확인한다. 그 확인 이후 같은 키의 subject가 바뀌는 경합은 서버의 caller binding 검사가 거부한다.
5. PATCH 성공의 대상·analysis ID·tenant·reviewer·상태·메모·새 ETag·caller binding을 확인한다. 성공 후에도 추가 검토는 현재 결과를 다시 조회해야 한다.

메모 수정·다른 결과 열기·연결 정보 수정은 확인 패널을 폐기한다. 비동기 신원 확인 중 내용을 바꾼 경우 이전 입력을 보내지 않는다. 다른 결과를 여는 동안 도착한 이전 준비 결과도 새 화면에 확인 패널을 띄우지 않는다.

## 연결 변경과 기존 기능

워크벤치 request helper는 같은 origin의 API만 사용하며 명시적 인증 헤더·`no-store`·redirect 거부·요청 시간 제한을 적용한다. 기존 모의 문서 접근도 이 helper를 사용해 현재 인증으로 요청한다. 일반 요청은12초, 기존 평가/공개 재생의 명시적 긴 요청은120초 한도다.

인증 적용/해제 시 epoch를 바꾸고 진행 요청을 abort한다. 원래의 빈 DOM을 복제해 이전 연결의 분석·평가·케이스·세션 표시와 입력을 제거하고 이벤트 핸들러를 다시 연결한다. 기존 시연용 세션 ID·허용 토큰도 메모리에서 비운다. 여러 단계의 분석·케이스·세션 요청에는 연결 변경 검사를 넣어 이전 작업을 새 자격 증명으로 이어 보내지 않게 했다.

이미 서버가 접수·커밋한 요청을 인증 변경이 취소하거나 되돌리는 것은 아니다. 응답 전달과 저장 이력의 보존은 기존 서버 경계를 따른다. 검토 외 다른 워크벤치 작업 모두에 새로운 서버 측 intent binding을 추가한 것은 아니다.

인증 비활성 로컬 시연은 계속 조회할 수 있다. 다만 개별 신원을 확인할 수 없거나 JSONL 등 조건부 검토를 지원하지 않는 경우 검토 저장을 허용하지 않는다. 기존 이름 직접 입력 방식으로 되돌아가지 않는다.

## 오류와 복구

| 결과 | 동작 |
|---|---|
| 412/428 | 조회한 버전이 변경됐다고 안내. 현재 결과 다시 조회 → 새 내용 확인 → 새 검토 준비 |
| 401/403·신원/역할 변경 | 확인과 observation 폐기, 현재 연결/권한 확인 요구 |
| ETag·신원 헤더 누락/약한 ETag·미지원 mode | 저장 버튼 비활성화. 조건 없는 PATCH fallback 없음 |
| 네트워크/5xx·성공 응답 불일치 | 이미 저장됐을 수 있음을 안내. 현재 기록을 확인하기 전 재전송하지 않음 |
| 상세 조회 실패 | 새 검토 버전을 만들지 않음. 기존 결과 표시가 남더라도 검토는 차단 |

서버의 `AUDIT_REVIEW_REQUIRE_IF_MATCH` 기본값은 false 그대로이며 `X-Review-Identity`도 서버에서 선택 헤더다. 워크벤치와 자체 대시보드는 두 헤더를 항상 요구하지만, 모든 API client에 이 정책이 강제되는 것은 아니다. CLI/다른 client의 서버 caller binding 소비와 전역 필수화는 별도 후속이다. 기본 JSONL을 SQLite로 자동 이관하거나 운영 설정을 변경하지 않았다.

## 무료 로컬 검증

신규 실제 Chromium 검증은32조건이다. 격리 SQLite·합성 API 키 계정·규칙 분석을 사용했고, 별도 인증 없는 JSONL 시연 서버도 실행했다. 두 소유 서버를 종료·회수한다. 검증 범위는 다음과 같다.

- 실제 GET의 ETag·caller binding을 PATCH에 정확히 전달하고 body의 reviewer 제거.
- 목록 캐시와 현재 상세 구분, 상세 조회 뒤 다른 검토 수정에 stale412, 명시적 재조회 복구.
- 두 워크벤치의 경합에서 먼저 커밋한 검토 보존.
- 확인 후 메모 수정, 최종 신원 확인 중 편집, 준비 도중 다른 결과 선택.
- 같은 키의 subject 변경, 브라우저 확인 직후 서버 계정 변경, viewer의 검토 차단.
- 누락/약한 ETag·누락 신원·미지원 backend에서 조건 없는 요청을 보내지 않음.
- 실제 commit 뒤 응답 유실, 이력 보존·자동 재전송 없음·다시 조회한 후 수동 검토.
- 연결 변경 시 확인/결과 초기화, 이전 tenant의 늦은 상세 응답 폐기, 이전 분석을 새 자격 증명으로 이어 보내지 않음.
- 실제 규칙 분석 직후 검토 observation 획득, 인증된 세션 회수 후 같은 미사용 허용의 실제403 거부.
- 인증 없는 기존 시연 조회, 자격 증명 입력창 비우기·브라우저 저장소 미사용, 외부 요청/JavaScript 오류 없음.

이는 탐지 모델의32개 독립 평가 사례나 기업 운영 인수 결과가 아니다. API 키를 사용한 브라우저 성공 시험과 기존 서버의 JWT/OIDC 회귀를 구분한다. OIDC 입력은 서버에 해당 인증원이 설정돼 있어야 하며 새 기업 SSO·MFA·online revocation을 배포한 것이 아니다.

OS별 pytest·기존 대시보드 검토 회귀와 raw XML·보고서·소스 지문은 [검증 원본 JSON](infrastructure-results/extra-workbench-review-20261119.json)을 따른다. 기존 테스트를 두 OS에서 반복한 수를 합산하지 않는다. 새 저장소 전체 시험이나 실제8시간 soak를 실행한 것은 아니다.

| 검증 | 최종 결과 | 범위 |
|---|---|---|
| Windows pytest | 191통과·POSIX3제외 | API/정적 파일·현재 검토/신원·CLI/TLS·release 입력 회귀 |
| Linux pytest | 194통과·제외0 | 같은194개 사례, 실제 별도 worker/CLI 프로세스 포함 |
| 신규 워크벤치 브라우저 | 32조건 통과 | 실제 Chromium·격리 API key/SQLite 서버와 인증 없는 JSONL 시연 서버 |
| 기존 대시보드 검토 | 27조건 통과 | 기존 화면의 버전/신원/응답 유실 보호 유지 |

[데스크톱 확인](infrastructure-results/workbench-confirmation-desktop-20261119.png), [모바일 확인](infrastructure-results/workbench-confirmation-mobile-20261119.png), [모바일 연결 입력](infrastructure-results/workbench-connection-mobile-20261119.png), [충돌 후 재조회 안내](infrastructure-results/workbench-stale-20261119.png)를 보존했다. 새 backend 단위 테스트를 추가한 작업은 아니며 기존 서버 계약을 실제 브라우저로 소비하고 회귀를 재확인한 작업이다.

확인 화면과 연결 입력을 desktop1440×1080·mobile390×844에서 직접 보고 가로 넘침을 검사했다. 검토 조작부의 글자와 대비를 보강했다. 공통 워크벤치의 작은 글자·기존 장식·대비 등 기계 검사 경고는 남았으며 전체 접근성 검사를 통과했다고 표현하지 않는다. 기계 검사 원본은 대비 보강 전 `6c0100f` 시점이고, 최종 브라우저는 `1b8233d`를 검증했다.

초기 검증의 문구 기대값 오류는 기존 “허용 회수” 표현에 맞춰 수정했다. 지연 응답 시험도 연결 적용 전까지 요청을 실제로 붙잡도록 보완했다. 이 과정의 실패를 성공 조건 수로 합산하거나 서버의 실패를 허용하도록 기준을 낮추지 않았다.

## 재현

프로젝트 개발 Python과 기존 별도 Playwright/Chromium 시험 환경에서 실행한다. fixture는 실제 키 파일을 읽지 않고 공개된 합성 placeholder만 사용한다.

```powershell
python -m scripts.test_workbench_review_browser --output-dir runtime/workbench-review-browser
python -m scripts.test_dashboard_review_browser --output-dir runtime/dashboard-review-browser
python -m pytest tests/test_api.py tests/test_audit_review_identity.py tests/test_audit_review_preconditions.py tests/test_audit_review_wire_identity.py tests/test_audit_review_preservation.py tests/test_audit_query_admission.py tests/test_audit_review_client.py tests/test_audit_review_client_transport.py tests/test_audit_review_client_process.py tests/test_http_review_preconditions.py tests/test_api_key_accounts.py tests/test_runtime_release.py -q --junitxml=runtime/workbench-review.xml
```

Chromium 설치가 기본 위치와 다르면 `--browser-executable`로 지정한다. 유료 API 호출 없이 재현하는 명령이며 실제 운영 계정의 권한 변경이나 AWS 배포를 수행하지 않는다.

## 성능 지표와 남은 작업

서버의 판정 로직·모델·프롬프트·평가 원본·정답·기존 예측은 변경하지 않았다. 기존 실제 API 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33%는 유지한다. 이번 작업으로 독립95% 목표 달성이나 탐지 성능 개선을 새로 주장하지 않는다.

자체 대시보드와 기존 워크벤치의 검토 소비는 연결됐다. CLI/다른 client의 서버 caller binding 이전, 전체 범위 자유 검색, 외부 기업 신원 인수, 독립 witness/WORM, 다중 호스트/전원 단절·긴 운영 인수와 최신 전체 회귀는 계속 남아 있다. caller binding은 subject·tenant·auth method에 대한 의도 연결이며 실제 사람이 읽었다는 증거나 공유 계정 사용자를 구분하는 수단이 아니다.
