# 대시보드 검토: 조회한 버전과 호출 신원 연결

> 후속: audit cursor UI 소비는 [감사 페이지 후속](extra-dashboard-paging-20261119.md), 기존 워크벤치의 검토 버전·신원 연결은 [워크벤치 후속](extra-workbench-review-20261119.md)에서 완료했다. 아래의 app.js 미이전 표현과 수치는 당시 작업 범위다. CLI/다른 client의 서버 binding·기업 신원·독립 성능 인수는 계속 남아 있다.

2026-11-19, 로컬 `extra` 후속. app/server 구현 기준은 `bef9a97`, 브라우저 응답 fixture 후속 보강은 `bd1cb17`이다. 두 commit 사이 app/tests는 동일하다. GitHub push·CI·main/aitest 병합·AWS·유료 모델 API 호출은 하지 않았다.

## 바뀐 동작

기존 서버의 SQLite 검토는 ETag/If-Match를 지원했지만 대시보드가 그 값을 제출하지 않았다. 이제 `/`의 운영 대시보드는 **운영자가 조회한 분석·검토 상태와 그때의 호출 신원**을 확인 요청에 연결한다. 두 운영자가 같은 기록을 열어도 오래된 화면이 먼저 저장된 검토를 덮어쓰지 못한다.

| 상황 | 이전 대시보드 | 이번 동작 |
|---|---|---|
| 상세 조회 뒤 다른 사람이 검토 수정 | 조회한 버전을 제출하지 않음 | 상세 조회 당시 ETag를 보존. 준비 단계에서 최신 버전으로 몰래 교체하지 않고, 저장 시 서버가 오래된 요청을 412로 거부 |
| 작업 메뉴에서 이벤트 ID 직접 입력 | 확인 입력과 관측 버전 연결 없음 | 준비 단계에서 신원→결과→신원을 조회하고 분석·검토 상태를 확인 화면에 제시 |
| 조회/확인 후 계정 매핑 변경 | 화면에 표시된 신원과 새 요청의 주체가 달라질 수 있음 | 제출 직전 신원을 재조회. 그 조회 뒤 변경되는 경합도 서버의 caller binding으로 거부 |
| 메모·대상·연결 정보 변경 | 비동기 작업과 이전 확인 상태의 경합 가능 | 입력 revision·연결 epoch·화면 sequence로 확인을 폐기. 비동기 신원 확인 중 편집해도 이전 입력을 제출하지 않음 |
| 검토 저장 뒤 응답 유실 | 일반 처리 오류만 안내 | 저장 여부 불확실 안내·현재 이력 재조회 요구. 자동 재전송 없음 |
| JSONL 등 조건부 저장 미지원 | 조건 없는 검토 제출 가능 | 해당 대시보드의 검토 준비 거부. 헤더를 빼거나 backend를 우회해서 제출하지 않음 |

## 구현 연결

1. `app/static/dashboard.js`의 `readReviewObservation()`이 `/auth/me`와 결과 상세를 확인하고 결과의 event ID·tenant·analysis ID를 검사한다. 조회 전후 신원이 다르거나 연결이 바뀌면 폐기한다.
2. `GET /results/{event_id}`가 기존 strong `ETag` 외에 `X-Review-Identity`, `X-Review-Mode`를 반환한다. SQLite는 `conditional`, 다른 저장소는 `unavailable`이다. 인증 응답의 기존 `no-store` 정책도 유지한다.
3. `dashboard-operations.js`가 상세 화면의 observation을 검토 폼으로 전달한다. 확인 화면에 관측한 분석과 검토 상태·호출자를 표시한다. reviewer 입력은 읽기 전용이며 요청 body에서 제거한다.
4. 저장 전 현재 신원을 다시 검사한 뒤 **관측한 ETag 그대로** `If-Match`와 `X-Review-Identity`를 보낸다. 일반 요청 helper에 임의 헤더 전달 기능을 열지 않고 두 헤더만 허용한다.
5. 서버가 인증된 principal과 binding을 비교하고, 기존 현재 권한 재검증·SQLite 트랜잭션 CAS·저장 행 보존 검증을 수행한다. reviewer는 서버 principal에서 확정한다.

caller binding은 tenant·subject·auth method의 정규 JSON을 domain-separated SHA-256으로 표현한 값이다. **인증 토큰·서명·실제 사람이 읽었다는 증거가 아니다.** API key/OIDC 인증·역할·tenant 검사가 계속 권한의 기준이다. 동일 계정을 공유하는 두 사람을 별도 사람으로 식별하거나, OIDC issuer/계정 세대를 추가로 구분하는 기능은 아니다.

## 사용 및 복구 절차

SQLite와 개별 API key/OIDC 인증을 사용하는 서버에서 로그 탐색 → 상세 → 검토 상태 변경 → 상태·메모 입력 → 입력 검토 → 관측한 분석·신원·변경 내용 확인 → 체크 후 실행 순서다. 작업 메뉴에서 이벤트 ID를 직접 입력하는 경우에는 입력 검토 시점에 새 결과를 읽는다.

- 412/428: 다른 수정이나 새 분석으로 조회 버전이 유효하지 않다. 확인 패널은 사라진다. 새로 상세를 열거나 **명시적으로 다시 입력 검토**를 눌러 새 결과를 읽고 확인한다.
- 신원 변경/401/403: 연결·현재 계정·권한을 확인한 다음 다시 조회한다. 다른 호출자의 검토를 그대로 제출하지 않는다.
- 네트워크 오류/5xx: 이미 저장됐을 수 있다. 현재 결과와 감사 이력을 먼저 확인한다. 오류가 rollback을 의미하지 않는다.
- ETag·신원 헤더 누락/형식 오류 또는 미지원 backend: 준비를 중단한다. 조건 없는 PATCH fallback은 없다.

`AUDIT_BACKEND=sqlite`, `AUDIT_DB_PATH=...`, `AUDIT_REVIEW_REQUIRE_IF_MATCH=true`가 서버의 버전 필수 정책 조합이다. 기존 저장소를 자동 이관하거나 전역 기본값을 변경하지 않았다. 개별 운영 환경의 기존 이력은 별도 이관·검증이 필요하다.

**범위 주의:** 이번 변경은 `/`의 자체 대시보드다. `/static/workbench.html`의 기존 `app.js`는 이번에 이전하지 않았다. 기존 CLI도 그대로 호환되도록 `X-Review-Identity`는 서버에서 선택 헤더이고, strict 기본값은 false다. 따라서 모든 기존 client가 이 보호를 강제한다고 말하지 않는다. 서버 strict는 If-Match만 필수화하며 caller binding을 모든 client에 필수화하는 설정은 아니다. [기존 검토 CLI](extra-operator-review-client-20261119.md)도 별도 구현 범위를 가진다.

## 무료 로컬 검증

관련 pytest 묶음은 **Windows206통과·23제외, Linux229통과·제외0**다. 신규 서버 신원 검증16개를 포함한다. OS별 동일 사례는 합산하지 않는다. Windows 제외는 POSIX 파일/프로세스 및 호스트 작업 조건이며 Linux에서 실행했다. 새 저장소 전체 시험이나 실제8시간 soak 결과는 아니다.

실제 브라우저 검증은 합성 데이터·loopback HTTP·규칙 분석·격리 SQLite만 사용했다. 새 검토 경로, 기존 운영 폼, 읽기 전용 화면은 별도 실행으로 구분하며 수치는 [원본·지문·범위 JSON](infrastructure-results/extra-dashboard-review-20261119.json)을 따른다. 신규 검토는 동시 브라우저 CAS, 상세 조회 뒤 수정, 신원 재확인 직후 계정 변경, 잘못된 헤더, 입력 중 변경, 자격 증명 전환, 실제 commit 뒤 응답 유실을 다룬다. 데스크톱1440×1080·모바일390×844의 확인/충돌 화면을 직접 확인했고 가로 넘침을 검사했다. impeccable 기계 검사 결과는 빈 목록이며 새 외부 라이브러리나 시각 디자인 교체는 없다.

| 브라우저 묶음 | 통과 조건 | 범위 |
|---|---:|---|
| 신규 검토 | 27 | 실제 Chromium·Windows 앱, API key·SQLite strict·동시 검토·신원 경합·응답 유실 |
| 기존 운영 작업 Linux | 146 | 기존 모든 운영 폼, rule 분석·검토·대응 승인·세션 철회·실제 POSIX mock job |
| 기존 운영 작업 Windows | 143 | 지원되는 운영 폼·작업과 지원 불가 host job의 차단 확인. POSIX job 시나리오 제외 |
| 기존 조회 화면 | 57 | 기존 조회·상세·오류·내보내기·반응형·합성 접근 허용/회수 시연 |

[데스크톱 확인](infrastructure-results/dashboard-review-confirmation-desktop-20261119.png), [모바일 확인](infrastructure-results/dashboard-review-confirmation-mobile-20261119.png), [데스크톱 충돌](infrastructure-results/dashboard-review-stale-desktop-20261119.png), [모바일 충돌](infrastructure-results/dashboard-review-stale-mobile-20261119.png)을 함께 보존했다. 이 조건 수는 서로 독립된 모델 평가 사례 수가 아니며 합산 성능 지표로 쓰지 않는다.

최초 Linux 묶음은228통과·1실패였다. 실패는 실행 도중 시험 스크립트를 수정해 소스 지문 변경을 감지한 것이며 검사를 완화하지 않았다. 소스를 고정한 뒤229개를 모두 다시 실행했다. 원본 실패 XML과 최종 성공 XML을 함께 보존한다. Windows 브라우저 도구의 UTF-8 다운로드 읽기와 POSIX host job 제외 보고도 보완했다. 지원 불가 작업을 통과 사례로 바꾸지 않는다.

새 브라우저의 잘못된 응답 헤더 시험에서 intercept 내부의 반복 upstream fetch가 간헐적으로 멈추는 문제는 실제 API 본문을 먼저 읽고 응답 metadata만 바꿔 주입하는 fixture로 분리했다. 실제 저장·동시 검토·신원 변경·응답 유실은 계속 실제 로컬 API를 사용한다. 최종27조건을 통과했고, fixture 보강 후 소스 지문·신원 관련54건을 Windows/Linux에서 각각 재확인했다. 이54건은 기존229건과 겹치므로 추가 건수로 합산하지 않는다.

재현하려면 프로젝트 개발 의존성 외에 기존 Playwright/Chromium 시험 환경을 사용한다. 신규 브라우저 명령은 실행한 Python의 앱 의존성을 자식 서버에 전달하며 소유한 실제 interpreter를 종료·회수한다.

```powershell
python -m pytest tests/test_audit_review_identity.py tests/test_audit_review_preconditions.py tests/test_audit_review_wire_identity.py tests/test_audit_review_preservation.py tests/test_audit_query_admission.py tests/test_audit_auth_review.py tests/test_audit_review_client.py tests/test_audit_review_client_transport.py tests/test_audit_review_client_process.py tests/test_http_review_preconditions.py tests/test_sqlite_audit.py tests/test_api_key_accounts.py tests/test_dashboard_audit_catalog.py tests/test_dashboard_identity.py tests/test_dashboard_integration_boundaries.py tests/test_dashboard_operations.py -q --junitxml=runtime/dashboard-review.xml
python -m scripts.test_dashboard_review_browser --output-dir runtime/dashboard-review-browser
python -m scripts.test_dashboard_operations_browser --browser-channel chrome --output-dir runtime/dashboard-operations-browser
python -m scripts.test_dashboard_browser --browser-channel chrome --output-dir runtime/dashboard-readonly-browser
```

Chromium 설치 위치가 기본 경로와 다르면 신규 명령에 `--browser-executable`로 지정한다. 실제 경로·실행 소스·원본 SHA-256은 결과 JSON에 보존한다.

## 성능 지표와 남은 항목

모델·prompt·분류 규칙·평가 정답·예측 파일은 변경하지 않았다. 기존 실제 API 합성 개발360건은 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33% 그대로다. 이 작업은 검토의 무결성과 신원 연결 개선이며 탐지 수치 향상이나 독립95% 목표 달성을 새로 주장하지 않는다.

감사 cursor API의 대시보드 페이지 소비, legacy workbench/다른 client의 신원 binding 이전, 외부 기업 SSO/online revocation, 독립 witness/WORM, 다중 호스트·전원 단절·실제8시간 soak는 남아 있다. 이번 브라우저 검증은 실제 기업 SSO나 운영 TLS 배포 인수를 대신하지 않는다. 기존 CLI TLS/mTLS 검증도 관련 pytest에 포함했으나 대시보드 브라우저의 새 mTLS 시험은 아니다.
