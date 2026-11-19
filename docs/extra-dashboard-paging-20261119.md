# 대시보드의 검증된 감사 페이지 조회

> 후속: [기존 워크벤치의 감사 페이지 탐색](extra-workbench-paging-20261119.md)을 완료했다. 아래 워크벤치 페이지 미완료 표현과 수치는 당시 기록이다. 전체 자유 검색·다른 목록 이전·실제 조직 배포/독립 성능 인수는 남아 있다.

> 후속: 아래에서 남긴 기존 워크벤치의 검토 신원 binding 이전은 [워크벤치 후속](extra-workbench-review-20261119.md)에서 완료했다. [CLI 서버 binding](extra-cli-review-binding-20261119.md)도 후속으로 완료했다. 워크벤치 페이지 탐색 이전·전체 자유 검색·[서버 필수화 선택 정책](extra-server-review-policy-20261119.md)은 추가했고 실제 client 이관/모든 worker 배포는 남아 있으며, 아래 수치는 감사 페이지 연결 시점이다.

2026-11-19 · 로컬 `extra`. app/server 기준 `57b1590`, 브라우저 지연 fixture 후속 `72610d0`이며 두 commit 사이 app/tests는 동일하다. 유료 API·AWS·Docker 자원 생성·push·CI·main/aitest 병합은 하지 않았다.

## 해결한 문제

기존 로그 탐색은 `/results?limit=100`에서 최근100건을 받아 브라우저에서12개씩 나눴다. 그보다 오래된 기록은 검색·필터 대상으로 들어오지 않았다. 이제 로그 탐색은 `/audit/results?limit=12`의 검증된 감사 snapshot을 다음·이전 커서로 탐색한다.

| 항목 | 기존 | 현재 |
|---|---|---|
| 조회 범위 | 최근100건 안에서만 화면 분할 | 같은 tenant의 전체 조건 일치 결과를 서버에서12건씩 반환 |
| 위험도·검토 필터 | 최근100건에만 적용 | 서버의 전체 snapshot에 적용한 뒤 페이지 제한 |
| 자유 검색·분석기 | 최근100건에 적용 | **현재 페이지**에만 적용. 입력과 안내에 범위를 표시 |
| 다음·이전 | 브라우저 배열의 위치 변경 | 매번 서버와 현재 신원을 확인. 이전 첫 페이지도 같은 snapshot으로 재조회 |
| 새 분석·검토 추가 | 최신 조회 배열로 교체 가능 | SQLite는 처음 조회한 prefix를 유지. 명시적 최신 목록 조회에서만 새 snapshot 시작 |
| 오류·만료 | 최근 배열에 대한 일반 조회 오류 | 이전 행·커서 이력을 지우고 다음·이전·내보내기 중단. 최신 목록 조회로 명시적 재시작 |
| JSON 저장 | 최근100건 중 필터 결과 | 현재 페이지의 필터 결과만 저장. 저장 전 신원과 같은 snapshot을 서버에서 재검증 |

검색이나 분석기 선택이 서버 전체 검색으로 바뀐 것은 아니다. 페이지에 검색 결과가 없더라도 다른 페이지의 일치 여부를 추론하지 않는다. 전체 조건 일치 수는 서버의 위험도·검토 필터 결과 수이며, 현재 페이지 표시 수와 별도로 안내한다.

관제 개요의 최근 기록·차트는 기존 `/results?limit=100`을 계속 사용한다. 이번 변경 범위는 로그 탐색이며, 모든 대시보드 목록과 legacy workbench를 새 API로 이전한 것은 아니다.

## API와 화면 연결

`AuditResultPage`에 현재 위치를 다시 읽는 `page_cursor`를 추가했다. 기존 `next_cursor`는 다음 위치, `page_cursor`는 지금 위치다. 첫 페이지의 `page_cursor`도 동일한 backend·source·tenant·필터·prefix/view·원래 만료 시각에 묶여 있다. 돌아가기 위해 cursor 없는 새 요청을 보내 조회 기준을 바꾸지 않는다.

`page_cursor`는 기존 AES-GCM 커서 계약을 재사용한다. 새로운 인증 수단이나 권한 발급 기능이 아니다. 서버는 매 요청의 인증·viewer RBAC·tenant·현재 계정/OIDC 만료·현재 저장소·전체 감사 무결성을 계속 검사한다. 이전 페이지 커서의 재조회로 만료를 연장하지 않는다.

브라우저의 로그 탐색 상태는 현재 최대12개 행과 방문 위치별 커서를 메모리에 유지한다. 다음·이전 페이지는 캐시된 행을 그대로 보여주는 대신 서버에서 다시 읽는다. 다음 사항도 검사한다.

- 조회 전후 `/auth/me`의 subject·tenant·auth method와 현재 연결 신원 일치.
- 같은 조회의 snapshot ID·생성/만료 시각·모드·전체 일치 수 유지.
- 현재 tenant와 선택한 위험도·검토 필터에 맞는 행, 페이지 크기와 다음 커서 유무.
- 페이지 내부 중복 analysis ID 및 인접 페이지가 같은 행을 반복 반환하는 응답 거부.
- 필터 변경의 generation, 연결 변경의 epoch와 AbortController로 이전 요청 폐기.

이 검사는 임의의 악성 서버에 대한 독립 서명 증명이나 전체 수집 원본의 최신성 보증이 아니다. 원래의 서버 무결성 검증과 인증 경계가 계속 필요하다.

## 조회와 현재 검토의 구분

목록은 표시한 시각의 감사 snapshot이다. SQLite의 새 분석·검토 이력은 기존 prefix의 순회 결과를 바꾸지 않는다. JSONL/연합 JSONL에서 자기 tenant view가 바뀌면 서버409를 그대로 표시하며 최신 목록으로 자동 전환하지 않는다.

상세를 열면 `/results/{event_id}`의 **현재 상태**를 다시 읽는다. 그 상세의 ETag·호출 신원에 검토 요청을 묶는 [이전 대시보드 검토 보호](extra-dashboard-review-20261119.md)를 유지했다. 예전 목록에 검토 대기로 보이는 행도 상세에서는 이후 조사 중으로 바뀐 상태를 확인할 수 있다. 과거 목록을 현재 접근 허용이나 검토 승인으로 사용하지 않는다.

주기적인10초 새로고침은 개요 지표를 갱신하지만 현재 탐색 페이지와 snapshot을 자동 초기화하지 않는다. 페이지 읽기/저장 중에는 주기적 새로고침을 미뤄 중복 조회를 피한다. 사용자가 누르는 새로고침 또는 최신 목록 조회는 명시적으로 새 snapshot을 시작한다.

## 저장과 오류 처리

현재 페이지 JSON에는 snapshot ID·생성/만료 시각·모드·페이지 번호·서버 전체 일치 수·적용 필터와 현재 페이지의 결과를 넣는다. 커서와 자격 증명은 넣지 않고 기존 민감 필드 redaction을 적용한다. localStorage/sessionStorage·주소창에 커서나 자격 증명을 저장하지 않는다.

저장을 누르면 현재 페이지의 커서로 다시 조회하고 현재 신원을 전후로 확인한다. 같은 API 키가 다른 subject로 재매핑된 경우에도 기존 페이지를 저장하지 않는다. 저장 중 검색·분석기 조건을 수정하면 이전 조건의 파일을 만들지 않고 다시 저장하라고 안내한다.

| 실패 | 화면 동작 |
|---|---|
| 400·409 | 이전 조회를 이어갈 수 없다고 표시. 행·커서 제거 후 최신 목록 조회 요구 |
| 410 | 조회 만료 안내. 자동 재시작/만료 연장 없음 |
| 501 | 현재 backend의 페이지 기능 미지원 안내. `/results`로 fallback하지 않음 |
| 401·403·신원 불일치 | 목록과 상세·내보내기 중단. 연결/현재 신원 확인 요구 |
| 503·네트워크 오류 | 이전 행을 성공한 현재 결과처럼 남기지 않음. 명시적 재시도 요구 |
| 형식·snapshot·tenant 불일치 | 부분 결과를 표시하거나 저장하지 않음 |

여러 worker나 재시작 후 이어 읽기는 [기존 커서 키 파일·pin 설정](extra-audit-paging-20261119.md)이 필요하다. 프로세스별 휘발성 키로 발급한 커서를 다른 worker가 읽지 못하는 경우에도 UI가 조건을 생략해 우회하지 않는다.

## 무료 로컬 검증

관련 pytest는 **Windows233통과·25제외, Linux256통과·2제외**다. 두 OS는 같은258개 사례를 실행했으며 결과를 합산하지 않는다. 공통 제외2개는 SQLite에 적용되지 않는 JSONL view 변경 사례이고, 추가 Windows23개는 POSIX 파일/프로세스·호스트 작업 조건이다. 신규 backend7개는 현재 페이지 커서로 되돌아가기, SQLite 추가/검토 뒤 원래 첫 페이지 보존, 원래 만료 시각 유지를 다룬다. 전체 저장소 시험을 새로 모두 실행한 결과는 아니다.

신규 브라우저는 격리 SQLite에 tenant-a136건과 다른 tenant1건을 넣고, 시험 중 rule 분석으로 자기 tenant1건을 추가했다. 최근100건에 없는 가장 오래된 위험도 필터 일치와 **자기 tenant137건의 중복 없는12페이지 순회**를 실제 HTTP/Chromium으로 확인한다. 다음 검증도 포함한다.

- 새 분석·검토 뒤 다음/이전의 동일 snapshot·원래 만료 유지, 명시적 재조회에서 새 결과 반영.
- 현재 페이지 JSON 저장 전 재검증·과거 목록과 현재 상세 상태 구분.
- 주기적 개요 새로고침의 페이지 보존, 늦게 도착하는 이전 필터 응답 폐기.
- 저장 중 검색 변경·같은 키의 subject 변경·진행 중 다른 tenant 연결로 전환.
- 400/409/410/501/503 및 잘못된 snapshot·만료·cursor·행 수·tenant·중복 응답의 차단.
- desktop1440×1080·mobile390×844의 실제 화면·가로 넘침·현재 페이지 검색 범위와 저장 범위.

기존 대시보드 검토·조회·Linux 운영 작업도 별도 브라우저 묶음으로 재검증했다. 조건 수와 raw 보고서·XML·소스 지문은 [검증 원본 JSON](infrastructure-results/extra-dashboard-paging-20261119.json)을 따른다. 이 조건 수는 독립 탐지 사례 수나 모델 정확도가 아니다.

| 브라우저 묶음 | 통과 조건 | 실행 범위 |
|---|---:|---|
| 신규 감사 페이지 | 38 | 실제 Chromium·Windows 앱·API key·SQLite·137건 순회·신원/필터/저장 경합 |
| 기존 검토 | 27 | 조회 버전·신원 binding·동시 검토·응답 유실 보호 유지 |
| 기존 조회 | 57 | 상세·내보내기·오류·합성 접근 회수·반응형 회귀 |
| 기존 운영 Linux | 146 | 모든 운영 폼·실제 POSIX mock job·승인·세션 회수 |

[데스크톱 조회 화면](infrastructure-results/dashboard-paging-audit-page-desktop-20261119.png), [모바일 조회 화면](infrastructure-results/dashboard-paging-audit-page-mobile-20261119.png), [만료 후 차단 화면](infrastructure-results/dashboard-paging-audit-expired-20261119.png)을 보존했다. 소유 시험 서버가 종료됐는지도 확인했다.

의도적으로 신원 요청을 붙잡는 브라우저 fixture에서 간헐적인 시간 초과가 있었다. 실제 interception 접수를 기다리고 첫 신원 요청만 지연시키며 후속 확인 요청은 통과시키도록 보완했다. 검사 기준을 시간 초과도 성공으로 바꾸지 않았다. 해당 실패는 최종 성공 조건 수에 합산하지 않는다.

기계 디자인 검사에서는 기존 HTML/CSS의 작은 기능 글자·일부 대비와 placeholder em dash 사용에 대한 경고가 남았다. 이번에 공통 CSS/폰트 체계를 교체하거나 접근성 검사를 모두 통과했다고 주장하지 않는다. 변경한 조회/오류 화면은 실제 desktop/mobile로 확인하며 기능 검증과 별도로 기록한다.

## 재현

프로젝트 개발 Python 환경과 별도 기존 Playwright/Chromium 환경에서 실행한다. 아래 브라우저 fixture는 실제 키를 받지 않고 규칙 분석·합성 계정만 사용하며 자신의 서버를 종료·회수한다.

```powershell
python -m pytest tests/test_audit_paging.py tests/test_audit_paging_http.py tests/test_audit_query_admission.py tests/test_audit_review_identity.py tests/test_audit_review_preconditions.py tests/test_audit_review_preservation.py tests/test_audit_review_client.py tests/test_audit_review_client_transport.py tests/test_audit_review_client_process.py tests/test_http_review_preconditions.py tests/test_sqlite_audit.py tests/test_federated_audit.py tests/test_compact_audit_integrity.py tests/test_dashboard_identity.py tests/test_dashboard_audit_catalog.py tests/test_dashboard_integration_boundaries.py tests/test_dashboard_operations.py -q --junitxml=runtime/dashboard-paging.xml
python -m scripts.test_dashboard_paging_browser --output-dir runtime/dashboard-paging-browser
python -m scripts.test_dashboard_review_browser --output-dir runtime/dashboard-review-browser
python -m scripts.test_dashboard_browser --browser-channel chrome --output-dir runtime/dashboard-readonly-browser
python -m scripts.test_dashboard_operations_browser --output-dir runtime/dashboard-operations-browser
```

Chromium이 기본 경로에 없으면 신규 paging/review 명령의 `--browser-executable`을 지정한다. Windows host job 미지원은 기존 운영 브라우저 시험에서 별도 제외로 보고하며 실제 POSIX job 동작은 Linux에서 검사한다.

## 남은 작업과 성능 지표

모델·프롬프트·분류 규칙·평가 원본·정답·예측은 바꾸지 않았다. 기존 실제 API 합성 개발360건은 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33% 그대로이며 새 독립95% 목표 달성으로 보고하지 않는다.

다음 후보는 legacy workbench/다른 client의 검토 신원 binding 이전과 별도 전체 범위 자유 검색 설계다. 외부 기업 SSO/online revocation, 독립 witness/WORM, 새 전체 회귀·실제8시간 soak·다중 호스트/전원 단절 인수는 계속 남아 있다. UI 페이지 연결로 서버의 전체 chain 검증 비용을 줄이거나 운영 처리량을 새로 입증한 것은 아니다.
