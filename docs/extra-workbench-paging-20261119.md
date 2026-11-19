# 기존 워크벤치의 감사 기록 페이지 탐색

2026-11-19 · 로컬 `extra`. 기능 구현은 `d82052e`, 모바일 표 표시 보완은 `79bdf4e`다. `/static/workbench.html`에서 기존 감사 cursor API를 사용한다. 서버·모델·프롬프트·평가 원본·정답은 변경하지 않았다. 유료 모델·AWS·Docker·push·CI·main/aitest 병합은 실행하지 않았다.

## 이전과 달라진 점

기준 `78828d5`의 워크벤치는 `/results?limit=8`로 최근8건만 가져왔다. 현재는 `/audit/results?limit=12`의 서버 페이지와 전체 범위 위험도·검토 상태 필터를 사용한다. 전체 기록을 브라우저로 내려받거나 최근100건 안에서만 필터링하는 방식으로 우회하지 않는다. 이 전후 비교의 이전 동작은 코드 확인이며 새 baseline 성능 평가가 아니다.

| 기능 | 현재 동작 |
|---|---|
| 처음 조회 | 현재 신원 확인 → 첫 감사 페이지 → 신원 재확인 |
| 이전/다음 | 서버가 준 현재/다음 cursor로 같은 조회 기준 이동 |
| 위험도·검토 상태 | 서버의 전체 tenant 감사 기록에 적용. 조건 변경은 새 첫 페이지 조회 |
| 개요 새로고침 | 현재 집계만 갱신. 감사 페이지와 조회 기준을 덮어쓰지 않음 |
| 최신 목록 조회 | 새 조회 기준으로 첫 페이지 시작. 신규 분석·검토 반영 |
| 목록의 열기 | 과거 목록 데이터를 저장에 재사용하지 않고 현재 상세·ETag·호출 신원 재조회 |
| 검토 저장 | 기존 If-Match + caller binding·명시적 확인·서버 필수화 선택 정책 유지 |

SQLite는 검증된 과거 prefix 기준으로 페이지를 유지한다. JSONL 계열은 변경되지 않은 로컬 view를 전제로 하며, 변경되면 처음부터 재조회해야 한다. UI가 이 두 backend 의미를 동일한 전역 트랜잭션으로 표현하지 않는다.

## 신원·경합·오류 처리

조회 전후의 subject·tenant·auth method를 현재 연결 및 페이지 신원과 비교한다. cursor 이동에서는 snapshot ID·조건 일치 수·생성/만료 시각·모드도 유지돼야 한다. 페이지 행 수·중복 analysis ID·다른 tenant·조건 불일치·응답 형식도 검사한다. 결과 문자열은 textContent로 렌더링한다.

조건 변경은 진행 요청을 취소하고 세대 번호로 늦은 응답을 폐기한다. 연결을 바꾸면 이전 cursor·행·상세·검토 확인·진행 요청을 초기화한다. 같은 키의 subject가 바뀌거나401/403이 발생해도 이전 내용을 지우고 **명시적으로 연결 및 인증을 다시 적용**하도록 한다. 새 계정으로 자동 로그인하거나 진행 중 분석을 새 키로 이어 보내지 않는다.

400/409/410/501/503·잘못된 응답은 기존 행과 다음/이전 이동을 비우며, 자동 재시도나 최근 목록 API fallback을 하지 않는다. 서버의 만료410 외에 화면의 로컬 만료 timer도 행/탐색을 비운다. 이 timer는 클라이언트 시계에 의존하는 표시 보호이고, 최종 권한·cursor 만료 검증은 서버가 담당한다. 목록 조회 실패가 이미 저장된 감사 이력의 삭제나 rollback을 뜻하지 않는다.

## 화면과 사용 순서

1. 기존 워크벤치에서 API key/OIDC 또는 허용된 로컬 익명 조회를 선택한다.
2. 분석 현황 아래 ‘감사 기록’의 위험도·검토 상태를 고른다.
3. 다음/이전 페이지로 같은 기준의 기록을 탐색한다. 신규 기록은 ‘최신 목록 조회’로 반영한다.
4. ‘열기’에서 현재 상세를 읽고, 검토 내용을 확인한 뒤 저장한다. 목록에서 보던 시점과 현재 상세 상태는 다를 수 있다.

현재 페이지/조건 일치 건수·기준 시각·복구 안내를 표시한다. 모바일에서는 표의 열을 잘게 세로로 쪼개지 않고 표 안에서 가로 스크롤한다. 안내 문구와 키보드로 초점을 줄 수 있는 표 영역, 필터/버튼의 focus 표시를 제공한다. [데스크톱 화면](infrastructure-results/workbench-paging-desktop-20261119.png), [모바일 화면](infrastructure-results/workbench-paging-mobile-20261119.png), [만료 상태](infrastructure-results/workbench-paging-expired-20261119.png)를 보존한다.

기계 디자인 검사는 기존 화면의 낮은 대비·작은 글자·장식/영문 kicker 경고를 반환했다. 기존 시각 체계를 전면 교체하거나 접근성 전체 통과를 선언하지 않는다. 새 필터/이동 버튼은44px 높이,13px 이상 글자와 focus 표시를 사용하며, 변경 영역은 실제 desktop/mobile 화면으로 확인했다.

## 무료 로컬 검증

| 실행 | 결과 | 범위 |
|---|---|---|
| 최종 감사 페이지 브라우저 | 45조건 통과 | 모바일 보완 포함 `79bdf4e` |
| 기존 워크벤치 검토 | 34조건 통과 | `d82052e`, 필수 caller binding·익명 시연·경합 회귀 |
| Windows pytest | 324통과·5제외 | 같은329개 사례 |
| Linux pytest | 327통과·2제외 | 같은329개, 공통2개는 SQLite에 해당하지 않는 JSONL view 변경 시험 |

추가 Windows3개는 POSIX 파일/별도 native worker 조건이며 Linux에서 통과했다. 실제 TLS/mTLS6건·CLI·SQLite CAS/행 보존·기존 감사 페이지/API/권한 회귀를 포함한다.

격리 SQLite에 자기 tenant136건·다른 tenant1건을 넣고 rule 분석1건을 추가했다. 자기 tenant137건을12페이지에서 중복 없이 순회하고, 최근100건 밖의 `page-event-001`을 위험도 조건으로 찾았다. 새 분석·검토 뒤 같은 조회 기준 유지와 명시적 재조회 반영도 확인했다.

브라우저는 실제 loopback 앱과 설치된 Chrome을 사용한다. 정상 API 왕복 외에 오류·잘못된 응답·지연된 이전 응답은 Playwright interception으로 주입한다. 같은 키 subject 변경은 실제 합성 계정 파일을 바꾸어 조회 전과 페이지 응답 후 각각 검증했다. 다른 tenant 연결 변경·키보드 이동·모바일 스크롤·자격 증명 비저장·외부 요청/JavaScript 오류 여부도 포함한다. 응답 주입 사례가 운영 DB의 실제 손상이나 전원 장애 인수를 대신하지 않는다.

초기 fixture는 새 CRITICAL 분석까지 추가했는데 결과를1건으로 단정했고, Playwright가 주는 두 번째 request 인수를 기본 매개변수로 잘못 받았다. 또한 tenant 전환 시험은 늦은 이전 계정 응답을 시험 수집기가 먼저 잡았으나 실제 UI는 새 tenant를 표시했다. 고정 기대값·callback 인수·응답 수집기의 credential 구분을 수정했다. UI/서버의 검증 조건을 낮춰 성공으로 바꾸지 않았으며, 초기 실패 원본과 최종 결과는 [검증 manifest](infrastructure-results/extra-workbench-paging-20261119.json)에서 구분한다.

기능/검토 묶음의 코드 기준과 모바일 표시 후속 기준을 구분한다. 후속은 HTML/CSS와 모바일 검증만 변경했으며 app.js·backend·pytest 파일은 동일하다. OS별 pytest와 브라우저 조건은 서로 더해 독립 사례 수로 표시하지 않는다. 저장소 전체 회귀나 새 탐지 품질 평가가 아니다. 소유 서버·브라우저·CLI process는 종료/회수한다.

## 재현

기존 개발 Python과 Playwright/Chrome 환경을 사용한다. 이번에는 새 설치 없이 `tmp/main-demo-video-tools`의 Playwright를 재사용했다.

```powershell
python -m scripts.test_workbench_paging_browser --browser-executable "C:/Program Files/Google/Chrome/Application/chrome.exe" --output-dir runtime/workbench-paging-browser
python -m scripts.test_workbench_review_browser --caller-bound-reviews --browser-executable "C:/Program Files/Google/Chrome/Application/chrome.exe" --output-dir runtime/workbench-review-browser
python -m pytest tests/test_audit_paging.py tests/test_audit_paging_http.py tests/test_audit_query_admission.py tests/test_audit_review_policy.py tests/test_audit_review_identity.py tests/test_audit_review_preconditions.py -q
```

실제 실행한 확대 pytest 파일 목록·OS별 제외 사유·raw XML/JSON·소스 지문은 manifest를 따른다. 서버의 필수 검토 설정 기본값은 여전히 false이며 실제 조직 배포를 변경하지 않았다.

## 남은 범위와 탐지 지표

워크벤치의 감사 페이지 이전은 완료했다. 전체 자유 검색·분석기 조건의 서버 검색, 다른 세션/사고 목록의 페이지 이전, 외부 조직 writer/worker의 필수 정책 배포·기업 SSO·독립 witness/WORM·최신 전체 회귀·다중 호스트/긴 운영 인수는 남아 있다. 이번에 전체 텍스트 검색이나 다른 목록까지 구현한 것으로 표시하지 않는다.

기존 실제 API 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33%는 그대로다. 원본·정답·기존 예측을 바꾸거나 이번 작업을 독립95% 목표 달성으로 집계하지 않는다.
