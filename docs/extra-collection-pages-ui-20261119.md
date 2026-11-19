# 세션·사고 목록 페이지: 두 화면 연결

2026-11-19 · extra 로컬 · 구현 `48520ef`. [서버 단계](extra-collection-paging-20261119.md) 다음으로 워크벤치와 자체 대시보드에 페이지 탐색을 연결했다. 활성 목표 중 세션·사고 목록 항목을 완료했으며 나머지 호출 정책 준비·별도 검증자 구현은 계속 진행한다.

| 화면 | 목록 | 서버 조건/기능 |
|---|---|---|
| 워크벤치 | 사고 케이스 | case-pages, 이전/다음/최신 조회 |
| 워크벤치 | 서명 수집기 세션 | session-pages, verified_source를 전체 목록에 적용 |
| 대시보드 | 사고 목록 | case-pages, 현재 상세 조회 양식 연결 |
| 대시보드 | 세션과 접근 | session-pages, 접근 판단 조건을 서버에 적용 |

한 번에12건씩 표시한다. 공통 CollectionView가 조회 전후 현재 subject·tenant·auth method, 같은 조회 지문·원래 만료·총수, 행/중복/조건을 확인한다. 조회 중에는 이전 행을 비우고, 연결 변경·오래된 응답·목록 변경409·만료410·형식 오류를 자동 재시도나 최근 목록 fallback으로 우회하지 않는다. 401/403 또는 같은 키의 subject 변경은 이전 화면과 검토 상태를 초기화하고 새 연결을 요구한다. 만료 timer도 이동/행을 비우며 최종 만료 검사는 서버가 담당한다.

목록은 변경되지 않은 현재 view를 이어 보는 것이며, 감사 DB의 과거 prefix 페이지와 다르다. 실제 세션 회수나 사고 변경 뒤에는 같은 cursor로 이동하지 못한다. 상세·검토·실제 접근 집행은 현재 상태와 권한을 별도로 확인한다. 토큰을 발급/소비하는 UI를 추가한 것이 아니다. 대시보드 회수 건수는 현재 조회 페이지의 표본임을 표시한다.

기존 사고 GET 양식은 ‘사고 최근 목록 (호환)’으로 표시하고 새 전체 페이지 목록과 구분했다. 기존 API 응답 자체는 유지한다. 로컬 CaseStore의 읽기 무결성 검증을 추가한 것이며 기존 CaseStore writer를 다중 process 공동 transactional writer로 바꾼 것은 아니다. 외부 정상 writer 추가를 새 페이지가 읽을 수 있다는 시험을 모든 기존 writer의 동시 쓰기 인수로 해석하지 않는다. DynamoDB 사고 페이지501 제한도 유지한다.

## 무료 로컬 기능 검증

| 실행 | 결과 |
|---|---|
| 새 네 화면 경로의 실제 브라우저 | 112조건 통과 |
| 기존 워크벤치 검토 | 34조건 통과 |
| 기존 대시보드 조회·모의 접근 | 57조건 통과 |
| 관련 Python Windows/Linux | 각각72통과·실패/제외0, 같은72개 사례 |

새 브라우저 fixture는 실제 Ed25519 서명과 등록 공개키를 이용해 합성 세션103건을 생성했다. 서명 검증을 우회해 verified_source라고 기록하지 않았다. 사고 목록은 페이지 크기 시험을 위해 한 합성 사고 근거에 서로 다른 case ID를 부여한27개 레코드이며 독립 사고 탐지 평가27건이 아니다. 다른 tenant의 별도 기록도 넣었다. 네 경로 모두 모든 ID를 중복 없이 탐색하고 API 행과 실제 DOM 행을 비교했다.

실제 합성 사고 상태 변경/세션 회수 이후 이전 cursor의409와 행 폐기를 확인했다. 400/409/410/501/503·잘못된 응답·401/403, 실제 동일 키 subject 재매핑, 다른 tenant 연결 뒤 늦은 응답도 검사했다. 오류 주입 사례와 실제 서버 변경 사례를 구분하며 OS 전원 단절이나 외부 기업 인수를 대신하지 않는다.

초기 네 화면 시험은 탐색 직후 reload를 기다리는 동안 이전 탐색의 응답을 수집기가 먼저 잡아 snapshot 비교에 실패했다. 화면 작업이 끝난 뒤 응답 수집을 시작하고 현재 credential의 응답만 수집하도록 fixture를 고쳤다. UI의 snapshot 일치 기준은 유지했다. 실패 원본과 최종 JSON/XML·소스 지문은 [검증 manifest](infrastructure-results/extra-collection-pages-ui-20261119.json)에 보존한다.

[대시보드 사고 모바일](infrastructure-results/collection-pages-ui-cases-mobile-20261119.png), [서명 세션 모바일](infrastructure-results/collection-pages-ui-signed-mobile-20261119.png)을 확인했다. 표 안에서 가로 스크롤하며 안내·키보드 focus와44px 탐색 버튼을 제공한다. 기존 화면 전체의 대비·작은 글자·장식 경고는 남아 있고 완전한 접근성 통과를 선언하지 않는다.

```powershell
python -m scripts.test_collection_pages_browser --browser-executable "C:/Program Files/Google/Chrome/Application/chrome.exe" --output-dir runtime/collection-pages-browser
python -m pytest tests/test_collection_paging.py tests/test_incident_cases.py tests/test_zero_trust_operations.py tests/test_dashboard_identity.py tests/test_dashboard_audit_catalog.py tests/test_api.py -q
```

소유 서버·브라우저는 종료/회수했다. 유료 모델·AWS·Docker·push·CI·병합은 하지 않았다. 프로젝트 전체 회귀 결과 정리와 실제8시간 시험은 이번 목표에서 제외한 상태 그대로다. 모델·규칙·평가 원본·정답·기존 예측은 바꾸지 않았고 기존 합성 개발 F1 93.41%를 새로 평가하거나 목표 달성으로 표시하지 않는다.
