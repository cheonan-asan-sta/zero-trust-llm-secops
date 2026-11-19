# 전체 감사 기록의 문자열 검색·분석기 조건

2026-11-19 · 로컬 extra · 구현 `400d742`. 활성 지속 개발 목표의 첫 항목이다. 목표 전체가 완료된 것은 아니다.

`GET /audit/results`에 `q`와 `analyzer`를 추가했다. 기존 tenant·risk/review 조건과 함께 검증된 전체 감사 자료에서 일치 항목을 고른 뒤 페이지를 만든다. SQLite·JSONL·federated JSONL 모두 동일한 검색 조건을 사용한다. 전체 chain 검증을 생략하거나 검색을 최근100건으로 자르지 않는다. 전용 검색 인덱스·성능 개선을 구현했다고 주장하지 않는다.

검색은 NFKC/casefold 기반 literal 부분 문자열이며 regex가 아니다. event/analysis/actor ID·분석기 이름·판단 근거·evidence·검토자·검토 메모만 대상이다. raw payload·자격 증명·LLM trace 전체를 검색하지 않는다. 검색어는256문자 및 정규화 후 UTF-8 512바이트, 분석기 식별자는64자로 제한한다. 공백만 있는 검색어는 조건 없음으로 정규화한다. 분석기 이름은 정확히 일치해야 한다.

암호화 cursor의 범위에 검색어·분석기를 포함했다. 다음/이전 페이지는 같은 조건과 조회 기준·원래 만료를 유지하며 조건을 바꾼 cursor 재사용은400으로 거부한다. 이전 cursor에 없던 필드가 추가돼 배포 버전 전환 중 snapshot ID가 달라질 수 있다. 화면은 불일치를 묵인하지 않고 새 목록 조회를 요구한다. 실제 조직의 롤링 배포를 실행한 것은 아니다.

워크벤치와 대시보드에 ‘전체 기록 검색’을 연결했다. 입력 변경은 기존 목록과 이동을 초기화하며 버튼으로 새 조회를 시작한다. 워크벤치에서는 Enter도 지원한다. 대시보드의 기존 현재 페이지 검색/분석기 필터는 내려받은 페이지에 대한 추가 필터로 유지하며, 전체 검색과 구분해서 표시한다. 현재 페이지 JSON 저장에는 서버 검색 조건과 로컬 추가 필터를 모두 기록한다. 검색은 서버 신원·권한을 대신하지 않으며 검토 저장의 ETag/caller binding은 그대로다.

## 이번 단계의 기능 검증

| 실행 | 결과 |
|---|---|
| 검색·기존 감사 페이지/API Windows | 83통과·2제외 |
| 같은85개 사례 Linux | 83통과·2제외 |
| 최대 한글 검색어·커서 크기 경계 | Windows3통과·Linux3통과, 위85개 이후 추가한 별도3개 사례 |
| 두 화면의 새 실제 브라우저 시험 | 18조건 통과 |
| 기존 워크벤치 감사 페이지 | 45조건 통과 |
| 기존 대시보드 감사 페이지 | 38조건 통과 |

공통 제외2개는 SQLite에 해당하지 않는 JSONL view 변경 사례다. OS별 결과나 반복 실행을 합산해 독립 사례 수로 표시하지 않는다. 이는 필요한 기능 검증이며 목표 범위에서 제외한 프로젝트 전체 회귀 결과 정리·실제8시간 시험은 수행하지 않았다.

합성136건의 실제 loopback 앱에서 최근100건 밖의 기록 검색, 분석기 조건 결합, 조건 유지 페이지 이동, 입력 후 이전 목록 폐기, 잘못된 분석기 응답 차단, desktop/mobile 가로 넘침을 확인했다. 원본과 지문은 [단계별 검증 manifest](infrastructure-results/extra-audit-search-20261119.json)에 보존한다. 새 정규화 시험의 최초 실패는 미검토 행에 검토 메타데이터를 넣은 fixture 때문이었다. 유효한 검토 상태·SQLite save_review CAS 경로로 fixture를 고쳤고 서버 무결성 검사를 약화시키지 않았다.

기계 디자인 검사에는 기존 대비·작은 글자·장식 경고가 남는다. 새 화면은 실제 렌더링으로 확인했지만 전체 접근성 통과를 선언하지 않는다. 유료 API·AWS·Docker·push·CI·병합은 하지 않았다. 모델·정답·기존 예측은 동일하며 기존 합성 개발 F1 93.41%를 새로 측정하거나 목표 달성으로 바꾸지 않는다.

```powershell
python -m pytest tests/test_audit_search.py tests/test_audit_paging.py tests/test_audit_paging_http.py -q
python -m scripts.test_audit_search_browser --browser-executable "C:/Program Files/Google/Chrome/Application/chrome.exe" --output-dir runtime/audit-search-browser
```

다음 목표는 세션·사고 목록의 페이지 탐색, 호출 경로/필수 검토 정책 적용 준비, 별도 감사 보관·검증자의 로컬 구현이다. 실제 조직 배포·외부 인증·독립 운영 보관 완료와 로컬 모의를 구분한다.
