# 세션·사고 목록 페이지 탐색: 서버 단계

2026-11-19 · extra 로컬. 활성 목표의 두 번째 항목을 진행 중이다. **서버 API·관련 기능 검증을 먼저 완료했으며 화면 연결은 아직 남았다.** 목표 전체나 세션·사고 페이지 작업 전체를 완료로 표시하지 않는다.

새 API는 `GET /case-pages`와 `GET /zero-trust/session-pages`다. 기존 `/cases`, `/zero-trust/sessions` 응답은 유지한다. 사건 ID나 세션 ID가 `page`인 기존 상세 경로와 충돌하지 않도록 별도 경로를 사용했다.

| 입력/출력 | 계약 |
|---|---|
| 공통 입력 | limit1~100, 기본12, 암호화 cursor |
| 사고 조건 | status, 현재 tenant |
| 세션 조건 | decision·signal_trust, 현재 tenant |
| 반환 | items·total_matches·현재/다음 cursor·조회 ID/생성/만료 시각 |
| 조회 방식 | unchanged_live_view, historical_audit_snapshot=false |
| 순서 | 사고 updated_at/case_id 내림차순, 세션 evaluated_at/session_id 내림차순 |

감사 목록의 과거 SQLite prefix와 달리 **변경되지 않은 현재 목록**을 이어 읽는 방식이다. 같은 조건의 공개 행이 바뀌면409로 중단하고 새 조회를 요구한다. 목록 조회가 세션 허용을 발급·소비하거나 권한을 회수하는 동작을 수행하지 않는다. 세션 응답에는 SessionDecision만 담고 grant token/hash는 넣지 않는다. 실제 자원 접근과 검토 저장은 기존 현재 권한·버전 검증을 사용한다.

cursor는 AES-GCM으로 보호하며, 감사 cursor master에서 별도 HKDF domain으로 키를 파생한다. 종류/저장소·현재 subject/tenant/auth method·limit·조건·목록 지문·위치·원래15분 만료에 묶는다. 다른 주체/조건/페이지 크기로 재사용하면400, 만료는410, 목록 변경은409다. 같은 cursor로 재조회해도 만료가 연장되지 않는다. master가 바뀌면 기존 cursor를 자동 변환하지 않는다. 재시작·여러 worker의 키 공유에는 기존 전용 key/path pin 설정이 필요하다.

사고 페이지는 기존 저장 객체의 메모리 캐시를 그대로 페이지로 자르지 않는다. 로컬 CaseStore 파일을 다시 읽어 정규 파일·읽기 전후 상태·hash chain·버전 연속성을 검사하고, 현재 process가 이미 알고 있던 기록의 prefix가 남았는지도 확인한다. 읽는 동안 변경되거나 손상/기록 누락이면503이다. 다른 정상 writer의 추가 기록은 새 조회에 반영하며 이전 cursor는409로 막는다. 이 검사만으로 관리자와 독립된 최신성 witness를 구현한 것은 아니다.

자원 상한은 최대128MiB 사고 파일·100,000개 이력 envelope·행당2MiB·반환 대상10,000개다. 세션 조회는 기존100건 절단 이전에 전체 최신 세션을 구하고 상한을 검사한다. 상한을 넘긴 자료를 전체인 것처럼 잘라 반환하지 않는다. 로컬 사고 저장소만 지원하며 DynamoDB 사고 페이지는501로 명시적으로 거부한다. AWS 호출/배포 인수를 수행하지 않았다.

두 API는 기존 query admission 슬롯을 사용하고, 실제 I/O 전후 현재 호출 신원·만료·저장소 객체/경로를 재확인한다. 취소된 요청도 소유 worker가 끝날 때까지 슬롯을 유지한다. 읽은 순간 이후의 다른 세션 변경까지 분산 원자적으로 잠그는 기능이 아니다. 목록은 조회 시점의 상태이며 현재 상세/실제 집행은 별도로 검증해야 한다.

## 이번 서버 단계의 검증

Windows·Linux 각각 **49통과·실패/제외0**이다. 같은49개 사례이며 합산하지 않는다. 새 페이지/경계10건과 기존 사고·제로 트러스트 동작39건을 함께 실행했다. 실제 세션103건을 모든 페이지에서 조회했고 27개 사고를 탐색했다. 신원 변경·키 철회·저장소 변경의 전달 거부, 현재 캐시 밖의 실제 파일 추가, 파일 손상/축소, cursor 조건 변경·키 변경·만료, 취소 시 슬롯 보존을 포함한다.

초기 세션 fixture의 첫 실패는 서로 다른 세션에 동일 event ID를 재사용했기 때문이다. 합성 event ID를 구분했고 기존 재사용 방지 정책은 유지했다. 원본 XML·소스 지문은 [서버 검증 manifest](infrastructure-results/extra-collection-pages-server-20261119.json)에 보존한다. 새 전체 저장소 회귀 결과 정리·브라우저 인수·실제8시간 soak가 아니다.

```powershell
python -m pytest tests/test_collection_paging.py tests/test_incident_cases.py tests/test_zero_trust_operations.py -q
```

다음은 워크벤치의 사고/서명 세션 목록과 자체 대시보드 세션 목록에 새 API를 연결하는 것이다. 기존 목록의 최근 건수/필터 의미를 전체 페이지로 바꿀 때 조회 신원·지연 응답·현재 상세/조치 경계를 함께 검사한다. 이 후속 전에는 UI 이전 완료로 발표하지 않는다.

유료 모델·AWS·Docker·업로드·CI·병합은 하지 않았다. 모델·프롬프트·규칙·평가 원본·정답·기존 예측은 변경하지 않았으며 합성 개발 F1 93.41%를 새로 평가하거나 독립 목표 달성으로 바꾸지 않는다. 나머지 호출 정책 준비·별도 감사 검증자 로컬 구현도 활성 목표에 남아 있다.
