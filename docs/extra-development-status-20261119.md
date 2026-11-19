# extra 로컬 개발 현황과 남은 검증

2026-11-19 오전 08:00 시간 상한의 이전 작업은 마감했고, 이후 사용자 요청으로 아래 후속을 진행했다. 소스·시험·문서는 로컬 extra에만 저장했으며 push·CI·병합하지 않았다.

2026-11-19 오전 개발 기록. 이 문서는 세부 보고서의 과거 수치/남은 항목을 현재 구현과 구분해 읽기 위한 시작점이다. 주차별 완료나 기말 발표 성과 전체를 새로 판정하는 문서는 아니다.

## 오전08:00 이후 후속

운영자의 실제 검토 client를 연결했다. [ETag·신원·HTTPS/mTLS 검토 CLI](extra-operator-review-client-20261119.md)는 조회 snapshot을 만든 뒤 명시적으로 검토하며 stale412·신원/tenant 변경·응답 유실에 자동 우회/재시도하지 않는다. 구현은 `c0a8108`의 scripts/tests이며 서버·모델·UI 코드는 변경하지 않았다. 기존 오전08:00 종료 기록은 그 작업 시간대의 기록으로 보존한다.

이후 [대시보드 조회 버전·호출 신원 연결](extra-dashboard-review-20261119.md)을 `bef9a97`에 구현했다. 상세에서 연 결과를 그대로 If-Match에 연결하고, 호출자 binding은 서버에서도 검사한다. 신규 브라우저27조건·기존 Linux 운영146조건·조회57조건, 관련 pytest Windows206통과/23제외·Linux229통과다. 확인/충돌의 desktop·mobile 화면과 원본 결과를 보존했다. 브라우저 오류 fixture 보강은 별도 `bd1cb17`이며 app/tests는 동일하다. legacy workbench의 이전과 audit cursor 소비는 남아 있고 strict 기본값은 false다.

대시보드 감사 페이지 후속은 [대시보드 감사 페이지 연결](extra-dashboard-paging-20261119.md)이다. `57b1590`에서 `/audit/results?limit=12`와 현재 페이지 `page_cursor`를 연결해 과거100건 밖의 필터 조회·동일 snapshot 다음/이전·저장 전 신원 재검증을 구현했다. 신규 브라우저38·기존 검토27·조회57·Linux 운영146조건, 관련 pytest Windows233통과/25제외·Linux256통과/2제외다. fixture 후속 `72610d0`은 app/tests를 바꾸지 않았다. 위 문단의 cursor 미완료는 이전 시점이며 지금은 완료했다. 자유 검색·분석기는 현재 페이지 범위이고 legacy workbench/다른 목록의 이전은 남아 있다.

CLI 후속은 [검토 CLI의 서버 호출 신원 연결](extra-cli-review-binding-20261119.md)이다. 구현 `a293c80`에서 최종 신원 확인 직후 같은 키의 subject가 바뀌어도 서버가 저장 전에403으로 거부하도록 조회 binding을 PATCH에 연결했다. 변경 전 새 재현1건은 실패했고, 개선 후 새26건을 포함해 Windows217통과/3제외·Linux220통과다. 스냅샷 v2를 사용하며 v1은 자동 변환하지 않는다. 새 파일로 prepare하고 내용을 다시 확인해야 한다. 서버·UI·모델은 변경하지 않았다.

서버 정책 후속은 [서버 검토 필수화 선택 정책](extra-server-review-policy-20261119.md)이다. 구현 `d461b5f`에서 SQLite·API key/OIDC·If-Match 설정을 전제로 `AUDIT_REVIEW_REQUIRE_IDENTITY=true`를 지원한다. 누락428·현재 신원/권한·저장 전 정책 강화·CAS 검사를 확인했다. Windows250통과/3제외·Linux253통과, 필수 모드 실제 대시보드29·워크벤치34조건 통과다. 기본값 false와 실제 운영 설정은 유지하며, 모든 조직 writer/worker의 이관·배포를 완료한 것은 아니다.

최신 후속은 [기존 워크벤치 감사 페이지 탐색](extra-workbench-paging-20261119.md)이다. 기능 `d82052e`·모바일 표시 `79bdf4e`에서 최근8건을 서버12건 페이지/전체 위험도·검토 상태 필터로 이전했다. 이전/다음 조회 기준 보존·신원 전후 검사·만료/오류/지연 응답 차단·현재 상세 재조회를 연결했다. 최종 브라우저45조건, 기능 기준 검토34조건·Windows324통과/5제외·Linux327통과/2제외다. backend/모델/평가 원본은 동일하며, 이 묶음을 새 전체 저장소 회귀나 탐지 성능 개선으로 집계하지 않는다.

## 기준과 실행 범위

기존 워크벤치 검토도 [별도 후속](extra-workbench-review-20261119.md)으로 연결했다. frontend `6c0100f`·대비 보강 `1b8233d`이며 backend는 변경하지 않았다. 개별 인증·상세 ETag/caller binding·확인 후 저장·연결 변경 시 이전 화면/요청 폐기를 구현했다. 워크벤치 실제 브라우저32조건·기존 대시보드 검토27조건, 관련 pytest Windows191통과/3제외·Linux194통과다. 워크벤치의 검토 이전은 완료했다. 당시 남긴 CLI는 위 후속으로 연결했고, 당시 남긴 워크벤치 페이지 이전은 위 최신 후속에서 완료했다. 다른 custom client의 조직 배포 인수는 남아 있다.

오전08:00 시점 app 기준은 `3165fc1`, 검토 연결은 `bef9a97`, 최신 감사 페이지 연결은 `57b1590`이다. 오전 당시 로컬의 `origin/main=e058bca`보다35개 commit이 앞섰다는 비교는 그 시점 기록이다. 원격을 새로 조회한 결과가 아니며 이번 작업을 push·CI·main/aitest 병합하지 않았다. 실행은 무료 로컬 Python·WSL·loopback HTTP/systemd다. AWS·유료 모델 API와 미뤄둔 실제8시간 soak는 실행하지 않았다.

최신 Linux 전체 실행은 8,411통과·2실패·4제외로 종료됐다. 감사 손상 조회를 빈 목록으로 기대하던 두 테스트를 수정한 뒤 관련 Linux53건·Windows75건이 통과했다. 새 전체 실행을 모두 통과했다고 표현하지 않는다. [원본 결과와 수정 후 재검증](extra-local-validation-20261119.md)을 함께 읽는다.

## 구현하고 검증한 흐름

| 영역 | 현재 동작 | 근거 |
|---|---|---|
| 실행 근거와 HTTP 분석 | 신뢰된 수집기의 짧은 실행 참조만 HTTP로 선택. tenant·caller·만료·현재 세션/정책을 재검증하고 advisory 분석·사람 검토·감사로 연결. local/test 경로이며 production에서 이 native 분석 경로는 비활성 | [HTTP 기본](extra-native-http-audit-20261118.md), [공유 참조](extra-shared-native-analysis-20261118.md) |
| 여러 worker의 감사 | 기존 JSONL shard를 검증해 통합 조회하는 모드와, 별도 SQLite 공동 writer 모드 제공. SQLite는 단일 chain 트랜잭션·review CAS·동일 analysis 재시도 중복 제거 | [federation](extra-audit-federation-20261119.md), [공동 writer](extra-transactional-audit-20261119.md) |
| 읽기·페이지·행 보존 | 전체 chain 검증을 생략하지 않고 compact scan. tenant/필터/source에 묶인 암호화 cursor. 반환할 분석이 실제 자기 감사 파일/DB에 남아 있는지도 다시 증명 | [페이지](extra-audit-paging-20261119.md), [SQLite 행](extra-analysis-row-preservation-20261119.md), [JSONL 행](extra-jsonl-row-preservation-20261119.md) |
| 백업·복원·rollback 기준 | 검증 이관, AES-GCM 백업, 새 경로 복원, pinned 최소 checkpoint·단조 증가 검증·runtime guard. 원본 자동 삭제나 복원본 자동 활성화 없음 | [이관/백업](extra-audit-transfer-backup-20261119.md), [checkpoint](extra-audit-checkpoint-progression-20261119.md), [runtime guard](extra-runtime-audit-checkpoint-20261119.md) |
| 현재 caller와 취소 | 초기 인증·분석·감사 조회 한도, I/O 전후 현재 신원/정책 확인. 취소 후 실제 worker가 끝날 때까지 자원 소유권 유지. 커밋된 감사 이력과 성공 응답 전달을 구분 | [조회/검토](extra-audit-query-admission-20261119.md), [일반 분석](extra-analysis-caller-boundary-20261119.md), [초기 인증](extra-authentication-admission-20261119.md) |
| SDK와 평가 자원 | 요청별 SDK 권한 범위와 checked token retry. 평가 사례의 admin/공용 한도, fatal 시 sibling settle, 요청 소유 client close. 공유 provider 첫 생성 직렬화·off-loop·취소 관리 | [SDK](extra-caller-sdk-retry-20261119.md), [평가 권한](extra-evaluation-authority-20261119.md), [평가 자원](extra-evaluation-runtime-20261119.md), [공유 생성](extra-cached-provider-setup-20261119.md) |

추가로 [HTTP 조건부 검토·자기 검토 행 보존](extra-audit-review-boundary-20261119.md)과 [JSONL 현재 디스크 검증·JSON 숫자/불리언 구분](extra-jsonl-query-source-20261119.md)을 구현했다. 최신 systemd54조건도 [새 실행](infrastructure-results/extra-local-validation-20261119-systemd.json)에서 다시 확인했다. 과거 묶음과 합산하지 않는다.

세부 보고서의 “미구현/다음 작업”은 **그 보고서 작성 시점**이다. 예를 들어 JSONL federation 자체에 여러 파일의 전역 원자적 스냅샷을 구현한 것은 아니지만, 별도 SQLite backend로 공동 transactional writer를 추가했다. 이 두 주장을 같은 것으로 읽으면 안 된다.

## 종료된 검증과 성능 지표

이전 관련 묶음은 Windows732통과·20제외, Linux750통과·2제외다. SQLite 다중 프로세스 쓰기·commit 전후 kill·checkpoint·암호화 복원 시험도 포함한다. [원본 XML/소스 지문과 시험 파일 목록](infrastructure-results/extra-cached-provider-setup-20261119.json)을 보존했다. 그 뒤의 작은 Hybrid 주입 adapter 수정은 신규2건 포함 Windows51건 집중 시험으로 검증했다. [별도 결과](infrastructure-results/extra-hybrid-adapter-ownership-20261119.json).

최근 실제 systemd/ptrace·소유 HTTP worker 강제 종료/재시작·공유 참조·cursor·감사 백업/복원 인수는54조건 통과다. [최신 실제 run](infrastructure-results/extra-local-validation-20261119-systemd.json). 이54조건은 provider stub을 사용하며, OS별 pytest 사례나 새 모델 성능 평가 수와 합산하지 않는다.

기존 실제 API **합성 개발360건**의 지표는 TP163·FP6·FN17·TN174, 정밀도96.45%·재현율90.56%·F1 93.41%·보수적 오탐률3.33%다. [원래 성능 보고서](llm-operation-evidence-20261117.md). 이번 인프라·권한·자원 보강으로 이 지표를 다시 측정하거나 바꾸지 않았다. 독립 운영 성능95% 달성으로 보고하지 않는다.

## 남은 항목

| 항목 | 현재 한계/다음 확인 |
|---|---|
| 전체 회귀 | 전체 실행 종료. 두 기대값 수정 후 관련 재검증 통과. 수정 후 새 전체 실행·Windows 전체 플랫폼 정리는 별도 미실행 |
| 사람의 오래된 검토 화면 | 자체 대시보드·기존 워크벤치·CLI 모두 ETag와 서버 caller binding 연결 완료. CLI v1 파일은 새 prepare 필요. 서버 caller binding 필수화 선택 정책도 추가. 다른 custom client 목록화/이전·모든 worker에 동일 정책 배포 인수는 남아 있으며 두 strict 기본값 false 유지 |
| 대시보드 전체 검색/다른 목록 | 자체 대시보드와 기존 워크벤치의 감사 cursor 소비 완료. 워크벤치 위험도/검토 상태는 서버 전체 범위. 대시보드 자유 검색·분석기는 현재 페이지 범위. 다른 목록 페이지 이전·서버 전체 자유 검색 설계는 남음 |
| 독립 최신성 증명 | checkpoint 파일/DB/pin 전체를 함께 되돌릴 수 있는 관리자에 대한 독립 witness/WORM 미완료. 최소 history 검증을 전체 최신성 보장으로 표현하지 않음 |
| 실제 기업 신원 | 로컬 signed OIDC/JWKS·key 계정 철회 시험은 완료했지만 외부 기업 SSO/MFA·online token revocation은 미완료 |
| 다른 장애 종류 | 소유 process kill/restart와 local SQLite 복구 검증은 OS 전원 단절·다중 호스트 장애·네트워크 저장소 내구성 검증을 대체하지 않음 |
| 긴 운영 시험 | 미뤄둔 실제8시간 soak는 미실행. 짧은 제어 시험이나 fake clock으로 완료 처리하지 않음 |
| 모델 목표 수치 | 재현율/F1 목표 미달 유지. 새 독립 자료와 실제 모델 평가가 필요하며 이번 무료 로컬 시험에서 달성했다고 바꾸지 않음 |

다음 구현에서는 같은 감사/권한 흐름의 실제 빈 경계를 우선 다루고, 기존 판정·평가 정답이나 결과를 성공 수치에 맞춰 수정하지 않는다.
