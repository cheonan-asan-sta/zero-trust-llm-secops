# extra 로컬 개발 현황과 남은 검증

2026-11-19 오전 08:00 시간 상한으로 개발을 마감했다. 소유 시험 실행은 종료됐으며 아래 미완료 항목은 다음 작업으로 남긴다. 이번 작업의 소스·시험·문서는 로컬 extra에만 저장했다.

2026-11-19 오전 개발 기록. 이 문서는 세부 보고서의 과거 수치/남은 항목을 현재 구현과 구분해 읽기 위한 시작점이다. 주차별 완료나 기말 발표 성과 전체를 새로 판정하는 문서는 아니다.

## 오전08:00 이후 후속

운영자의 실제 검토 client를 연결했다. [ETag·신원·HTTPS/mTLS 검토 CLI](extra-operator-review-client-20261119.md)는 조회 snapshot을 만든 뒤 명시적으로 검토하며 stale412·신원/tenant 변경·응답 유실에 자동 우회/재시도하지 않는다. 구현은 `c0a8108`의 scripts/tests이며 서버·모델·UI 코드는 변경하지 않았다. 기존 오전08:00 종료 기록은 그 작업 시간대의 기록으로 보존한다.

## 기준과 실행 범위

구현 기준은 `extra`의 `3165fc1`다. 당시 로컬에 저장된 `origin/main=e058bca`보다35개 commit이 앞섰고 이후 테스트·문서 보강은 별도 로컬 commit이다. 원격을 새로 조회한 결과가 아니며 이번 작업을 push·CI·main/aitest 병합하지 않았다. 실행은 무료 로컬 Python·WSL·loopback HTTP/systemd다. AWS·유료 모델 API와 미뤄둔 실제8시간 soak는 실행하지 않았다.

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
| 사람의 오래된 검토 화면 | SQLite 서버와 운영자 검토 CLI의 ETag/If-Match 연결 완료. UI 소비는 남음. strict 기본 false 유지 |
| 대시보드 페이지 소비 | 새 `/audit/results` API를 자체 대시보드에서 사용하도록 바꾸는 것은 아직 남음. API 구현과 UI 적용을 구분 |
| 독립 최신성 증명 | checkpoint 파일/DB/pin 전체를 함께 되돌릴 수 있는 관리자에 대한 독립 witness/WORM 미완료. 최소 history 검증을 전체 최신성 보장으로 표현하지 않음 |
| 실제 기업 신원 | 로컬 signed OIDC/JWKS·key 계정 철회 시험은 완료했지만 외부 기업 SSO/MFA·online token revocation은 미완료 |
| 다른 장애 종류 | 소유 process kill/restart와 local SQLite 복구 검증은 OS 전원 단절·다중 호스트 장애·네트워크 저장소 내구성 검증을 대체하지 않음 |
| 긴 운영 시험 | 미뤄둔 실제8시간 soak는 미실행. 짧은 제어 시험이나 fake clock으로 완료 처리하지 않음 |
| 모델 목표 수치 | 재현율/F1 목표 미달 유지. 새 독립 자료와 실제 모델 평가가 필요하며 이번 무료 로컬 시험에서 달성했다고 바꾸지 않음 |

다음 구현에서는 같은 감사/권한 흐름의 실제 빈 경계를 우선 다루고, 기존 판정·평가 정답이나 결과를 성공 수치에 맞춰 수정하지 않는다.
