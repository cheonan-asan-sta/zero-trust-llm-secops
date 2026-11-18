# 선택형 공동 감사 writer

> 후속: [기존 자료 검증 이관·암호화 백업·새 경로 복원](extra-audit-transfer-backup-20261119.md)을 추가했다. 아래는 공동 writer를 처음 구현한 단계의 결과이며 이관과 복원 경계는 후속 문서를 기준으로 한다.

2026-11-19 · extra · 오전 08:00 KST까지 이어가는 로컬 개발의 다음 묶음이다. 유료 API/AWS/push/CI/병합은 수행하지 않는다.

## 구현

`AUDIT_BACKEND=sqlite`와 선택적인 `AUDIT_DB_PATH`로 로컬 공동 writer를 사용한다. 경로를 생략하면 `AUDIT_LOG_PATH`의 확장자를 `.sqlite3`로 바꾼 새 파일을 사용한다. 기존 JSONL 기본값과 DynamoDB 동작은 유지하며 과거 파일을 자동 이관하거나 삭제하지 않는다. 정책 DB/JSONL 원본과 같은 경로를 거부하고 다른 서비스 테이블이 있는 DB에도 새 감사 테이블을 만들지 않는다.

각 SQLite 쓰기는 `BEGIN IMMEDIATE`와 `synchronous=FULL`을 사용한다. 기존 체인의 연속 sequence·이전 해시·payload 해시와 별도 durable head를 검증한 뒤 같은 트랜잭션에서 append/head를 확정한다. worker별 마지막 해시 캐시가 없어 독립 프로세스의 쓰기도 하나의 체인에 직렬화된다. 조회는 읽기 전용 트랜잭션에서 체인을 검증하며 여러 worker가 같은 결과·metrics를 읽는다.

동일 analysis ID의 동일 payload 재시도는 추가 행을 만들지 않는다. 검토 변경은 `save_review(new, expected)`가 현재 기록 및 해당 이벤트의 최신 분석과 expected가 같은 경우에만 확정한다. 불변 필드 변경, 오래된 기록, 조건 없는 덮어쓰기는 거부한다. HTTP 검토 중 경쟁 변경은 409로 반환한다. 검토 변경 뒤 집계는 같은 analysis를 중복 계산하지 않는다.

이는 서버가 PATCH 처리 중 읽은 기록에 대한 CAS다. 오래된 화면의 클라이언트 ETag/버전 precondition을 새로 제공한 것은 아니다. JSONL/federated backend의 검토 쓰기를 공동 트랜잭션으로 바꾼 것도 아니다. 이 동시 쓰기 보장은 선택한 SQLite backend에 적용된다.

native HTTP 분석은 기존 정책 가드·감사 저장·반환 전 현재 신원/근거 재검증을 재사용한다. 알려진 SQLite 체인 손상은 모델 호출 전 차단하고 저장 실패를 성공 응답으로 바꾸지 않는다. 조회 실패는 일반화된 503으로 반환한다.

## 검증

새 SQLite 시험 20건이 Windows에서 통과했다. 실제 독립 Python 프로세스 4개가 동시에 하나의 DB에 기록하고 전역 체인이 유지되는 것을 확인했다. 경쟁 검토 4개 중 1개만 확정되고 나머지는 conflict로 거부됐다.

실제 자식 프로세스가 commit 전/후에 정지점을 알리면 부모가 프로세스를 강제 종료했다. 새 인스턴스 초기화 후 미확정 행은 rollback되고 확정 행은 남았으며, 새 append도 정상 체인으로 이어졌다. OS 전원 단절/호스트 재부팅/네트워크 파일시스템 내구성을 시험한 것은 아니다.

HTTP 시험에는 native 분석 결과 저장·다른 인스턴스 조회·검토 반영, 검토 경쟁 409, 손상 시 모델 호출 0과 조회 503이 포함된다. 앞선 관련 Windows 묶음 46건 통과 이후 두 시험을 추가해 최신 집중 20건을 실행했다. Linux 확대 결과는 [검증 요약](infrastructure-results/extra-transactional-audit-20261119.json)에 남긴다. 서로 겹치는 결과를 합산하지 않는다.

## 다음 작업과 한계

- 기존 JSONL/federated 자료의 검증된 명시적 이관 및 새 저장소 backup/restore 검증
- 중단/취소·동시 작업·부하·재시도 경계와 실제 native 실행의 새 backend 인수
- 현재는 매 transaction에서 전체 체인을 검사한다. 최대 100,000행·payload 합계 256MiB 제한이 있으며 대규모 인덱싱/검증 비용 개선이 남아 있다.
- 별도 head도 같은 DB에 있다. 마지막 행만 삭제하거나 head와 불일치하는 손상은 감지하지만 전체 DB/head를 함께 rollback하거나 해시를 재계산하는 관리자에 대한 원격 증명은 아니다.
- 기본 backend는 바꾸지 않았다. 실제 모델 품질이나 F1은 새로 평가하지 않았다. 8시간 연속 시험도 자동 시작하지 않았다.
