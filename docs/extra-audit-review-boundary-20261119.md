# 감사 검토 버전·정확한 저장 행·JSON 동일성 보강

2026-11-19 · extra · 로컬 무료 개발. 유료 API/AWS·push·CI·병합 없음.

## 문제와 변경

오래된 검토 화면의 요청이 다른 사람의 최신 검토를 덮어쓰는 사례2건, 검토 저장 직후 행을 잃어도 성공을 전달하는 사례3건, Python의 `True == 1`/`False == 0` 비교로 불변 JSON trace 변경을 허용하는 사례8건을 재현했다. 이는 모델 정답/성능 평가가 아니라 감사·동시성·반환 계약 시험이다. trace 시험은 논리적으로 나중인 검토 시각을 명시해 Windows 시계 해상도 때문에 다른 검증에 먼저 걸리지 않도록 했다.

검토 응답 전 기존 `verify_saved(updated)`를 query slot 안에서 실행한다. SQLite는 전체 현재 chain과 정확한 검토 행을 같은 read transaction에서 확인한다. JSONL/federated는 실제 자기 writer 파일의 해시 행을 다시 확인한다. 다른 shard의 복사본은 잃어버린 자기 행을 대체하지 않는다. 이후 정상 검토나 같은 event의 새 분석이 생겨도 자기 검토 행이 보존돼 있으면 성공할 수 있다. 단순 최신 조회와 비교해 정상 동시 쓰기를 오탐 거부하지 않는다.

추가된 proof I/O 전후에도 현재 caller와 선택한 store를 재확인한다. 취소 후에도 실제 worker가 끝나기 전 query slot을 반환하지 않는다. 이미 커밋한 이력은 취소/철회 때문에 지우지 않는다. 검증한 read snapshot 이후 외부 변경까지 HTTP 전송과 원자적으로 묶었다는 뜻은 아니다.

SQLite의 review core·expected CAS·동일 ID 재시도, JSONL 검증, federation merge, 명시적 이관의 동일성 비교를 canonical JSON wire에 맞췄다. 불변 trace의 숫자/불리언 차이는 거부하고, tuple→array·정수 mapping key→문자열처럼 같은 JSON 표현은 정상 처리한다. 전역 analysis ID의 충돌 거부와 기존 검토 시각/상태 전이 제약은 유지한다. 원본과 모든 해시를 함께 재작성하는 관리자를 막는 독립 witness는 아니다.

## HTTP 검토 조건

`GET /results/{event_id}`와 성공한 검토 PATCH가 인용부호를 포함한 strong `ETag`를 반환한다. 기존 `Cache-Control: no-store`는 middleware가 유지한다. ETag는 응답 표현 전체에 묶이며 인증 토큰이나 사람이 실제로 내용을 읽었다는 증명은 아니다.

```text
GET /results/<event_id>
ETag: "r1-<64자리 SHA-256>"

PATCH /results/<event_id>/review
If-Match: "r1-<GET에서 받은 값>"
{"status":"IN_REVIEW","note":"확인한 버전에 대한 검토"}
```

SQLite에서 일치하면 기존 CAS로 저장한다. stale/replayed tag, 같은 event의 새 analysis, 읽은 뒤 다른 writer가 이긴 경쟁은412다. role/tenant·현재 신원 검증을 우회하지 않는다. wildcard/weak/list/중복/과대 tag는400이며 감사 I/O 전에 거부한다. source 손상/저장 행 유실은503이다.

기존 client의 header 없는 검토는 기본 유지한다. 다음 설정으로 필수화할 수 있다.

```dotenv
AUDIT_BACKEND=sqlite
AUDIT_REVIEW_REQUIRE_IF_MATCH=true
```

필수화 뒤 누락은428이다. SQLite 외 backend에서 필수화를 설정하면 시작 검증이 실패한다. JSONL/federated가 조건부 요청을 받으면503으로 거부하고 조용히 일반 쓰기로 바꾸지 않는다. **자체 대시보드는 아직 If-Match를 보내도록 변경하지 않았다. client 적용/검증 후 필수화해야 한다.** HTTP 조건을 실제 모든 검토 client에 기본 적용했다고 주장하지 않는다.

## 전체 회귀에서 확인한 통합 문제

기준 구현 `25adf8c` 전체 시험은 Windows7,722통과·73실패·21오류·533제외, native Linux8,321통과·4실패·19오류·4제외였다. [원본 지문/분류](infrastructure-results/extra-audit-review-boundary-20261119.json)를 보존한다. 전체를 통과한 상태로 기록하지 않는다. 공유 폴더 Linux 중단197건과 실행 준비 경로 오류로 중단한 별도 run도 완전한 시험으로 계산하지 않는다.

확인한 공통 원인은 다음과 같이 보완했다.

- 운영 콘솔 catalog에 native 분석 경로가 빠져 있었다. native 분석과 감사 페이지 항목을 추가하고 보안 통제 목록/상세의 표시 role도 실제 admin dependency와 맞췄다. 권한을 부여하는 목록은 아니다.
- 분석 부하 시험은 새 초기 인증 한도 때문에32요청 모두가 분석 queue에 도달한다는 전제가 깨졌다. 이 시험만 인증 한도16/대기2초를 명시해 분석4슬롯·28거부 계약을 계속 검사한다. 실제 인증 기본4/0.05초는 바꾸지 않고 기존30건의 인증 포화/취소 시험을 함께 실행한다.
- legacy 복원 **unit fixture**가 서로 다른 tenant에 같은 전역 analysis ID를 사용했다. fixture ID에 tenant를 포함해 유일하게 만들었다. 운영의 ID 충돌 거부를 완화하지 않았고, 복원·권한 검증 assert나 평가 원본/정답/예측은 바꾸지 않았다.
- 유지관리 protocol의32,769바이트 공격 입력이 pytest node ID에도 복사돼 Windows 환경 변수 한도를 넘었다. 짧은 명시적 case ID만 추가했다. 공격 payload와 거부 검증은 유지했다.

POSIX syscall·권한·peer credential의 Windows 전체 실패는 별도 지원 범위/검증 항목으로 남긴다. native Linux 전체 재검증으로 실제 서버 환경의 결과를 확인한다.

## 종료된 시험과 다음 검증

신규45건은 조건부 검토21·저장 행 보존10·JSON wire 동일성12·catalog/RBAC2건이다. 기존 인증30건·실제 JWT/JWKS의 모의 provider 부하1건과 묶어 Windows76건 통과했다. 유지관리 protocol은 별도35통과·POSIX2제외다. 앞선 감사/복원121통과·2제외와 중복 합산하지 않는다. [시험 파일/원본 XML/소스 지문](infrastructure-results/extra-audit-review-boundary-20261119.json).

```sh
python -m pytest tests/test_audit_review_preconditions.py tests/test_audit_review_preservation.py tests/test_audit_review_wire_identity.py tests/test_dashboard_audit_catalog.py tests/test_evidence_review_load.py tests/test_authentication_admission.py -q
```

최신 native Linux 전체·Windows 관련 확대·systemd 인수는 이 묶음 저장 후 재검증한다. 모델 prompt·판정·평가 원본/정답/예측·기존 F1/오탐/미탐은 갱신하지 않았다. 실제 기업 SSO/online revocation, 독립 witness/WORM, 다중 호스트·전원 단절·미뤄둔8시간 soak는 남아 있다.

후속: [JSONL 현재 source 조회·숫자/불리언 구분](extra-jsonl-query-source-20261119.md)을 추가했다. 위 수치/예정 항목은 당시 기록이다.
