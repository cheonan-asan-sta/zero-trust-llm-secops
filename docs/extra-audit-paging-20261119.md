# 검증된 감사 기록의 tenant별 페이지 조회

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 새 API

`GET /audit/results?limit=20&review_status=PENDING&risk_level=LOW`

현재 인증된 viewer 이상 권한으로 자기 tenant의 감사 결과만 읽는다. `limit`는1~100이며 필터는 전체 tenant 결과에 먼저 적용한다. 최근100개보다 오래된 일치 기록도 조회할 수 있다. 응답은 `items`, `total_matches`, `next_cursor`, `snapshot_id`, 생성/만료 시각과 `snapshot_mode`를 포함한다. 다음 요청은 같은 필터와 `cursor=<next_cursor>`를 사용한다. cursor가 없으면 마지막 페이지다.

기존 `/results` 배열·`/results/{event_id}` 상세 조회는 유지한다. 초기 후보 `/results/page`는 `event_id=page`와 충돌하는 회귀를 재현해 폐기했다. 최종 주소 `/audit/results`는 기존 이벤트 이름을 예약하지 않는다. 자체 대시보드는 아직 이 새 API를 소비하도록 변경하지 않았다.

## 저장소별 일관성

| Backend | 페이지 동작 |
|---|---|
| SQLite | 첫 페이지의 검증된 seq/digest prefix를 고정한다. 새 기록·검토가 추가돼도 그 시점의 이전 상태를 이어 읽는다. 각 요청은 prefix 이후를 포함한 **현재 전체 체인**도 검증한다. |
| 단일 JSONL | 매번 bounded 파일 읽기·체인/모델/검토 이력을 검증한다. 자기 tenant의 직렬화된 결과 view가 바뀌면409로 새 시작을 요구한다. 다른 tenant의 정상 추가는 자기 페이지를 무효화하지 않는다. |
| 연합 JSONL | 기존 전체 shard 검증·durable manifest checkpoint를 사용하고 자기 tenant view가 바뀌면409다. 여러 파일의 전역 원자적 snapshot을 주장하지 않는다. |

SQLite는 compact 검증 중 필요한 tenant/필터/고정 prefix의 행 위치만 수집하고, 선택한 최대100개 결과를 같은 read transaction에서 읽는다. legacy GET/metrics/CAS writer의 기존 동작은 바꾸지 않았다. JSONL은 view를 materialize하므로 대규모 읽기 비용이 남는다. 두 JSONL 경로의 새 페이지 API는 unhashed legacy를503으로 거부한다. 기존 legacy 조회 호환성은 유지하며 이관은 기존 명시적 migration 절차를 사용한다.

DynamoDB 페이지 구현은 포함하지 않았다. 해당 backend에서 이 API는 AWS 호출 없이501을 반환한다. 다른 backend로 조용히 전환하거나 데이터를 자동 이관하지 않는다.

## 커서와 권한

커서는 AES-256-GCM으로 암호화/인증한다. 전용32바이트 master에서 HKDF의 서로 다른 purpose로 암호화 키와 snapshot ID HMAC 키를 유도한다. tenant·필터·backend·고정 source 식별·prefix/view·위치를 포함하며, 원래900초 만료를 다음 페이지에서 연장하지 않는다. 원시 head/전역 row 수·파일 경로는 응답이나 평문 커서로 노출하지 않는다. nonce는 매번 새로 만든다.

커서는 접근 권한이 아니다. 모든 HTTP 요청은 기존 인증·viewer RBAC·tenant 격리를 거치며, 기존 감사 query 슬롯과 I/O 전후 현재 계정/OIDC 만료·serving store 재검증을 사용한다. 취소된 page 요청도 디스크 작업이 끝나기 전 슬롯을 반환하지 않는다. 공통 미들웨어의 `Cache-Control: no-store`를 재사용한다.

| 상태 | 의미 |
|---|---|
| 400 | 커서 변조·다른 키·tenant/필터/source scope 불일치 |
| 409 | SQLite prefix가 없어졌거나 JSONL의 자기 view가 바뀜; 첫 페이지부터 명시적 재시작 |
| 410 | 커서 만료/시계 역행; 자동 재시작이나 만료 연장 없음 |
| 422 | 잘못된 limit·과도한/잘못 인코딩된 cursor·enum 요청 |
| 503 | 포화·무결성 실패·키 철회/변경 등; 부분 결과 반환 없음 |
| 501 | 지원하지 않는 cloud paging backend; 이 경로에서 AWS 호출 없음 |

인증 거부는 기존401/403이다. 이 API의 `historical_audit_snapshot=true`는 현재 권한·최신 조치 승인과 구분하기 위한 표시다. SQLite의 `snapshot_created_at`는 첫 요청의 커서 생성 시각이며, 모든 원본 사건의 발생 시각이나 DB commit 시각을 대신하지 않는다.

## worker/재시작 시 키

설정이 없으면 프로세스별 휘발성 키를 사용한다. 재시작/다른 worker에서는 그 커서가400이 되므로, 여러 worker나 재시작 후 이어 읽기가 필요하면 **전용 private32바이트 키 파일과 SHA-256 pin을 함께** 설정한다.

```dotenv
AUDIT_CURSOR_KEY_PATH=<프로젝트/Git 밖의 private32바이트 파일>
AUDIT_CURSOR_KEY_SHA256=<파일의 소문자 SHA-256>
```

파일은 새로 자동 발급하지 않는다. 기존 backup key reader의 regular file/길이/pin·POSIX 소유자/권한·link 제한을 재사용한다. 설정은 두 항목이 모두 있어야 하고, 잘못된 파일/pin은 시작 시 실패한다. 매 page 전후 다시 읽어 철회를 확인하며 기존 메모리 키로 우회하지 않는다. 변경된 키를 쓰려면 새 pin/설정으로 reader를 시작하며, 이전 커서의 grace key ring은 구현하지 않았다. 다른 용도의 API 키/CA 키를 재사용하지 않는다.

## 검증과 한계

최근100건을 넘는125개 기록의 중복 없는 순회·오래된 필터 일치·세 backend의 tenant 격리·다른 tenant 정상 추가·자기 view 변경·SQLite 역사적 검토 상태·prefix 교체·anchor 이후 다른 tenant의 chain 변조를 확인한다. 커서 변조/크기/scope/만료·키 철회·기존 event_id 주소·실제 HTTP 인증/취소/503·실제 별도 reader 프로세스의 고정 키 재개도 시험한다. 초기 HTTP 헤더 중복과 테스트 실행기의 tuple 인자 문제는 수정한 뒤 재검증했다.

페이지 기능 첫 검증은 신규61개 통과/적용 대상이 아닌2개 제외를 포함해 **Windows 관련165건 통과·2건 제외, Linux 확대275건 통과·2건 제외**다. 제외2개는 SQLite에 적용하지 않는 JSONL view 변경 사례다. 해당 시점의 XML/소스 지문은 [검증 기록](infrastructure-results/extra-audit-paging-20261119.json)에 남긴다. OS별 중복 사례를 독립 수로 합산하지 않는다. 이후 HTTP worker cursor 재개와 현재 key readiness를 추가 검증했다([최신47조건 인수](extra-http-cursor-recovery-20261119.md)).

```sh
python -m pytest tests/test_audit_paging.py tests/test_audit_paging_http.py tests/test_audit_query_admission.py tests/test_compact_audit_integrity.py tests/test_sqlite_audit.py tests/test_federated_audit.py -q
```

첫 별도 프로세스 재개는 direct reader 호출이었다. 후속에서 실제 HTTP worker3개를 강제 종료·재기동해 같은 cursor를 TCP HTTP로 이어 읽고 현재 key 오류가 readiness에도 나타나는 것을 확인했다([재현과 범위](extra-http-cursor-recovery-20261119.md)). JSONL 전역 transaction·전원 단절·다중 호스트·원격 WORM·독립 rollback 방지와 연기한8시간 시험은 미완료다. 새 페이지도 전체 검증을 하므로 HTTP 처리량/최악 메모리 상한을 새로 입증한 것은 아니다.

모델/프롬프트/탐지 판정·평가 원본·정답·예측은 바꾸지 않았고 새 F1/오탐·미탐 평가는 없다.
