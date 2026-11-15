# 실행 복구 상태의 일관된 암호화 묶음 백업

## 해결하는 문제

이전 outbox 백업은 완성된 실행 원본을 보관한다. 부모 프로세스가 seal 전에 사라진 실행의 intent, 앱의 이미 소비한 grant, 브로커의 bound/uncertain 기록까지 같은 상태로 보존하지는 않았다. 이 기능은 별도 형식 `zt-exec-recovery-snapshot-1`로 그 상태를 묶는다. 캡처 DB에 가짜 이벤트를 넣어 서로 다른 자료를 억지로 저장하지 않는다.

대상은 관리자가 선택한 **단일 테넌트 앱 DB·단일 서버/unit 브로커 DB**와 intent 저널이다. 다른 테넌트/서버/unit 기록이 섞인 DB, 예상하지 않은 SQLite 테이블·뷰·트리거, 현재 신뢰/정책과 맞지 않는 원본은 거부한다. 운영의 다중 테넌트 DB 전체 백업을 대체하지 않는다.

## 일관성·보안 경계

1. 소유자 전용 intent 잠금 → 브로커 `BEGIN IMMEDIATE` → 기존 앱 검증 트랜잭션 순서로 잠근다. 브로커에 launching 상태가 하나라도 있으면 백업을 거부한다. 새로운 dispatch의 상태 전환은 이 DB 잠금에 막힌다. intent·브로커·앱의 협력 writer 계약을 따르지 않는 root/외부 writer까지 막는 분산 트랜잭션은 아니다.
2. 앱·브로커는 잠금 안에서 동일한 SQLite 상태를 직렬화한다. WAL 파일을 단순 복사하지 않는다. WAL 모드이면 별도의 읽기 연결에서 SQLite backup으로0700 임시 디렉터리의0600 사본을 만들고 그 사본만 standalone 모드로 바꾼다. 원래 DB의 WAL 설정은 유지하며, 새 사본의 앱 chain/head·브로커 행이 잠금 안에서 읽은 값과 같아야 한다. 이 경우 복원 대상은 일관된 standalone 스냅샷이며 원래 WAL 파일/페이지 표현 전체의 byte 동일 사본은 아니다. 원래 chain/세션 상태 검증과 앱 access hash·호출자·세션·정책·원본 seal 결합을 확인한다. 각 DB 최대16MiB, 스냅샷 최대64MiB, intent 최대10,000건이다. 한도나 수집 기한을 넘기면 부분 성공으로 처리하지 않는다.
3. intent.json, 선택적인 완성 capture.json, 설정된 최대16개 worker 디렉터리의 capture.json만 읽는다. request.json·명령 argv·키 디렉터리·토큰 파일은 재귀 복사하지 않는다. worker 경로가 재사용되어 다른 요청의 파일이면 `reused`, 파일이 없으면 `missing`을 남긴다. worker 파일 존재를 승인 또는 독립 실행 증명으로 승격하지 않는다.
4. 원래 앱 DB에 있는 grant hash와 회수/소비 이력은 복원 상태의 일부다. 원문 grant token·OIDC token·서명 개인키·복구 키를 스냅샷에 추가하지 않는다. 사용자 식별자와 서명된 경로 등 원본 상태 자체에는 민감한 정보가 있으므로 평문 staging/복원 디렉터리는0700, 파일은0600이다.
5. AES-256-GCM payload와 manifest를 만들고, **원본 트리·패키지 밖의 checkpoint** SHA를 외부에서 고정한다. nonce·키 ID·범위·스냅샷 hash/시각은 AAD에 결속한다. 복구 키는 별도32바이트 입력이며 저장·출력하지 않는다. 최신 외부 checkpoint로 과거의 유효한 다른 패키지를 복원하려 하면 거부한다. 관리자가 오래된 pin까지 함께 되돌리는 특권 행위는 이 로컬 도구의 보장 밖이다.

## 격리 복원·재검증

복원은 현재 공개 신뢰/정책, 외부 checkpoint, ciphertext hash/GCM, 원본 intent/seal과 DB 상호 결합을 전부 검증한 뒤 **새 격리 디렉터리**를 만든다. 원래 signed worker 절대 경로를 따라가거나 원래 앱/브로커/intent 경로에 쓰지 않는다. 기존 출력은 덮어쓰지 않는다. 완료 marker `restore.json`을 마지막에 쓰며, 쓰다 중단된 디렉터리는 유효 복원본으로 인정하지 않는다.

복원 파일 inventory와 원본 스냅샷 hash를 receipt에 결속한다. `verify_review`는 복구 키 없이 현재 공개 신뢰와 외부 receipt/checkpoint pin으로 모든 복원 바이트를 다시 조립·대조하고 서명·DB·미완료 상태를 재검증한다. 기존 정책 DB를 앱 서비스로 활성화하지 않으며, grant 환불·재발급·명령 실행·누락된 seal 생성 API는 없다. 신뢰된 운영자가 검토 사본을 별도로 강제 활성화하는 행위까지 막았다는 뜻은 아니다.

## 실행 방법

로컬 관리 명령은 `python -m scripts.exec_recovery_bundle {backup,restore,verify}`다. 세 하위 명령에 범위(`--tenant/--server/--unit/--source`)와 공개 registry/caller-registry 파일 및 SHA, `--checkpoint`를 지정한다. 기본 호출자 환경은 실제 oidc이며 로컬 fixture만 `--caller-environment local_oidc`를 명시한다.

| 명령 | 추가 입력 | 결과 |
|---|---|---|
| backup | `--intents`, `--broker-db`, `--app-db`, `--worker-directory`(반복 가능), `--key-file`, `--key-id`, `--output`; 필요 시 `--app-policy` | 새 encrypted package와 외부 checkpoint SHA |
| restore | `--package`, `--checkpoint-sha256`, `--key-file`, `--key-id`, `--output` | 새 격리 review와 receipt SHA |
| verify | `--review`, `--receipt-sha256`, `--checkpoint-sha256` | 복원본의 현재 재검증 집계, 복구 키 입력 없음 |

원본 DB와 부모 디렉터리는 사전에 관리자 소유0600/0700으로 준비해야 한다. CLI는 DB를 만들거나 초기화/마이그레이션하지 않는다. backup의 읽기용 객체에는 signer·issue·dispatch·access API가 없다. 기존 앱 검증 트랜잭션만 재사용한다. 키는32바이트0600 파일에서 읽으며 실패 출력은 민감한 경로나 원문 대신 unavailable 집계만 제공한다. 자동 timer·원격 업로드·AWS·유료 API는 없다.

## 로컬 인수와 한계

예비 계약92개와 실제 systemd62조건이 통과했다. 실제 exec6회 중 첫 수동 실행은 intent 도입 전 경로여서 이 묶음의 대상이 아니다. **intent5건 중 완성4건·확인 불가1건**을 백업하고 실제 선택 원본 DB·intent·worker 디렉터리를 제거한 뒤 격리 복원했다. 앱/브로커 DB와 전체 intent/seal 바이트가 일치하고 원래 live 경로는 계속 부재다. worker 경로가 재사용되어 현재1건만 보존 가능한 사실도 숨기지 않는다. 잘못된 복구 키와 실제 ciphertext 변조는 출력 디렉터리 생성 전에 거부됐다.

최종 CLI/프로세스 간 잠금 추가 검증 및 전체 회귀는 진행 중이며, 완료 후 같은 후보의 소스 hash/결과를 추가한다. 최초 외부 도우미의 Linux 스크립트 파일명 오타는 native 시험 시작 전에 실패했다. 프로젝트 코드/기준을 바꾸지 않고 호출 경로만 수정해 같은 동결본에서 실행했으며 최초 로그를 보존했다.

추가 WAL 시험은 처음에 직렬화한 WAL 헤더를 메모리에서 열지 못해 실패했다. 메모리 backup 사본의 journal mode 변경만으로는 standalone 헤더가 만들어지지 않는 실패도 보존했다. 원래 DB 설정을 바꾸거나 헤더 바이트를 수동 수정하지 않고 위의 전용 파일 사본 방식으로 수정한 뒤 관련35개가 통과했다. 외부 집중 selector가 새 CLI 시험 파일을 포함하지 못했던 경우도 기록했고, 같은 소스의 이미 통과한93개를 반복하지 않고 빠진 CLI6개만 별도 실행해 통과했다.

기존 여섯 영역 탐지 정답·임계값·모델을 바꾸지 않는다. 복구/잠금/암호화 조건을 공격 탐지 표본이나 F1로 합산하지 않는다. 실제 조직 SSO·MDM·물리 호스트/외부 저장소 복원·운영 복구키 escrow·다중 writer 절체 인수는 별도다. 8시간/12시간 soak는 계속 유예한다.


## 최종 통합 인수 — 2026-11-16

동일 소스 `4a9f8e206466243a4e15a626d1f79eb8c2f96023383fc6c3019d7140a369b226`로 집중 489개·전체 6,017개·실제 systemd 62조건·실제 복구 관측 10조건을 통과했다. 신규 계약 41개를 포함하며 실패·skip은 0이다. 집중은 전체의 부분집합이다. 관리 CLI 6개와 실제 별도 프로세스의 DB 트랜잭션 경합도 포함한다. 예비 결과를 최종 결과에 합산하지 않는다.

한 검증 실행의 보호 명령 exec 6회 중 intent 5건(완성 4·확인 불가 1)과 현재 일치하는 worker 1건을 묶었다. 선택한 원본 앱/브로커 DB·intent·worker 디렉터리를 실제 제거하고 격리 사본에서 원래 DB/intent/seal 바이트를 확인했다. 이 native 입력은 DELETE DB다. WAL은 단위 시험에서 원래 설정 유지와 동일한 논리 상태의 standalone 복원을 확인했으며 원래 WAL 파일의 byte 동일 사본을 주장하지 않는다. 검토 사본만 만들고 원래 live 경로는 계속 부재다. 원래 첫 수동 exec 1건·기존 live 캡처·공개 trust·나머지 시험 제어 자료가 모두 삭제됐다는 뜻은 아니다.

확인 불가 1건은 그대로이며 grant/승인 재발급·환불·명령 재실행은 0이다. 현재 keyless 재검증은 키 인수를 받지 않지만 같은 신뢰된 부모 프로세스에는 fixture 키 객체도 있다. 별도 OS 계정의 복구 키 없는 주기 관측은 후속 항목이다. 기존 복구 관측 10조건도 실제 원래 보고서로 통과했으며, 새 묶음 자체의 전용 주기 관측/경보 완료와는 구분한다.

기존 v85의 1,681,815건 판정 SHA는 동일하며 새 FP·기존 TP 손실·정답 재열람은 0이다. 공유 감사 F1 0%·FP24/FN6, 웹 감사 F1 80.70%·FP21/FN1, 인증 F1 95.08%·FP0/FN3를 유지한다. 별도 v87 새 멤버 8,908행과 섞지 않으며 원래 여섯 영역 독립 목표는 미달이다.

소유 컨테이너·임시 unit·WSL 소스·개인 시험 상태와 WAL 임시 사본을 정리했다. AWS/유료 API는 0이고 8/12시간 soak는 유예한다. 부모 PR81은 CI 17개 성공 후 aitest `ace85d3`에 병합됐으며 이 작업의 게시/CI/병합은 후속 PR 기록을 따른다. [공개 실행 근거](infrastructure-results/extra-exec-coherent-backup-v89-20261116.json).


## PR83 CI에서 확인한 보관 잠금 경합과 후속 수정

기존 head `e68f0a9`의 CI43743937515에서 execution-mTLS와 종합 test가 실패했다. 안전한 원본 receipt는 `observer_archive / observer_init / collector_busy`였다. 실행 중인 observer와 시험 보관 작업이 같은 비차단 수집 잠금을 경합했다. 다른15개 check 성공을 전체 성공으로 기록하거나 단순 재실행하지 않는다.

`fdd9dd0`은 잠금 정책을 유지하고 시험 소유 observer만 멈춘 후, 정확한 release/image·volume 소유권/미사용 상태를 확인해 한 번의 고정 offline 작업을 수행한다. network none·비root·capability0·NNP·read-only root·제한된 세 volume이며 임의 명령을 받지 않는다. typed receipt 성공·종료0·소유 작업 정리 확인 후에만 원래 observer를 재개한다. 실패/부분 성공에서는 자동 재시도·성공 카운터 치환 없이 멈춘 상태를 유지한다.

새 경계18개를 포함한 집중70개와 실제 Docker mTLS25조건이 통과했다. 실제 보관 compact9/input retire10/server archive30, 권한 없는 입력 거부·중복/강제 종료 재개·관련 접근403/무관200·복원 중단/재개·기존 토큰403/새 토큰200·이력 보존을 확인했다. 소유 시험 자원 정리도 완료했다. 이는 실제 실행의 관측 수치이며 임의로 고정한 운영 보관량 목표가 아니다.

기존6,017개 전체 시험은 이전 고정 archive `4a9f8e206466243a4e15a626d1f79eb8c2f96023383fc6c3019d7140a369b226`의 결과다. 이번 수정 head에 그 전체 시험을 실행했다고 바꾸지 않는다. 변경은 시험 조정 두 파일과 새 시험 한 파일이며 app/기존 모델·정책의 지문은 유지했다. 새 head의 CI와 후속 통합 archive 전체 인수는 별도 결과로 기록한다. [실패·수정·실제 재검증 근거](infrastructure-results/extra-execution-maintenance-quiesce-v89-20261116.json).
