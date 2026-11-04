# 다른 AI 작업자를 위한 프로젝트 인수인계서

## 2026년 11월 4일 후속 호스트 전환 실행기 중단 복구

- PR #15는 `aitest` `ee8067b`에 병합됐고 병합 후 CI도 통과했다. 후속 브랜치는
  `feature/chaeheeju-executor-transition-recovery`. [구성·재개·경계](docs/executor-transition-recovery.md)를 읽는다.
- `scripts.executor_transition`의 고정 PID-1 actor와 생존 볼륨 flock으로 전환을 직렬화한다. 같은 컨테이너
  ID/전체 사양을 확인해 정지한 actor만 명시적으로 다시 시작한다. 실행 중/ID 변경/유실한 미완료 actor는 거부한다.
- 공개 op journal의 peer-first fsync, 양 marker 완료 전 일반 작업 거부, OPID 볼륨/실행기 채택, 같은 부분
  복제 재개와 old/new owner 대조를 사용한다. `complete`는 copy/fence/owner 재설치를 반복하지 않는다.
- actor도 socket을 가진 신뢰 관리자다. physical HA/quorum/자동 선출·불확실한 업무 POST 재전송으로 확대하지
  않는다. OS 신뢰/AWS/유료 LLM/탐지 기준을 바꾸지 않고 기존 컨테이너/ZIP은 보존한다. 실제 결과는 위 문서를 따른다.
- `operator-final1` project `c02-62de02a2e5c6`: operator30+실행기15+관리제거2=47, 별도 사전8+14 통과.
  같은 actor 실제 exit73 16회·관리 프로세스2회·새 콘솔20회, Root1·이전 JWK132거부·완료 뒤 새 토큰 소비 보존.
  실행/관리 epoch3 A활성·양세대2·옛 실행볼륨4/관리18 삭제. 111입력/양이미지91씩·외부20과 정리 증거를 보존했다.
- 신규 단위66, 캠페인 회귀 Windows1152+2skip/Linux1154·Ruff 통과. 초기에 더 좁은 사전2회는 최종 합계에서
  제외했다. 동료의 수집기 PR #16 `a908270`이 별도로 병합돼 결합 후 회귀 결과를 추가하며 해당 기여는 보존한다.

## 2026년 11월 4일 후속 관리 실행 호스트·기록 이중화

- PR #14 병합 `aitest` `8569385`에서 `feature/chaeheeju-executor-host-redundancy`로 진행한다.
  [구성·신뢰 경계·전환·재현](docs/executor-host-high-availability.md)을 먼저 읽는다.
- `scripts.executor_cluster`의 두 유지보수 실행기는 별도 rootfs와 journal/owner 볼륨을 갖는다.
  `ExecutorManagement`가 기존 관리 backend에 peer-first 전환 기록/프로필과 실행 epoch 검사를 더한다.
  실행 host epoch와 관리 cell epoch를 구분한다. 양 owner 불일치·대기·기록 불일치는 거부한다.
- operator lock 아래 고정 실행기 ID/전체 사양 확인·두 실행기 제거·옛 임시 작업 정리·서비스 ExecIDs 0
  확인 후 새 세대 저장소를 생존 사본으로 채운다. 공개 anchor와 명시한 생존 볼륨이 복구 입력이다.
  Windows JSON은 필요하지 않다. 임시 작업은 시작 전/관리 파일 변경 전에 양 owner를 확인한다.
- 실행기는 부모 Docker socket을 가진 신뢰 관리자다. UID/RO rootfs/cap-drop이 socket의 관리자 권한을
  줄이지 않는다. 온라인 CA/leaf에 socket/vault를 추가하지 않고 Root/백업 키는 network-none 작업만 읽는다.
- 같은 부모 Docker/물리 PC, 두 노드 수동 전환이며 quorum·물리 HA·자동 선출이 아니다. operator 전환
  자체 중단/부분 실패는 lock·봉쇄 상태에서 수동 조사한다. `opening` 이후 보안 상태를 초기화하지 않는다.
- `.env.local`을 읽지 않고 기존 `docs.zip`, `docs/week03.zip`, `pod-forensics-20261025-control-plane`을
  보존한다. AWS·유료 LLM 호출 없이 시험 프로젝트 자원만 정리한다. 역할/전체 주간 완료는 별도다.
- 최종 `executor-final2`, project `c02-e6790d753406`: 새 CA 1회·실행기15+관리 저장소 제거2, 별도 사전8,
  실제 본 종료2/사전1, Root/issuer/JWK epoch1·옛 JWK132거부. 관리/실행 epoch3, 양 세대2, 옛 실행 볼륨4/
  관리 볼륨18 삭제. 준비된 동일 키 후보와 접속 재개 후 새 JWT 소비가 양 호스트 손실/재개 후 보존됐다.
- 신규 단위68, Windows1087+1skip/Linux1088·Ruff 통과. 입력109개·양 이미지 안89개씩/외부20개·새 단위
  지문을 공개 결과에 남겼다. 최종/예비/단위7개 범위 잔여0, 기존 컨테이너/ZIP 보존. BuildKit 빌드 참조
  실패·unlabelled host drain 보완을 위한 준비 중단·이전 좁은 사전 실험은 최종 합계에서 제외했다.

## 2026년 11월 4일 후속 관리 전환 중단 복구

- PR #13 병합 `aitest` `1531625`에서 `feature/chaeheeju-control-transition-recovery`로 진행한다.
  [전환 단계·재개·검증·한계](docs/control-transition-recovery.md)를 먼저 확인한다.
- `scripts.control_transition`은 기존 호스트 lease 아래 공개 `management-transition.json`을 원본으로 쓴다.
  `scripts.control_plane_ha resume`은 같은 전환을 이어간다. 미완료 기록은 일반 host control 작업을 막는다.
- `idle`/`prepared` 후보 검증·busy 거부는 유지한다. 작업 전 의도/사양을 기록하고 부분 사본 일치와
  Docker 표식·이미지·ID·명령·환경·권한·마운트·네트워크를 확인한다. ID 기록 후 바뀐 객체는 대체하지 않는다.
- `opening` 이후에는 copy/initialize/reconcile/writer-stop을 반복하지 않는다. 접속을 이미 열었다면
  최신 pending/토큰 소비를 남긴 채 완료 기록만 확정한다. 업무 POST의 일반 재전송 기능이 아니다.
- `scripts.test_control_transition`은 별도 호스트 프로세스의 실제 강제 종료와 다음 프로세스의 lease 획득을
  검사한다. 새 실행기 import 누락으로 중단한 준비는 최종 통과 합계에 넣지 않는다. 실제 결과는 위 문서를 따른다.
- 로컬 journal/신뢰된 실행기·동일 부모 Docker가 남아야 한다. 전원/디스크/호스트 전체 손실·quorum·자동
  선출·임의 authority 중간 단계·구 이미지 인플레이스 이전·팀원 독립 검토·전체 주간 완료로 확대하지 않는다.
- 최종 새 클러스터 1회·35개(기존 관리20+추가15), 실제 process death9회, 신규 단위58개,
  Windows1019+1skip/Linux1020·Ruff 통과. 동일 생성 컨테이너 ID 채택과 접속 재개 후 새 JWT 소비 보존을 확인했다.
  5개 프로젝트/단위 이미지 태그 잔여0, 기존 Docker/ZIP 보존. 예비 import·60초 상한·정지한 발행기에서의
  CSR 준비·CA 재기동 전 JWT의 올바른401 거부를 최종 합계에서 제외한다. CSR은 정지 전 준비하고 JWT는
  접속 재개 후 network-none/RO vault 작업에서 만든다. 운영 전환 코드는 예비 실행기 수정 중 변경하지 않았다.

## 2026년 11월 4일 후속 관리 영역 이중화

- `aitest` `635638a`에서 `feature/chaeheeju-control-plane-ha`로 진행한다.
  [관리 구성·전환·재현·한계](docs/control-plane-high-availability.md)를 먼저 읽는다.
- `scripts.control_plane_ha.Management`가 management 프로필의 backend다. 기존 프로필은 기존 동작이다.
  cell별 9개 볼륨, 대기 우선 동기 파일 쓰기/삭제, 두 RO 역할 기록·관리 epoch, 단일 활성 leaf와 RO
  대기를 사용한다. 조정기 Linux 사본이 원본이며 Windows JSON은 복구 가능한 캐시다.
- 승격은 host lease, 완료된 관리/leaf 작업, `idle`/`prepared`, CA/vault/계획 일치와 PG system ID를
  요구한다. 기존 프로세스/관문과 CA writer를 정지한 뒤 새 세대 볼륨으로 이전한다. busy 삭제·과거
  프로필 재사용·불확실한 POST 재전송으로 복구하지 않는다. 전환 도중 실패의 자동 복구는 후속이다.
- `scripts.test_control_plane_ha`는 실제 준비된 root 계획 중 a→b, 완료 뒤 b→새 a와 옛 볼륨 삭제를
  검증한다. root/backup 키는 network-none 작업만 읽고 온라인 제어기에 socket/vault를 주지 않는다.
- 두 cell은 같은 부모 Docker/PC다. CA 서비스 호스트 두 DinD와 구분한다. 신뢰된 호스트 실행기/
  파일 lease, workload 인증서 볼륨과 앱 SQLite는 공통/별도 경계다. 물리 HA·quorum·운영 SLA·독립
  팀원 검토·전체 주간 계획 완료로 확대하지 않는다. 실제 결과는 위 문서와 공개 증거를 따른다.
- 최종 새 클러스터 1회·20개, 신규 단위 45개, Windows 961+1 skip/Linux 962와 Ruff 통과.
  역할/CA 설정 파일 유실 후 같은 키 계획 재개, cell 전환 2회·이전 볼륨 18개 삭제·미만료 소비/폐기
  거부·캐시 삭제 후 백업 인증을 검증했다. 4개 프로젝트/전체 회귀 이미지 태그 잔여 0, 기존 Docker/ZIP 보존.
  TLS health의 봉쇄 관문 의존과 quiesce의 Windows 캐시 의존 예비 실패를 최종 합계에서 제외한다.

## 2026년 11월 4일 CA DB·서비스 호스트 복구

- `aitest` `b6e35be`에서 `feature/chaeheeju-db-host-recovery`로 진행한다.
  [구현·복원 절차·검증·한계](docs/ca-db-host-recovery.md)를 먼저 확인한다.
- `scripts.test_ca_host_recovery`는 별도 Docker 데몬/저장소의 CA+DB 두 노드와 remote_apply 복제를
  구성한다. `scripts.ca_host_recovery`는 고정 소유 객체의 정지를 증명한 뒤에만 승격하며, 재가입은 새 저장소에
  reseed한다. 자동 네트워크 분할 선출이 아니고 실제 PC/관리 영역은 단일 장애점이다.
- 독립 관문 journal은 전달 전 intent를 기록한다. 암호화 백업의 authority/DB incarnation 및 최신 보안
  checkpoint와의 일치를 검사하고, 이전 dump 복원 후 토큰 소비·폐기를 재적용한 뒤 접속을 연다.
  관리 영역까지의 재해 복구·전역 antirollback·앱 SQLite 복구로 확대하지 않는다.
- 키 교체의 기존 모든 노드 증명 장벽은 `service_hosts` 프로필에서 새 backend를 사용한다. 기본 프로필과
  앱/탐지/개선 전 평가 기준선은 보존한다. 실행 결과·실패·정리는 위 문서와 공개 증거를 따른다.
- DinD 호스트만 신뢰된 privileged 시험 서버다. 일반 CA/leaf에 부모 Docker socket·root/JWK 보관함을
  연결하지 않는다. 백업/오류 후 leaf pause 유지와 수동 복구 조건을 문서에서 확인한다.
- 최종 새 클러스터 1회·33개 검사, Windows/Linux 각 917개(신규 47개), Ruff 통과. daemon 5개를
  관측하고 seal 후 cold restore 329.891초, 유효 토큰/폐기 인증서 거부와 새 nonce 양 CA 발급을 확인했다.
  [공개 근거](docs/infrastructure-results/c04-ca-db-recovery-windows-20261104.json)에 예비 실패도 구분한다.
  내부 CA/DB는 `unless-stopped`, 봉쇄 대상 외부 host는 검증된 `no` 정책이다. 전용 container/volume/
  network/image tag 0, 기존 Docker/ZIP 보존. Docker Desktop/물리 PC/관리 영역 전체 HA는 미완료다.

## 2026년 11월 3일 후속 CA 프로세스 고가용성

- PR #10 병합 `aitest` `0c32273`에서 `feature/chaeheeju-ca-high-availability`로 진행한다.
  [구현·재현·한계](docs/ca-high-availability.md)와 [계약](infra/mtls/ca-ha-contract.json)을 확인한다.
- CA 두 프로세스는 같은 온라인 issuer 설정을 읽기 전용으로 사용하고 단일 PostgreSQL의 발급/토큰/폐기
  상태를 공유한다. DB 전용 내부망·독립 transport PKI·노드별 mTLS·verify-full·최소 권한 역할을 적용한다.
  앱 SQLite나 기존 Badger 운영 DB를 마이그레이션하지 않는다. DB/호스트 이중화는 별도다.
- `ca-endpoints.json`이 있는 관리 프로필만 연결 장애 시 승인 CA로 전환한다. TLS 인증 오류·전송한 POST·
  401/403은 다른 노드로 재시도하지 않는다. 같은 일회용 토큰의 동시 소비에는 SERIALIZABLE 충돌 거부를
  사용한다. 전체 CA/ACME/admin API의 분산 트랜잭션 보장이나 성공 exactly-once로 확대하지 않는다.
- 키 교체는 단일 조정기·leaf pause/ack를 유지하고 모든 pinned CA의 새 issuer TLS·개별 새 JWK 발급·각
  구 JWK의 개별 거부를 확인한다. 순차 재시작이어도 발급 유지보수 중단이 가능하다. 무중단 SLA는 아니다.
- 실제 검사 수·실패·이미지/소스 지문·정리는 위 검증 문서를 따른다. 팀원 독립 검토·운영 배포·HSM·DB
  transport PKI 자동 수명 관리는 후속이다. 아래 HA 미완료 표기는 이전 프로필의 당시 범위로 보존한다.

- 최종 HA 90초 canary/여유 60초 프로필로 새 CA/DB 2회 × 222 = 444개, Windows/Linux 각각 전체
  870건과 Ruff 통과. 새 단위 사례 52개, 회당 48개 활성 신원/14개 TLS 서버/3 authority epoch,
  양 CA의 구 JWK 새 요청 총 792개 거부를 확인했다. 중단 배포 48개/46개 각각 동일 후보를 복구했다.
  [공개 증거](docs/infrastructure-results/c04-ca-ha-windows-20261103.json)에 초기 bootstrap 파일 assertion,
  전체 batch 가정 assertion, 30초 canary의 실제 만료 실패를 최종 합계와 분리했다. 소진 파일 삭제를
  배포 성공과 분리하고 전체 키 보존/실제 중단 후보 재사용/전체 이행을 따로 검증한다. 30초 HA SLA
  통과로 표현하지 않는다. 5개 프로젝트 자원/전용 태그와 단위 이미지 4개의 잔여 0, 기존 Docker/ZIP 보존.

## 2026년 11월 3일 후속 CA·발급 JWK 키 자동 교체

- PR #9 병합 `aitest` `4d74f06`에서 `feature/chaeheeju-authority-key-rotation`으로 진행한다.
  [구현·운영 경계](docs/authority-key-rotation.md)와 [계약](infra/mtls/authority-rotation-contract.json)을 확인한다.
- 신뢰된 호스트 조정기와 `network=none` custodian을 분리한다. 새 프로필은 루트/중간/전체 JWK를 인증
  암호화한 Linux bundle에 보관한다. 이전 RAM 전용 루트 프로필은 그대로다. 보관함 암호도 같은 볼륨에
  있으므로 HSM/물리적 air gap/독립 secret manager 보호가 아니다. 온라인 CA·leaf에는 보관함/socket을 주지 않는다.
- 이전 루트 서명 계획·단일 writer·leaf pause/ack·겹침 신뢰→CA/JWK 등록 교체→모든 활성 leaf의 새 issuer/
  epoch·TLS 확인→구 신뢰 제거→구 JWK 모두 거부→구 비밀 파일 제거 순서다. 별도 committing 단계로 재개한다.
- CA/JWK별 타이머를 독립 검증한다. 부트스트랩 52개와 서버 JWK 14개를 모두 교체하되 이름·용도·정책을
  보존한다. issuer-only 교체는 훔친 구 중간 CA 체인의 active 폐기가 아니다. 정상 교체/사고 복구도 구분한다.
- 앱·탐지·정책·개선 전 품질은 변경하지 않는다. 팀원 독립 검토·운영 배포/HA·저장소 anti-rollback·물리 소거는 후속이다.
- 최종 새 CA/상태 2회 × 197 = 394개 통합 assertion, Windows/Linux 각각 전체 818건과 Ruff를 통과했다.
  회당 48개 신원/14개 TLS 서버, root+issuer+JWK→issuer+JWK→JWK 3 epoch과 각 66개 구 JWK 요청 거부를 확인했다.
  별도 3개 신원 루트1→루트2 반복의 구 root TLS 거부/현재 root 200은 보조 검사 3건으로 합계에서 분리한다.
  [공개 증거](docs/infrastructure-results/c04-authority-rotation-windows-20261103.json)에 소스/이미지 지문·실패·정리를 보존했다.
  초기 policy 함수/상속 dict 이름 충돌과 smoke Host 설정을 고친 후 전체 반복을 검증했다. 5개 프로젝트/단위 이미지
  잔여 0이며 기존 Docker 작업·사용자 ZIP은 보존했다. 아래 CA/JWK 미구현 표기는 이전 프로필의 당시 범위다.

## 2026년 11월 3일 후속 C04 서비스 개인키 자동 교체

- PR #8 병합 `aitest` `e8e7867`에서 `feature/chaeheeju-private-key-rotation`으로 진행한다.
  [구현·재현·한계](docs/private-key-rotation.md)와 [계약](infra/mtls/private-key-rotation-contract.json)을 확인한다.
- 명시적 `key_rotation` 모드만 leaf 키를 교체한다. 기본 동일 키 갱신은 유지한다. 관리 mTLS 키도 교체하지만
  CA 루트/issuer와 별도 등록 JWK 서명키는 제외하며, JWK 키는 관리 mTLS 키와 독립적으로 생성한다.
- immutable 세대별 파일→겹침 pin→profile/config 원자 전환→reload ack/실제 TLS→구 pin 제거→구 client
  serial 자체 폐기→유예 후 구 파일 unlink 순서다. journal에 private PEM을 저장하지 않는다.
- 단일 publisher/운영자 pause/ack 규칙과 만료·retired·disabled 거부를 유지한다. unlink는 물리 소거나
  메모리/백업 키 제거가 아니다. HSM/HA/운영 배포/독립 재현과 별도로 기록한다. 아래 C04 결과는 이전 기준선이다.
- 최종 2회 × 174 = 348개 통합 assertion, Windows/Linux 각각 전체 766건과 Ruff를 통과했다.
  회당 48개 신원·14개 서버, 3회 이상 새 키 전환·실제 activated 단계 중단 복구·CA 장애 후 복구를 확인했다.
  등록 JWK 교차 발급 401은 별도 검사 1건이다. [공개 증거](docs/infrastructure-results/c04-key-rotation-windows-20261103.json)를 따른다.
  초기 null 세대 비교 TypeError·3개 신원 빠른 시험은 최종 합계에서 제외했다. 3개 프로젝트/단위 이미지 잔여 0,
  기존 Docker 작업과 사용자 ZIP은 보존했다. 앱·탐지·정책 소스는 변경하지 않았다.

## 2026년 11월 3일 후속 C04 인증서 수명 자동화

- PR #7 병합 `aitest` `1775491`에서 `feature/chaeheeju-certificate-automation`로 진행합니다.
  [범위/재현/한계](docs/certificate-automation.md), [선정 기록](docs/technology-decisions/C04-certificate-lifecycle.md),
  [계약](infra/mtls/certificate-lifecycle-contract.json)을 확인합니다.
- step-ca 0.30.2/CLI 0.31.0을 고정 출처/SHA-256으로 확인합니다. 루트 개인키는 드라이버 RAM에만,
  온라인 중간 CA는 암호화 키·부팅 암호·DB를 전용 Linux 볼륨에 둡니다. 제어기는 CA 키/Socket이 없습니다.
- clientAuth는 mTLS로 갱신합니다. serverAuth 전용 `/renew`는 실제 버전에서 거부되어 서버별
  `renew-<서버>`에 연결된 제어면 전용 JWK 서명키로 제한된 재발급을 사용합니다. 일반 CA client 인증서에
  관리 권한을 주는 범용 X5C provisioner는 설치하지 않습니다. 서버 EKU를 넓히거나 업무 역할을 주지 않습니다.
- 단일 publisher/journal, 새 pin 겹침→인증서 교체→reload ack/실제 TLS 관측→구 pin 제거를 연결합니다.
  운영자 정책 변경은 pause/ack를 지켜야 하며 분산 writer·anti-rollback을 구현한 것은 아닙니다.
- 최초 grant는 CSR에 묶어 사용 후 지우고, 만료한 관리 신원의 자동 재등록을 하지 않습니다.
  CA 폐기와 즉시 peer pin 제거, 서버 leaf 폐기와 별도 발급 권한 폐기를 구분합니다.
- 실제 반복 결과는 위 문서/공개 증거를 따릅니다. 앱 탐지/정책/개선 전 품질은 보존하고,
  Codex 도구 실행을 팀원 수동 실행·독립 검토로 소급하지 않습니다. 운영 CA/HA/HSM/독립 재현은 후속입니다.
- 최종: 2회 × 153 = 306개 통합 검사, Windows/Linux 전체 각각 739건과 Ruff 통과.
  회당 50개 활성 신원의 발급/타이머 갱신과 서버 14개의 새 TLS 지문을 확인했습니다.
  [공개 증거](docs/infrastructure-results/c04-certificates-windows-20261103.json)에 초기/중단 시도를 분리했습니다.
  시험 8개 프로젝트 자원/전용 이미지 잔여는 0이며 시작 때 실행 중인 다른 Docker 작업은 보존했습니다.

## 2026년 11월 3일 후속 선택 경로 전체 mTLS

- PR #6 병합 `aitest` `f7fc48d`에서 `feature/chaeheeju-mtls-all-hops`로 진행합니다.
  [전체 경로/한계](docs/all-hops-mtls.md)와 [계약](infra/mtls/all-hops-contract.json)을 확인합니다.
- NGINX front/auth/resource, bridge/gateway/native core/consume, 실제 수집기 입력과 선택한
  Prometheus/exporter/Alertmanager/receiver, 관리 조회에 mTLS를 적용합니다. worker는 network=none입니다.
- `python -m scripts.test_all_hops_mtls --repeats 3`은 기존 I2 30·새 경로 43·C02 42개를 반복합니다.
  파일 IPC·호스트 Docker exec 파이프·공개 artifact 다운로드와 서비스 네트워크를 구분합니다.
- native core는 앱 소스를 바꾸지 않고 실제 TLS peer를 Uvicorn h11 guard에 연결합니다.
  peer/header 위조·평문·pin 취소·grant 소비 상태와 실제 firing/resolved의 동일 episode를 확인합니다.
- Python endpoint의 leaf pin, NGINX/Go의 CA/이름/SAN 검증을 구분합니다. 운영 CA/CRL/OCSP/HA/
  정책 anti-rollback·진행 중 업무 취소·독립 재현은 미완료입니다. 과거 HTTP 비교 기록은 보존합니다.
- 실제 실행·측정은 Codex 도구 보조이며 팀원 수동 실행/독립 검토로 소급하지 않습니다. 탐지 기준선은 유지합니다.
- 최종 검증: Windows/Linux Docker 각각 전체 687건과 Ruff 통과. mTLS 그래프 3회 345개 +
  실제 수집기 `_post`/지속 관찰 연결 후 최종 1회 115개, 합계 460개 반복 검사를 통과했습니다.
  앞선 3회와 최종 수집기 구현 1회는 [공개 증거](docs/infrastructure-results/all-hops-mtls-windows-20261103.json)의
  입력 지문/이미지로 구분합니다. 시험 자원·전용 이미지 정리 후 Docker Desktop은 종료했습니다.

## 2026년 11월 3일 후속 I2 서비스 mTLS

- PR #5 병합 `aitest` `87f24f6`에서 `feature/chaeheeju-i2-mtls`로 진행합니다.
  [I2 경계/검증/한계](docs/i2-service-mtls.md), [계약](infra/mtls/contract.json)을 확인합니다.
- C02의 기본 HTTP 실행은 유지하고 별도 실행기가 PEP bridge→인가 gateway에 mTLS를 연결합니다.
  chain/시간/EKU/서버 이름/leaf pin과 서비스별 경로를 검사하며 기존 앱 API 키/역할도 유지합니다.
- `python -m scripts.test_mtls_infrastructure --repeats 3`은 Linux 전용 임시 키 볼륨과 내부망만 씁니다.
  개인키는 호스트 파일이나 OS trust store에 쓰지 않습니다. runtime 경로는 기존 C02 실행기 아래입니다.
- client/server 인증서 교체·pin 폐기·잘못된 설정과 기존 C02의 위험 신호→회수→다음 문서 거부를 검증합니다.
  실제 결과는 I2 문서/공개 원자료를 따릅니다. 앱 탐지·정책·개선 전 평가 기준선은 바꾸지 않습니다.
- gateway 뒤와 다른 hop은 HTTP입니다. 운영 배포/IdP/CA 자동화/CRL·OCSP/HA/독립 검토는 후속입니다.
  C04 step-ca는 자동 발급 요구가 확인될 때 비교하며 이번 도입/비교 완료로 기록하지 않습니다.

I2 추가 결과: 3회 × 72개 = 216개 통합 검사, Windows/Linux Docker 전체 655건을 통과했습니다.
[I2 공개 증거](docs/infrastructure-results/i2-mtls-windows-20261103.json)에 TLSv1.3 관측과 초기 시도를
분리했습니다. 폐기 정책의 과거 버전 복원을 막는 anti-rollback은 미구현이며 다른 hop·운영 배포는 후속입니다.

## 2026년 11월 3일 후속 C02 HTTP 집행

- PR #4 병합 `aitest` `9f61f35`에서 `feature/chaeheeju-c02-pep`로 진행합니다.
- [C02 기록](docs/technology-decisions/C02-http-pep.md)과 [계약](infra/pep/contract.json),
  [고정 이미지](infra/pep/tools.lock.json)를 확인합니다. 기존 앱/정책/탐지 소스는 바꾸지 않습니다.
- `python -m scripts.compare_pep --repeats 3`은 두 프록시를 같은 core API와 별도 자원 서버에 연결합니다.
  core grant를 소비한 뒤 3초짜리 일회용 handoff로 문서를 전달하며, 장애에 재허용/환불하지 않습니다.
- 위험 신호 내구 접수·기존 networkless worker 처리·관련 세션 제한·다음 HTTP 거부를 연결합니다.
  직접 접근·헤더 위조·동시 소비·테넌트/운영자·회수·만료·키 폐기·장애/재시작도 대조합니다.
- 인가 시점은 core SQLite 트랜잭션입니다. 이미 허용된 in-flight 요청을 회수로 취소하거나 업무와
  원자적으로 커밋하는 구현은 아닙니다. 운영 TLS/IdP/HA/고부하·영속 업무 감사·독립 재현은 후속입니다.
- 최종 반복·검증·초기 실패와 한계는 C02 문서/원자료를 따릅니다. 아래 기록은 당시 상태로 보존합니다.
- 최종 각 3회·42개씩 총 252개 검사와 Windows/Linux Docker 전체 630건을 통과했습니다.
  [공개 실측](docs/infrastructure-results/c02-windows-20261103.json)에 준비 실패를 분리했고, 소스 지문도 재검사했습니다.
  로컬 통합 NGINX를 잠정 제안하되 관측 지연은 Envoy가 낮았음을 보존합니다. 운영 채택·독립 검토는 후속입니다.

## 2026년 11월 3일 후속 C01 관측·경보

- PR #3까지 병합한 `aitest` `719f069`에서 `feature/chaeheeju-c01-observability`로 작업합니다.
- [C01 기록](docs/technology-decisions/C01-observability.md), [계약](infra/observability/contract.json),
  [공통 경보](infra/observability/alerts.yaml), [고정 도구](infra/observability/tools.lock.json)를 확인합니다.
- 새 exporter는 기존 viewer inbox API의 aggregate만 GET하며 DB/정책에 쓰지 않습니다.
  수집 실패에는 오래된 큐 수치를 제공하지 않고 별도 failure gauge를 냅니다.
- `python -m scripts.compare_observability --repeats 3`은 내부망에서 두 구성을 실제 시험하며
  서명 개인키는 메모리, 임시 토큰은 전용 Linux 볼륨에만 둡니다. 호스트 공개 포트·Docker socket 마운트가 없습니다.
- 초기 연결·query lookback 설정 실패도 보존합니다. 성공 반복과 독립 재현·운영 채택을 구분합니다.
  실제 IdP/EDR·운영 TLS/인가·HA·고부하/장기 보존·알림 무손실 검증은 미완료입니다.
- 기존 앱 소스·탐지 기준선은 유지하며 AWS/유료 모델을 호출하지 않습니다. 아래 기록은 당시 상태로 보존합니다.
- 최종 후보당 3회·18개씩 총 108개 기록 검사를 통과했습니다. 신규 보안/정합성 회귀 25건을 포함한 전체
  Windows/Linux Docker 591건이 각각 통과했습니다. [실측 요약](docs/infrastructure-results/c01-windows-20261103.json)에
  같은 대상·fingerprint·startsAt·구간 인덱스로 검증한 알림, 자원·초기 실패와 한계를 남깁니다.
  후속 로컬 통합 기준선은 Prometheus+Alertmanager를 잠정 제안하며 운영 채택은 보류합니다.

## 2026년 11월 3일 후속 C03·M6 계약

- PR #2는 `aitest`의 `b4660ad`에 병합했습니다. 현재 후속 작업은
  `feature/chaeheeju-c03-supply-chain`에서 진행하며 별도 PR로 기록합니다.
- [C03 로컬 비교](docs/technology-decisions/C03-supply-chain.md): 공식 고정 바이너리의 서명/지문 검증,
  같은 이미지 tar에서 Syft+Grype와 Trivy의 오프라인 반복·설치 metadata 대조·작은 advisory 대조군입니다.
  실제 결과와 보관 위치·한계를 확인하고 스캐너 채택·독립 재현 완료로 오해하지 않습니다.
- [M6/C10 평가 계약](docs/m6-evaluation-contract.md)과 [JSON](infra/model-evaluation-contract.json)은
  후보·질문·안전·비용 조건 초안입니다. 유료 호출·키 등록·새 공급자 실행기·제품 연결은 하지 않았습니다.
  생성형 설명과 Jev/Laya 분류를 분리하고 AI 단독 권한 허용/복구를 금지합니다.
- 이번 변경은 탐지 규칙·임계값·정규화·정책 및 개선 전 품질 결과를 바꾸지 않습니다.
  AWS/실계정 변경 없이 로컬에서 시험합니다. 아래 과거 기록은 당시 상태로 보존합니다.
- C03 도구의 변조/경로·체크섬·패키지 버전·집계 검증 21건을 추가해 전체 566건을
  Windows와 Linux Docker에서 통과했습니다. 각각 기존 경고 3개/2개이며 탐지 품질 목표 통과를 뜻하지 않습니다.

## 2026년 11월 3일 희주 담당 인프라 작업

- 원격 `aitest`의 PR #1 병합 커밋 `82285c6`를 받아 `feature/chaeheeju-m3-infra-validation`에서 작업합니다.
- 사용자 요청에 따라 희주 작업은 `feature/chaeheeju-<작업명>` 브랜치와 `aitest` 대상 PR로 남깁니다.
  직접 통합 브랜치에 푸시하지 않고 [작업 절차](docs/contribution-workflow.md)를 따릅니다.
- 기존 M3 구현을 재사용하며 탐지 규칙·임계값·개선 전 평가 자료는 변경하지 않습니다.
- 시험 개인키는 메모리에서만 사용하고 공개 등록 JSON만 마운트합니다. Windows에서 POSIX 모드 비트를
  그대로 요구하던 시험을 플랫폼 계약에 맞췄습니다. worker는 공유 SQLite만 필요해 네트워크를 제거했습니다.
- `python -m scripts.measure_signal_infrastructure --repeats 3`으로 격리 반복·자원·지연을 기록합니다.
  시연 부하·소표본 결과이며 서비스 SLA·실제 IdP/EDR·mTLS·독립 PEP·RTO/RPO 완료로 사용하지 않습니다.
- 실행·표본·실제 결과·한계는 [인프라 측정 기록](docs/m3-infrastructure-measurement.md)을 우선합니다.
  아래 11월 2일과 11월 1일 기록은 당시 기준선으로 보존합니다.

## 2026년 11월 2일 로컬 개발 업데이트

- 작업 브랜치: `feature/m3-durable-signals`, 시작 커밋: `71cbfc0`. M3 구현·검증 결과이며
  아래 11월 1일 기준선 기록을 보존합니다. 버전 번호는 아직 `0.17.0`입니다.
- M3/I1: `zt-observation-1` identity/device 관찰, 종류·주체·키 권한 분리,
  SQLite 내구 접수, 별도 `scripts.signal_worker`, 관련 세션 제한·회수와 영수증·지표를 추가했습니다.
- 정책 fanout과 관찰 표식을 한 journal 트랜잭션으로 반영합니다. 완료 기록 유실은
  재전달 또는 마지막 시도의 읽기 전용 대조로 복구하며 정책 효과를 중복 적용하지 않습니다.
- 관찰 전용 source는 기존 full-session 서명 경로를 사용할 수 없고, 같은 테넌트에서
  다른 source가 같은 공개키를 공유하면 등록 전체를 실패 폐쇄합니다. 기존 키 등록을 옮길 때 주의합니다.
- 정상 관찰·동기 재평가·새 세션으로 위험 제한을 자동 해제하지 않습니다.
  검토된 해제·복구 프로토콜, 실제 IdP/EDR, GuardDuty, 독립 업무 PEP는 후속 작업입니다.
- 새 API와 worker도 local/test 전용입니다. 기존 Sigma 규칙·임계값·개선 전 평가 원자료는 유지했습니다.
- 계약·시험 위치·M6/M7 준비 사항은 [M3 명세](docs/m3-durable-signals.md)를 따릅니다.
  [검증 결과](docs/m3-validation-results.md): Python 3.12·3.14 각각 전체 518건 통과,
  Ruff·Compose 구성 검사 통과. 이후 Colima의 Linux Docker에서 앱·worker 통합 검사
  11개와 전체 524건을 검증했습니다. 실제 컨테이너 재시작·회수 후 HTTP 403과
  무관 세션 HTTP 200, 공유 SQLite·UID 10001을 확인했습니다.
  [Docker 검증 기록](docs/m3-docker-validation.md)의 환경·재현 명령·원자료를 확인합니다.

이 문서는 다른 AI 또는 개발자가 `zero-trust-llm-secops` 저장소를 처음 열었을 때 현재 상태를 오해하지 않고 안전하게 작업을 이어가기 위한 기준 문서다.

갱신일: 2026년 11월 1일. 프로젝트의 핵심은 **제로트러스트 오퍼레이션**이다. 아래 기능·평가 기준 커밋은 `68519f5`이며 실제 최신 HEAD는 `git log -1`로 확인한다. 현재는 개선 전 탐지 기준선을 보존하는 단계이므로 점수가 낮더라도 규칙·임계값·정규화·정책 집행을 임의로 개선하지 않는다.

## 1. 한눈에 보는 프로젝트

| 항목 | 내용 |
|---|---|
| 프로젝트명 | LLM 기반 지능형 제로 트러스트 보안 오퍼레이션 및 자동화 프레임워크 구축 |
| 팀명 | 천안아산역 |
| 팀원 | 채희주, 김택희 |
| 저장소 | `https://github.com/cheonan-asan-sta/zero-trust-llm-secops` |
| 패키지 버전 | `0.17.0` |
| 언어·프레임워크 | Python 3.11 이상, FastAPI, Pydantic, pytest |
| 기본 분석 모드 | API 비용이 들지 않는 `rule` 모드 |
| 현재 작업 브랜치 | 로컬 `aitest` |
| 기능·평가 기준 커밋 | `68519f5 Record pre-improvement detection benchmark with 720 labeled cases` |
| 핵심 안전 경계 | 실제 계정 차단, 권한 변경, 세션 격리, 외부 SIEM·ITSM 전송을 수행하지 않음 |

이 프로젝트는 합성 이벤트와 출처가 고정된 공개 보안 로그를 받아 다음 작업을 수행하는 시연용 SecOps 애플리케이션이다.

1. 공통 `SecurityEvent` 형식으로 입력을 검증한다.
2. OCSF 1.9.0 형식으로 정규화하고 원본·변환 해시를 남긴다.
3. Sigma 2.1 규칙으로 탐지한다.
4. 규칙 기반, OpenAI 또는 하이브리드 분석기로 위험도와 근거를 구조화한다.
5. 정책 허용 범위와 사람 검토 필요 여부를 확인한다.
6. 여러 이벤트를 엔터티 그래프와 시간창으로 상관분석한다.
7. 사고 케이스와 변경 이력을 저장한다.
8. 외부 연동용 CloudEvents를 아웃박스에 보존하지만 실제 목적지 전송은 기본적으로 수행하지 않는다.
9. local/test 전용 제로트러스트 경로에서 서명·범위·신선도와 사용자·기기·자원·행위를 검증한다.
10. 세션별 단기·단일 사용 허용을 발급하고 위험 변화·키 폐기 시 회수하여 다음 모의 자원 접근을 거부한다.

실제 IdP·MFA·EDR 증명, 상시 신호 수신/관련 세션 자동 재평가, 독립 업무 서비스 PEP는 아직 미완료다. 서명은 등록 수집기의 출처·무결성을 확인하며 그 주장의 진실성을 보장하지 않는다. 새 경로는 production에서 비활성화된다.

## 2. 학사 일정과 실제 코드 진척 구분

이 저장소는 계획보다 빠르게 구현되었다. 발표자료나 주차별 보고서를 작성할 때 실제 코드의 모든 기능을 해당 주차 성과로 쓰면 안 된다.

- 중간 영상의 1~6주차 범위: 제로 트러스트 학습, 위협 시나리오, 이벤트 모델, 합성 로그, Structured Outputs, 로컬 Docker 검증까지다.
- 현재 코드 범위: 계획서의 3~14주차 개발 항목과 이후 기업 적용 고도화 기능까지 구현되어 있다.
- 15~16주차 최종 보고서와 발표는 아직 별도 작성 대상이다.
- 주차별 근거는 반드시 [`docs/README.md`](docs/README.md)와 각 `docs/weekXX/README.md`를 기준으로 사용한다.

## 3. 현재 Git 상태

문서 작성 시점의 상태는 다음과 같다.

```text
branch: aitest
feature/evaluation baseline: 68519f5
remote: origin -> https://github.com/cheonan-asan-sta/zero-trust-llm-secops.git

aitest: 현재 v0.17.0 구현과 개선 전 탐지 평가
실제 원격 상태: git ls-remote --heads origin으로 확인
```

주의사항:

- 2026년 11월 1일 사용자가 현재 코드를 GitHub에 올리도록 요청했다. 대상은 기존 작업 브랜치 `aitest`이며 `main` 병합·강제 푸시는 포함하지 않는다. 실제 게시 상태는 원격 브랜치와 로컬 HEAD 일치 여부로 확인한다.
- `docs.zip`, `docs/week03.zip`은 추적되지 않은 사용자 파일이다. 요청 없이 삭제, 이동, 커밋하지 않는다.
- 기존 브랜치를 강제로 재설정하거나 사용자 변경사항을 되돌리지 않는다.
- 사용자가 지정한 브랜치와 기존 승인을 따른다. 인증정보·실행 데이터·사용자 압축본은 업로드하지 않는다.

## 4. 전체 처리 구조

### 보안 이벤트 분석 경로

```text
SecurityEvent
  -> 입력 모델 검증
  -> 규칙 기반 / OpenAI / 하이브리드 분석
  -> SecurityAssessment
  -> 정책 안전장치와 대응 미리보기
  -> AnalysisResult
  -> JSONL 또는 DynamoDB 감사 기록
  -> 분석가 검토 상태 갱신
```

### 탐지·사고 관리 경로

```text
SecurityEvent
  -> OCSF 1.9.0 정규화
  -> Sigma 2.1 규칙 탐지
  -> 5분·30분·24시간 상관분석
  -> OCSF Incident Finding
  -> 테넌트별 Incident Case
  -> CloudEvents 1.0 Integration Outbox
  -> 전달 상태 기록과 재시도 관리
```

두 경로 모두 실제 보안 시스템을 변경하지 않는다. 대응은 `simulation` 미리보기이며 외부 전달도 로컬 상태 머신에 머문다.

### 제로트러스트 운영 경로

```text
서명 수집기 -> 출처/범위/신선도 검증 -> 규칙+Sigma 및 자원 정책
  -> 세션 판단/버전/단일 사용 허용 -> 모의 PEP -> 모의 자원 200 또는 403
  -> 위험 재평가/키 폐기 -> 이전 허용 회수 -> 다음 접근 거부
```

v0.16은 세션·자원 정책·허용 소비/회수, v0.17은 Ed25519 서명·120초 재인증 챌린지·키 회전/폐기를 추가했다. `/analysis`의 선택적 LLM과 케이스 경로가 완성된 하나의 자동 집행 체인으로 통합된 것은 아니다. LLM은 필수 검증이나 최종 허용·회수를 대체하지 않는다.

## 5. 폴더 구조와 역할

```text
zero-trust-llm-secops/
├─ app/                     FastAPI 애플리케이션
│  ├─ analyzers/            규칙·OpenAI·하이브리드 분석기
│  ├─ data/                 통제대장, Sigma 규칙, 공개 재생 표본
│  │  ├─ replay/            출처·라이선스·해시가 고정된 공개 로그
│  │  └─ sigma/             로컬 Sigma YAML 규칙
│  ├─ services/             정책, 감사, 탐지, 상관분석, 케이스 등 도메인 서비스
│  └─ static/               한국어 관제 대시보드
├─ tests/                   단위·API·통합·회귀 테스트
├─ docs/                    주차별 산출물과 기업 적용 문서
├─ infra/                   AWS CloudFormation 정의
├─ scripts/                 Docker 시험과 AWS 배포 스크립트
├─ .github/workflows/       CI 정의
├─ runtime/                 실행 중 생성되는 로컬 JSONL 데이터
├─ compose.yaml             비용 없는 로컬 실행 구성
├─ Dockerfile               애플리케이션 이미지
├─ Dockerfile.test          검사·테스트 전용 이미지
├─ Dockerfile.lambda        AWS Lambda 컨테이너 이미지
├─ pyproject.toml           패키지·의존성·pytest·ruff 설정
├─ .env.example             비밀값 없는 환경변수 예시
└─ README.md                사용자용 전체 기능·실행·API 설명
```

### `app/`

애플리케이션의 모든 실행 코드가 있다.

| 파일·폴더 | 역할 |
|---|---|
| `main.py` | FastAPI 앱 생성, 의존성 연결, 모든 HTTP 엔드포인트 정의 |
| `models.py` | 이벤트, OCSF, 탐지, 분석, 케이스, 아웃박스, 평가 모델과 교차 필드 검증 |
| `config.py` | `.env.local`과 환경변수 로딩, 운영 환경의 안전하지 않은 설정 거부 |
| `security.py` | 비활성·API 키·OIDC 인증, 역할 기반 권한, 테넌트 주체 생성 |
| `middleware.py` | 요청 ID, 본문 크기 제한, 보안 헤더, Prometheus 요청 지표 |
| `scenarios.py` | 정상 3건과 위협 5건, 시나리오 조건, 합성 이벤트 생성 |
| `prompting.py` | Few-shot 선택, LLM 입력 생성, 자유 텍스트를 데이터로 다루는 프롬프트 경계 |
| `analyzers/` | 분석기 인터페이스와 세 가지 분석 모드 |
| `services/` | 도메인별 처리 로직과 저장소 구현 |
| `data/` | 버전 관리되는 규칙·통제·공개 데이터 |
| `static/` | 대시보드 HTML, CSS, JavaScript, 파비콘 |

### `app/analyzers/`

| 파일 | 역할 |
|---|---|
| `base.py` | 분석기가 따라야 하는 `Analyzer` 프로토콜 |
| `rule_based.py` | API 키 없이 결정적으로 동작하는 기본 위험 분석기 |
| `openai_analyzer.py` | OpenAI Structured Outputs로 `SecurityAssessment`를 생성하는 선택 기능 |
| `hybrid.py` | 규칙 결과가 애매할 때만 LLM을 호출하고 실패 시 안전하게 규칙 결과로 복구 |

분석기를 변경할 때는 `ground_truth`가 LLM 입력으로 전달되지 않는지, 낮은 신뢰도와 고위험 결과가 사람 검토로 전환되는지 확인한다.

### `app/services/`

| 파일 | 역할 |
|---|---|
| `policy.py` | 위험 점수·등급 일관성, 허용 대응 목록, 정책 예외, 대응 미리보기 |
| `scenario_evaluator.py` | 구조화된 조건으로 이벤트와 시나리오의 일치도 계산 |
| `evaluation.py` | 반복 평가, 정확도, JSON 유효율, 지연시간과 오류 진단 |
| `audit.py` | JSONL·DynamoDB 감사 저장, 테넌트 격리, SHA-256 해시 체인 |
| `assurance.py` | 기계판독 통제대장 검증과 구현 증적 조회 |
| `ocsf.py` | `SecurityEvent`를 OCSF 1.9.0 Authentication·API Activity로 변환 |
| `sigma.py` | 승인·버전·시험 메타데이터가 있는 Sigma 2.1 로컬 탐지 엔진 |
| `public_replay.py` | 고정된 Splunk·Microsoft Sentinel 표본을 네트워크 없이 재생 |
| `detection_quality.py` | 규칙별 혼동행렬, Precision, Recall, F1, 오탐률과 품질 게이트 |
| `correlation.py` | 엔터티 그래프와 다중 시간창으로 Incident Finding 생성 및 중복 제거 |
| `incident_quality.py` | 사건 단위 Precision·Recall·F1, 오상관률과 구조 품질 게이트 |
| `cases.py` | 사고 케이스 생성·저장·상태 전이·버전 충돌 방지·증거 지문 |
| `integration_outbox.py` | 케이스 버전을 CloudEvents로 투영하고 대기·재시도·완료·실패 상태 관리 |
| `zero_trust.py` | 세션 정책 판단, 허용 발급·소비·회수, SQLite 상태와 저널 |
| `trusted_signals.py` | Ed25519 서명·범위·신선도·키 수명주기 검증 |
| `detection_benchmark.py` | 합성 개발/평가 분리, 혼동행렬·계열 부트스트랩·품질 게이트 |

### `app/data/`

| 위치 | 역할 |
|---|---|
| `control-register.json` | 18개 기업·공공 보안 통제와 코드·시험 증거를 연결한 대장 |
| `sigma/*.yml` | 계정 침해, 미관리 기기, 권한 상승, 내부 확산, 데이터 유출 규칙 |
| `replay/manifest.json` | 공개 표본의 출처, 커밋, 라이선스, SHA-256, 기대 결과 |
| `replay/*.json*`, `*.xml` | 오프라인 재생용 공격·정상 이벤트 표본 |
| `replay/NOTICE.md` | 공개 데이터 출처와 라이선스 안내 |
| `benchmark/` | 합성 720건·72계열, 분할·라벨 근거·생성기/자료 지문 |
| `zero-trust-policies.json` | 서버 소유 자원·행위·역할·허용/신호 유효기간 정책 |

데이터 파일을 수정하면 관련 해시, manifest, 품질 목표, 테스트도 함께 갱신해야 한다.

### `app/static/`

| 파일 | 역할 |
|---|---|
| `index.html` | 관제 대시보드 구조 |
| `styles.css` | 천안아산역을 연상시키는 남색·파랑·노랑 화면 스타일 |
| `app.js` | API 호출, 시나리오 선택, 분석·탐지·케이스 결과 표시 |
| `favicon.svg` | 프로젝트 아이콘 |

프론트엔드는 별도 빌드 도구 없이 FastAPI가 정적 파일로 제공한다.

### `tests/`

최신 Windows 로컬 기준 421건 통과다. 매개변수별 시험 조건을 포함한 건수이며 코드 커버리지나 탐지 품질 합격을 뜻하지 않는다.

| 영역 | 주요 파일 |
|---|---|
| 모델·시나리오·프롬프트 | `test_models.py`, `test_scenarios.py`, `test_prompting.py` |
| 분석기·정책 | `test_openai_analyzer.py`, `test_hybrid_analyzer.py`, `test_policy.py` |
| API·인증·설정 | `test_api.py`, `test_security.py`, `test_enterprise_config.py` |
| 감사·보증 | `test_audit.py`, `test_assurance.py` |
| OCSF·Sigma·공개 재생 | `test_detection_pipeline.py`, `test_correlation_replay.py` |
| 탐지·사건 품질 | `test_detection_quality.py`, `test_incident_quality.py` |
| 엔터티 상관분석 | `test_entity_graph_correlation.py` |
| 사고 케이스 | `test_incident_cases.py` |
| 연동 아웃박스 | `test_integration_outbox.py` |
| Docker·배포 설정 | `test_docker_setup.py` |
| 반복 평가 | `test_evaluation.py` |
| 제로트러스트·서명 | `test_zero_trust_operations.py`, `test_trusted_signals.py` |
| 추가 회귀 204건 | `zero_trust/test_session_regressions.py`, `test_signal_regressions.py`, `test_api_regressions.py`, `test_identity_regressions.py` |
| 확대 평가기 40건 | `test_detection_benchmark.py` |

새 기능은 정상 경로뿐 아니라 인증 실패, 테넌트 분리, 잘못된 상태 전이, 위변조, LLM 실패 같은 실패 경로도 테스트한다.

### `docs/`

| 위치 | 역할 |
|---|---|
| `README.md` | 계획 주차와 실제 구현 근거를 연결하는 색인 |
| `week03/` | 위협 모델, 이벤트 스키마, 요구사항, 아키텍처 |
| `week04/` | 탐지 조건, 정책 예외, 평가 설계 |
| `week05/` | 비용 없는 Docker 검증 |
| `week06/` | 합성 이벤트, Few-shot, 구조화 출력 |
| `week07/`~`week14/` | 분석기, 정책, API, UI, 성능·오류 진단 산출물 |
| `enterprise-readiness.md` | 현재 통제 상태와 실제 기업 운영 전 필수 게이트 |
| `deep-research-enterprise-secops.md` | 실무 사례·논문 기반 고도화 우선순위 |
| `reference-catalog-enterprise-public-sector.md` | 기업·공공·금융·표준 참고자료 목록 |
| `zero-trust-operations.md` | 제로트러스트 원칙·코드·시험·실환경 한계 |
| `mentoring-priority-roadmap.md` | 멘토링 M1~M8·인프라 I1~I8·남은 주간 일정 |
| `team-responsibilities.md`, `roles/`, `역할분담_주간계획_한눈에보기.md` | 공동 경계·개인 계획·주간 역할 표 |
| `model-candidate-review.md` | Jev·Laya 등을 포함한 작업별 AI 비교 후보 |
| `technology-selection-plan.md`, `technology-decisions/` | 도구 C01~C10 비교 계획·선정 대장·빈 양식 |
| `benchmark-results/` | 개선 전 개발/평가 예측·오류·지표 JSON 원자료 |

보고서나 발표자료의 성과 문구는 코드만 보고 추정하지 말고 해당 주차 문서를 근거로 작성한다.

### `infra/`

| 파일 | 역할 |
|---|---|
| `ecr.yaml` | ECR 저장소와 이미지 스캔 설정 |
| `lambda.yaml` | Lambda 컨테이너, IAM 인증 함수 URL, 실행 역할, DynamoDB 저장 구성 |

이 폴더는 실제 AWS 리소스를 만들 수 있다. 사용자 요청 없이 배포하거나 삭제하지 않는다.

### `scripts/`

| 파일 | 역할 |
|---|---|
| `test-docker.ps1` | Docker 안에서 Ruff, pytest, API 스모크 테스트 실행 |
| `deploy-aws.ps1` | AWS 계정 `172585182454` 확인 후 이미지 빌드·ECR 업로드·CloudFormation 배포 |
| `local_signal_collector.py` | 별도 임시 키를 쓰는 루프백 서명 수집기 시연 |
| `build_detection_benchmark.py`, `evaluate_detection_benchmark.py` | 합성 평가 자료 생성·검증·개선 전 성능 보고 |

배포 스크립트는 비용과 외부 상태 변경을 일으킬 수 있으므로 명시적인 배포 요청이 있을 때만 실행한다.

### `runtime/`

실행 중 생성되는 다음 로컬 상태를 담는다.

- `audit.jsonl`: 분석 결과와 검토 이력
- `cases.jsonl`: 사고 케이스와 상태 변경 이력
- `integration-outbox.jsonl`: 외부 연동 대기·재시도·완료 상태

파일들은 해시 체인으로 연결된다. 테스트 목적이 아니면 직접 편집하지 않는다. 저장소에 없을 수도 있으며 실행 시 생성된다.

## 6. 실행 방법

### 기존 가상환경 사용

현재 로컬에는 `.venv`가 있다.

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

접속 주소:

- 대시보드: `http://127.0.0.1:8000/`
- API 문서: `http://127.0.0.1:8000/docs`
- 상태 확인: `http://127.0.0.1:8000/health`

### 새 환경 구성

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

### Docker 실행

```powershell
docker compose up --build
docker compose down
```

로컬 Docker는 `rule` 모드, 인증 비활성, 읽기 전용 파일시스템, 비루트 사용자로 실행된다. 감사·케이스·아웃박스 볼륨까지 삭제하려는 경우에만 사용자의 의도를 확인한 뒤 `docker compose down --volumes`를 실행한다.

## 7. 환경변수와 비밀정보

- `.env.example`은 비밀값 없는 설정 예시다.
- `.env.local`은 로컬 전용이며 Git에 포함하면 안 된다.
- 다른 AI는 `.env.local`의 값을 출력, 로그, 문서 또는 커밋에 복사하지 않는다.
- 기본 개발은 `ANALYZER_MODE=rule`로 충분하다.
- OpenAI 또는 하이브리드 모드가 필요할 때만 기존 `.env.local`을 재사용한다.
- AWS 배포에서는 API 키 평문 대신 Secrets Manager ARN을 사용한다.

주요 분석 모드:

```dotenv
ANALYZER_MODE=rule
ANALYZER_MODE=openai
ANALYZER_MODE=hybrid
```

운영 환경에서 `AUTH_MODE=disabled`는 설정 검증 단계에서 거부된다.

## 8. 테스트 기준선

2026년 11월 1일 기존 `.venv`의 Windows 로컬 기준:

```text
pytest: 421 passed, 3 dependency deprecation warnings
ruff:   All checks passed
JavaScript syntax: passed
```

검증 명령:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
```

Docker 포함 종단 검증:

```powershell
.\scripts\test-docker.ps1
```

경고 3건은 현재 Starlette TestClient, AnyIO 별칭, Mangum 이벤트 루프 관련 의존성 폐기 예정 경고다. 테스트 실패는 아니지만 의존성을 갱신할 때 회귀 여부를 확인한다.

최근 컨테이너 시험은 Docker 엔진이 꺼져 있어 실행하지 않았다. 10월 27일 로컬·Docker 177건 통과는 이전 기록이며 Docker 421건을 확인한 것으로 쓰지 않는다.

### 개선 전 탐지 평가

- 기존 공개 원본 12건은 고정 회귀 표본으로 보존한다. 새 합성 자료는 720건(정상360·위협360), 72계열, 고유 신호 패턴631개다.
- 개발·평가 각360건이며 계열·세션·사용자·기기·동일 신호 패턴의 분할 간 중복은 0이다. 라벨은 작성자 부여 상태로 독립 팀 검토가 남아 있다.
- holdout: TP90·FP50·FN90·TN130, 정밀도64.29%·재현율50.00%·F1 56.25%·오탐률27.78%.
- 목표 P/R/F1≥95%, 오탐률≤5%에 미달한다. `gate_passed=false`이며 결과를 좋게 만들기 위한 탐지 수정은 하지 않는다.
- 이는 Sigma 이벤트 경보 품질이며 LLM 또는 PEP 전체 성능이 아니다. 합성 자료를 기업 모집단 성능이나 외부 블라인드 평가로 표현하지 않는다.
- API: `GET /evaluation/detection-benchmark?split=holdout`(viewer), CLI: `python -m scripts.evaluate_detection_benchmark --require-targets`. 목표 미달 시 종료 코드1은 정상적인 품질 게이트 실패다.

전체 방법·불확실성·규칙별 결과는 `docs/week04/detection-and-evaluation.md`와 `docs/benchmark-results/`를 따른다.

### 역할과 일정

채희주는 설계·AI와 인프라 구성/실행/장애 주입/자원·지연·복구 측정/원자료/선정 근거를 주담당한다. 김택희는 백엔드·데이터·앱 지표·기능/상태 시험과 M6 모델 평가 실행기·집계를 담당한다. 공동 통합·상대 재현을 수행하며 예정 배정을 과거 실적으로 소급하지 않는다.

미완료 멘토링 M3 지속 검증→M4 GuardDuty 공식 형식 로컬 입력→M5 안전한 독립 집행을 우선한다. 11/29 기능 동결, 12/6 제출 가능본, 12/7~13 잠정 최종 제출이며 공식 일정은 미확정이다. 대시보드는 자체 개발하고 모델·도구 후보는 비교 계획이지 도입 결과가 아니다.

## 9. 작업 종류별 시작 위치

| 요청 | 먼저 볼 위치 | 함께 확인할 테스트 |
|---|---|---|
| API 추가·수정 | `app/main.py`, `app/models.py` | `tests/test_api.py` |
| 이벤트 모델 변경 | `app/models.py`, `app/scenarios.py` | `test_models.py`, `test_scenarios.py` |
| LLM 프롬프트·출력 | `app/prompting.py`, `app/analyzers/openai_analyzer.py` | `test_prompting.py`, `test_openai_analyzer.py` |
| 위험 분석 로직 | `app/analyzers/`, `app/services/policy.py` | `test_policy.py`, `test_hybrid_analyzer.py` |
| 인증·권한 | `app/security.py`, `app/config.py` | `test_security.py`, `test_enterprise_config.py` |
| 감사 저장 | `app/services/audit.py` | `test_audit.py` |
| OCSF 정규화 | `app/services/ocsf.py` | `test_detection_pipeline.py` |
| Sigma 규칙 | `app/services/sigma.py`, `app/data/sigma/` | `test_detection_pipeline.py` |
| 공개 로그 재생 | `app/services/public_replay.py`, `app/data/replay/` | `test_correlation_replay.py` |
| 사건 상관분석 | `app/services/correlation.py` | `test_entity_graph_correlation.py` |
| 품질 지표 | `detection_quality.py`, `incident_quality.py` | 같은 이름의 테스트 파일 |
| 사고 케이스 | `app/services/cases.py` | `test_incident_cases.py` |
| 외부 연동 상태 | `app/services/integration_outbox.py` | `test_integration_outbox.py` |
| 대시보드 | `app/static/` | API 회귀 테스트와 브라우저 확인 |
| AWS 배포 | `infra/`, `scripts/deploy-aws.ps1` | `test_docker_setup.py`와 계정 확인 |
| 주차 보고서 | `docs/README.md`, `docs/weekXX/` | 코드 커밋과 실제 산출물 대조 |

## 10. 안전·설계 불변 조건

다음 조건은 기능을 추가해도 유지한다.

1. `ground_truth`는 평가 전용이며 분석기와 LLM 입력에서 제외한다.
2. 이벤트의 자유 텍스트는 지시가 아니라 분석 대상 데이터로 취급한다.
3. 고위험, 낮은 신뢰도, 규칙과 LLM이 불일치하는 결과는 사람 검토로 전환한다.
4. 추천 대응은 허용된 열거형 안에서만 선택한다.
5. 고위험 대응은 모의 미리보기·승인 범위다. 제로트러스트 경로의 허용·회수·집행은 local/test 모의 자원에 한정한다.
6. 테넌트가 다른 분석 결과, 케이스, 아웃박스 이벤트에 접근할 수 없어야 한다.
7. 감사·케이스·아웃박스 해시 체인이 손상되면 실패 폐쇄한다.
8. 공개 데이터와 탐지 규칙의 출처, 라이선스, 버전, 해시를 보존한다.
9. `production` 환경은 인증 없이 시작할 수 없다.
10. 실제 AWS 변경, 외부 전송, 유료 API 호출은 사용자의 명시적 요청 범위에서만 수행한다.

## 11. 현재 한계와 다음 우선순위

현재 코드는 기업 도입을 위한 기술 기준선이지 운영 승인이나 보안 인증을 받은 제품이 아니다.

주요 미완료 항목:

- 실제 기업 IdP와 OIDC 역할 매핑 검증
- API Gateway 또는 사내 게이트웨이의 속도 제한·WAF·TLS 정책
- 조직의 개인정보·보존·데이터 지역성 정책 승인
- 더 넓고 독립적으로 라벨된 공격·정상 데이터셋 평가
- 운영 부하, 장애 복구, RTO·RPO, 경보·당직 훈련
- SAST, SCA, SBOM, 이미지 서명, DAST, 외부 침투시험
- 프롬프트 공격과 모델 변경에 대한 승인·롤백 절차
- 실제 SIEM·ITSM 커넥터, 목적지 인증, 재전송·충돌 처리
- 15~16주차 최종 보고서와 발표자료

현재 실행 순서는 [`docs/mentoring-priority-roadmap.md`](docs/mentoring-priority-roadmap.md), 운영 한계는 [`docs/enterprise-readiness.md`](docs/enterprise-readiness.md)를 기준으로 한다. GitHub 업로드 요청은 AWS 배포·새 도구 설치·유료 모델 호출·탐지 개선을 뜻하지 않는다.

## 12. 다른 AI의 권장 작업 절차

1. 이 문서와 `README.md`, 관련 `docs/weekXX/README.md`를 먼저 읽는다.
2. `git status --short --branch`로 사용자 파일과 현재 브랜치를 확인한다.
3. 요청과 관련된 모듈·테스트만 우선 읽는다.
4. 구현 전에 안전 불변 조건과 실제 외부 상태 변경 여부를 확인한다.
5. 코드를 수정하면 같은 영역의 실패 경로 테스트를 추가한다.
6. Ruff와 전체 pytest를 실행한다.
7. 기능 진척과 학사 주차를 구분해 문서를 갱신한다.
8. 실제 키, 개인정보, 기업 로그, AWS 자격증명을 출력하거나 커밋하지 않는다.
9. 배포, 푸시, 실제 외부 연동은 사용자가 요청한 경우에만 수행한다.

## 13. 다른 AI에게 전달할 시작 프롬프트 예시

```text
이 저장소는 아주대학교 파란학기 천안아산역 팀의 zero-trust-llm-secops 프로젝트다.
먼저 AI_HANDOFF.md와 README.md를 읽고, git status와 현재 브랜치를 확인해라.
현재 실제 코드는 v0.17.0까지 구현되어 있지만 학사 주차별 성과는 docs/README.md와
docs/weekXX 문서에 맞춰 구분해야 한다.

실제 계정 차단, 권한 변경, 세션 격리, 외부 SIEM·ITSM 전송은 구현 범위가 아니다.
.env.local의 비밀값을 출력하거나 커밋하지 말고, ground_truth를 분석기 입력에 넣지 마라.
사용자 파일과 기존 변경사항을 보존하고, 작업 후 Ruff와 전체 pytest를 실행해라.
개선 전 탐지 결과를 보존하고 탐지 규칙·임계값을 임의로 개선하지 마라.

이번 요청: [여기에 수행할 작업을 적기]
```

## 14. 가장 먼저 읽을 문서

1. [`README.md`](README.md): 실행 방법, 전체 기능, API 목록
2. [`docs/README.md`](docs/README.md): 계획 주차와 실제 구현 연결
3. [`docs/enterprise-readiness.md`](docs/enterprise-readiness.md): 현재 보안 기준선과 남은 운영 검증
4. [`docs/deep-research-enterprise-secops.md`](docs/deep-research-enterprise-secops.md): 다음 고도화 근거
5. 작업 대상과 관련된 `docs/weekXX/README.md`와 테스트 파일
6. [`docs/zero-trust-operations.md`](docs/zero-trust-operations.md): 핵심 운영 경로와 한계
7. [`docs/mentoring-priority-roadmap.md`](docs/mentoring-priority-roadmap.md): 현재 피드백 우선순위와 비용 경계
