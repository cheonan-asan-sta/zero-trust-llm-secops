# C04: 로컬 인증서 발급·갱신 선정 기록

11/4 후속 [관리 전환 재개](../control-transition-recovery.md)는 생존한 신뢰 호스트의 공개 파일
journal과 기존 Docker/lease를 사용한다. 이 선택은 중단된 로컬 전환을 검증 가능한 단계로 이어가기 위한
것이며 분산 consensus나 타 제품 대비 우열이 아니다. 부분 사본·생성 사양/소유 ID를 대조하고 `opening`
이후에는 보안 상태 대조/초기화를 되풀이하지 않는다. 실제 프로세스 종료와 새 요청 소비 보존을 검증한다.

11/4 후속 [관리 영역 이중화](../control-plane-high-availability.md)는 기존 로컬 Docker를 재사용한다.
9개 구성의 두 볼륨 묶음과 peer-first 파일 반영은 키/조정기 상태를 로컬에서 이전하려는 이번 요구에
맞춘 선택이다. 외부 quorum/분산 저장소를 추가하지 않아 공통 호스트 실행기가 남는다. 자동 선출이나
etcd/Patroni와의 동등 조건 측정·성능 우열은 주장하지 않는다. 허용 체크포인트·명시적 봉쇄·불확실한
작업 거부를 검증하며 운영 채택은 독립 재현·물리 분리·관리 장애 복구 조건을 별도 검토한다.

11/4 [DB·서비스 호스트 복구](../ca-db-host-recovery.md)는 같은 PostgreSQL의 물리 동기 복제를 선택한다.
논리 복제·DB 파일 공유를 추가하지 않고 WAL 순서와 remote_apply를 검증한다. 승격은 명시적 정지 증명을
필요로 하므로 Patroni/etcd 자동 선출을 도입한 것으로 기록하지 않는다. 재가입은 기존 primary 파일의
재사용 대신 새 저장소의 `pg_basebackup`을 사용한다. 로컬 privileged DinD는 서로 다른 데몬/저장소의
장애 주입을 위한 선택이며 물리 호스트 분리나 다른 HA 제품과의 성능 우열을 증명하지 않는다.
백업 복원은 최신 독립 보안 checkpoint와 대조하고, 과거 키 세대로의 임의 rollback은 거부한다.
실제 검증은 [33개 검사·Windows/Linux 각 917개·복원 329.891초의 공개 근거](../infrastructure-results/c04-ca-db-recovery-windows-20261104.json)를 따른다.
내부 CA/DB의 재시작 정책은 `unless-stopped`, 봉쇄 대상 외부 host는 `no`로 구분해 검증한다.
초기 재기동·harness 제한·준비 단계·앱 process 시험의 예비 실패는 최종 결과와 분리했다.

후속 [CA 프로세스 고가용성](../ca-high-availability.md)은 기존 step-ca를 2대로 재사용하고 CA 상태만
PostgreSQL에 공유한다. Badger 파일 공유는 동시 접근을 지원하지 않아 제외한다. MySQL도 공식 지원
대안이지만 이번에 실제 설치·성능 비교하지 않았으므로 우열을 주장하지 않는다. PostgreSQL은 로컬 무료
실행·인증서 기반 TLS·격리 수준 제어를 적용할 수 있어 선택했고 노드별 mTLS·SERIALIZABLE을 검증한다.
관리 클라이언트에서 전환해 별도 LB의 장애점을 추가하지 않는다. 단일 주소가 필요한 외부 클라이언트의
LB 이중화나 DB 복제/호스트 HA는 별도다. 기존 수동/단일 CA 결과는 당시 기준선으로 보존한다.

후속 [CA·JWK 자동 교체](../authority-key-rotation.md)는 기존 step-ca를 유지한다. 루트 서명 작업을 일반
발급/leaf 제어기와 분리한 network=none custodian에서 실행하고 공개 서명 계획·겹침 신뢰·이행 barrier를
연결한다. JWK는 발급을 quiesce한 뒤 같은 이름의 등록 공개키를 교체한다. 이름을 보존해야 client의
인증서 기반 갱신이 이어지며, 임의 이름 중복 등록이나 오래된 서명키 허용을 해결책으로 쓰지 않는다.
소프트웨어 보관함 암호도 같은 볼륨에 있으므로 HSM/KMS 보호와 동일하지 않다. 운영/독립 재현은 별도다.
후속 [원자료](../infrastructure-results/c04-authority-rotation-windows-20261103.json)는 새 CA/상태 2회·394개
통합 assertion과 Windows/Linux 각각 전체 818건, 66개 등록 키의 독립 타이머·48개 신원/14개 서버 이행을
기록한다. 별도 루트1→루트2의 새 TLS 거부/정상 대조와 초기 실행기 실패는 최종 합계와 분리했다.

후속 [개인키 교체](../private-key-rotation.md)는 step-ca를 재사용한다. clientAuth의 mTLS `/rekey`와
serverAuth의 기존 제한된 발급 경로에 새 키 CSR을 연결하고, 세대별 파일과 서비스 재적용·구 serial
자체 폐기를 직접 구성한다. 단순 CLI 덮어쓰기는 여러 파일을 한꺼번에 교체하지 않아 서비스 설정 전환을
별도 journal로 연결했다. CA/JWK 관리 키 교체·HSM·운영 PKI 선정은 이 결과에 포함하지 않는다.
후속 실측은 [개인키 교체 원자료](../infrastructure-results/c04-key-rotation-windows-20261103.json)에 있다.
새 CA/상태 2회·348개 통합 assertion과 Windows/Linux 각각 전체 766건을 통과했다. 회당 신원 48개가
3회 이상 교체했고 서버 14개의 TLS와 업무/경보를 확인했다. 초기 검증 실행기 실패는 합계에서 분리했다.

2026-11-03 · 대상: 선택한 로컬 mTLS 운영 경로 · 운영 배포/독립 검토는 별도

사용자가 자동 발급·갱신을 요청해 기존 조건부 시험의 필요 조건이 충족됐다. 수동 CA/교체는 [이전 I2](../i2-service-mtls.md)의
기준선이며, 이번에는 [실행·제약](../certificate-automation.md)에 따라 `step-ca`를 연결한다.

| 요구 | 고정 인증서·수동 교체 기준선 | 로컬 step-ca + 제어기 | 판정 근거 |
|---|---|---|---|
| 서비스 상호 인증 | 기존 mTLS에서 가능 | 기존 mTLS 유지 | TLS 적용만으로 자동화 도구가 필요한 것은 아님 |
| 무인 발급 | 명시적인 드라이버/운영자 키·파일 작업 필요 | 서비스/SAN/용도/CSR에 묶인 일회용 grant | 권한 없는 발급·grant 재사용과 인증 실패 검사 |
| 기한 전 갱신 | 자동 스케줄 없음 | timer + 제한된 재시도 + 상태/journal | 실제 짧은 수명의 고정/자동 인증서 비교 |
| 정확한 leaf pin 배포 | 운영자가 갱신과 함께 맞춰야 함 | 신규 등록→교체/재읽기→구 지문 제거 | CA만 설치해서 해결되지 않아 최소 연결 제어기 추가 |
| 만료/CA 장애 | 만료 시 거부, 수동 복구 필요 | 유효 인증서는 계속 사용, 만료 후 자동 재등록 금지 | 가용성 때문에 신원을 자동 복원하지 않음 |
| 폐기/재시작 | 기존 peer pin 제거 | CA 갱신 거부와 서비스 pin 제거를 구분, DB/journal 재사용 | CA 폐기만으로 즉시 모든 연결 종료를 주장하지 않음 |
| 운영 부담 | 단순한 폐쇄 시험에 적합 | CA DB/키/제어기·reload의 추가 운영 필요 | 자동화 요구가 명시된 이번 범위에 한해 채택 |

선정은 **후속 로컬 기준선으로 step-ca를 채택**하는 것이다. 전사 PKI나 관리형 서비스와 동일 조건의
성능/비용 비교를 했다는 뜻이 아니다. 기존 수동 구성을 삭제하지 않으며 Kubernetes 기반 대안은 이번에
설치·시험하지 않았다. 중앙 제어기의 leaf 키 접근과 단일 writer 규칙, root/issuer 수명 관리·HSM·HA·
전용 만료 경보·독립 재현의 운영 부담을 남은 과제로 기록한다.

실제 고정 버전에서 serverAuth 전용 인증서는 `/renew`가 거부됐다. 서버 EKU를 넓히는 방식 대신
제어면 전용 등록 JWK 키로 서버별 재발급을 제한했다. own-root X5C 대안은 Sign template의 제한이
CA 관리 API 전체의 권한 제한이 되지 않아 최종 구성에서 제외했다. 이 판단은
[X5C AuthorizeRevoke](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/x5c.go)와
[CA revoke 처리](https://github.com/smallstep/certificates/blob/v0.30.2/api/revoke.go)의 검토에 근거하며,
이전 구성에서 교차 폐기 공격을 실제 성공시켰다는 뜻은 아니다. 최종 구성은 일반 client의 다른 신원
폐기와 다른 서버 발급 요청을 실제로 거부하는지 검사한다.

공식 기능: [step-ca](https://smallstep.com/docs/step-ca/), [renew와 서비스 재적용](https://smallstep.com/docs/step-cli/reference/ca/renew/).
실제 우리 구성의 통과 수·실패 이력·실행 이미지와 입력 지문은 최종 공개 실행 증거를 따른다.

최종 실측은 [공개 원자료](../infrastructure-results/c04-certificates-windows-20261103.json)에 있다.
새 CA/상태로 2회·총 306개 통합 검사와 Windows/Linux 각각 전체 739건을 통과했다. 활성 신원 50개의
자동 발급/갱신과 서버 14개의 새 TLS 지문, 정적/자동 30초 인증서의 만료 동작·CA/제어기 재시작·
폐기 유지·권한 경계를 확인했다. 초기/중단 prototype은 최종 합계에서 제외했다. 배경 부하를 통제하지
않았고 수동과 자동의 발급 시점이 달라 속도나 성능 SLA의 우열을 주장하지 않는다.
