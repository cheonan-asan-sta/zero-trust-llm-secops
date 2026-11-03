# 로컬 인증서 자동 발급·갱신

후속 [CA 프로세스 HA](ca-high-availability.md)는 공유 PostgreSQL·CA 2대·관리 클라이언트 연결 전환을
별도 opt-in 프로필로 추가한다. 아래 단일 CA/CLI 갱신 시험은 당시 기준선이며 DB/호스트 HA와 구분한다.

후속 [CA·발급 JWK 자동 교체](authority-key-rotation.md)는 별도 네트워크 없는 custodian·암호화 보관함·
신뢰 이행 프로필을 추가한다. 아래 RAM 전용 루트·기본 갱신 기록은 당시 기준선이다.

후속 [개인키 자동 교체](private-key-rotation.md)를 별도 opt-in 모드로 추가했다. 아래 동일 키 갱신과
이전 실행 결과는 기준선으로 보존한다. 새 키 모드의 범위·결과·재현은 후속 문서를 따른다.

2026-11-03 · 기준 `aitest` `1775491` · `feature/chaeheeju-certificate-automation`

채희주 담당 인프라 범위에서 Codex가 구현·실행·검증한다. 김택희 담당 앱·탐지·정책·worker를 재사용하며
팀원 수동 실행이나 독립 검토 완료로 기록하지 않는다. AWS·유료 모델·실제 계정·OS 인증서 저장소를 사용하지 않는다.

## 적용 범위

[전체 mTLS 경로](all-hops-mtls.md)의 선택 NGINX·native Python API·Prometheus·Alertmanager 구성에
로컬 `step-ca`와 갱신 제어기를 연결한다. 기존 수동 CA/HTTP 비교 실행기는 재현 기준선으로 보존한다.
운영 배포나 Kubernetes 전체에 설치한 결과가 아니다. **workload leaf 인증서의 발급과 갱신**을 자동화하며
루트/중간 CA 교체와 개인키 rekey는 별도 작업이다. 갱신은 기존 개인키를 유지한다.

제어기 자체는 `python -m scripts.certificate_controller init/run --config /state/config.json`으로 초기화/연속
실행할 수 있다. [설정 예시](../infra/mtls/controller.example.json)는 이미 승인된 서비스 등록·TLS 볼륨·
CA를 연결하는 구조를 설명하며 인증서/키/발급 권한은 포함하지 않는다. 테스트 실행기가 이 준비와
실행을 자동으로 수행하고 마지막에 정리한다. 현재 로컬 프로필의 서버 재발급 수명은 20분으로 고정하고
전용 갱신 신원은 1시간으로 발급한다. 예시 설정은 일반 leaf 만료 400초 전·갱신 신원 1200초 전을 사용한다.
본 회귀 시험은 각각 1190초·3590초 전으로 가속하고, 별도 canary만 30초/22초 전 갱신으로 실행한다.
**시험의 급격한 임계값을 운영 기본값으로 복사하지 않는다**. 운영 수명 정책과 루트/issuer 수명 관리가 별도로 필요하다.

| 구성 | 권한과 보호 범위 |
|---|---|
| 오프라인 루트 | 임시 루트 개인키는 시험 드라이버 RAM에만 유지. 온라인 CA/제어기 볼륨에 복사하지 않음 |
| 온라인 `step-ca` | 암호화된 중간 CA 개인키·시작 암호·DB를 전용 Linux 볼륨 0600으로 보관. 루트 개인키·서비스 개인키 없음 |
| 최초 발급 권한 | 서비스 이름·단일 SAN·client/server 용도별 JWK provisioner. 최초 bootstrap 서명 개인키는 드라이버 RAM에만 유지 |
| bootstrap grant | 짧은 수명의 일회용 JWT를 정확한 CSR SHA-256에 연결. 제어기 전용 볼륨/표준입력으로 전달하고 발급 응답 저장 후 삭제 |
| 갱신 제어기 | leaf 개인키·공개 pin 정책을 관리하는 **신뢰된 중앙 제어면**. 여러 서비스 망/인증서 볼륨에 접근하지만 CA 개인키·Docker socket은 없음 |
| 서버별 갱신 권한 | `renew-<서버명>`에 연결된 서명키의 공개키를 CA에 등록. 제어면 전용 Linux 볼륨에만 보관하며 발급 결과를 해당 서버의 이름/SAN/serverAuth로 고정. 관리 신원 인증서도 mTLS로 기한 전 갱신하지만 업무 역할은 없음 |
| 서비스 프로세스 | 자기 TLS 볼륨을 읽기 전용으로 사용. NGINX/Go 재적용 확인용 별도 ack 볼륨만 쓰기 허용 |
| 일반 클라이언트/worker | CA 망에 직접 접근하지 않음. 기존 정상 클라이언트 망 분리와 `network=none` worker 유지 |

중앙 제어기가 여러 leaf 개인키를 취급하는 로컬 구조다. 서비스별 agent/하드웨어 키 저장소/실제 workload
attestation을 구현한 것으로 표현하지 않는다. CA 발급 요청은 서버 인증 TLS와 CSR에 묶인 JWT로 인증한다.
clientAuth 자체 갱신은 mTLS다. **실제 step-ca 0.30.2는 serverAuth 전용 인증서의 `/renew`를 거부**하므로
서버는 별도의 제어면 전용 JWK 서명키로 `/sign` 재발급을 받는다. CA는 등록된 공개키의 서명과
정확한 CSR 결합을 검증하고 발급 대상 이름·SAN·serverAuth를 고정한다. 일반 client나 다른 서버의
서명키는 이 발급 권한을 쓸 수 없다. 범용 own-root X5C provisioner는 CA 관리 API 권한을 넓힐 수 있어
최종 구성에 설치하지 않는다. 다른 사용자의 인증서를 폐기하려는 일반 client 요청도 거부하는지 검사한다.
최초 인증서가 없는 bootstrap을 mTLS로
표현하거나, 갱신을 위해 서버 인증서에 clientAuth 용도를 추가하지 않는다. 업무 통신의 mTLS는 유지한다.
로컬 CA 시작 암호도 같은 전용 볼륨에 있으므로 외부 secret manager/HSM으로 분리한 보호 수준은 아니다.

## 자동 처리 순서

1. 등록된 활성 profile과 고정 서비스 인증서 목록에서 신원·개인키 일치 여부·기존 권한을 확인한다.
2. 서비스별 CSR을 만들고, 해당 CSR에만 유효한 일회용 grant로 실제 CA에 발급 요청한다.
3. 응답의 발급자 서명·공개키·서비스 이름·SAN·단일 EKU·유효기간·CA 권한 부재를 다시 검사한다.
4. 새 지문을 기존 지문과 함께 등록하고, 같은 개인키에 연결되는 새 인증서를 원자적으로 교체한다.
5. NGINX/Go의 재읽기 ack와 실제 TLS에서 제공되는 새 서버 지문을 확인한다. 재적용 전에는 구 지문을 제거하지 않는다.
6. 짧은 겹침 기간 후 구 지문을 제거하고 세대·만료·오류 상태를 기록한다. 만료 전에 같은 순서를 반복한다.

Python listener/client는 기존 요청별 profile 재확인 기능을 재사용한다. NGINX는 설정 검사를 거쳐
자기 프로세스에 reload를 전달한다. Prometheus/Alertmanager는 자기 자식 프로세스에 SIGHUP을 전달한다.
Docker socket이나 호스트 PID 접근을 서비스에 주지 않는다. CA/SAN 인증을 쓰는 Go/NGINX 구간과
Python의 정확한 leaf pin을 구분하며, 네이티브 Go의 API별 RBAC/개별 leaf 폐기가 추가된 것은 아니다.

## 장애·폐기·재시작 경계

- 유효한 인증서가 있으면 CA 장애 중에도 기존 업무는 계속된다. 발급/갱신 실패에는 제한된 재시도·backoff를 적용하며 평문이나 자체 서명 발급으로 우회하지 않는다.
- 인증서가 만료되면 접근을 거부한다. CA는 clientAuth의 만료 후 자체 갱신을 거부하고 제어기도 만료된 관리 leaf의 자동 재등록을 하지 않는다. 재등록에는 새로 승인된 발급 권한이 필요하다.
- clientAuth serial 폐기는 자체 갱신을 막으며 DB 재시작 뒤에도 확인한다. 서버 재발급 권한은 별도 갱신 신원/provisioner에 있으므로 서버 leaf serial 폐기만으로 그 권한까지 폐기한 것은 아니다. 서버 폐기는 대상과 갱신 신원의 제어기 권한을 함께 끊고 CA 측 발급 권한도 관리해야 한다.
- 즉시 업무 접근 차단에는 peer pin 제거가 별도로 필요하다. CA 폐기만으로 Go의 기존 연결까지 즉시 끊는다고 주장하지 않는다. active CRL/OCSP는 이번 구성에 없다.
- 서버 발급용 JWK 등록은 관리 신원 인증서의 유효기간과 독립이다. 제어기는 만료/disabled 관리 신원을 쓰지 않지만, CA에서 발급 권한을 폐기하려면 해당 provisioner/등록 서명키도 끊어야 한다. 이 키는 CA 관리 계층의 권한이므로 외부 workload에 배포하지 않는다. CA 관리 API의 세분화된 RBAC와 서명키 자동 교체는 별도 운영 과제다.
- 제어기는 이미 없어진 권한 pin을 자동 복원하지 않는다. 폐기 시 제어기를 pause하고 완료 ack를 확인한 뒤 신원을 disabled 처리하고 현재 pin을 제거한다.
- 정책 파일은 단일 제어면이 쓴다. 운영자 변경도 pause/ack 절차를 지켜야 한다. 직접 동시 편집을 지원하는 분산 CAS가 아니다.
- 단일 publisher 잠금과 단계별 journal로 파일 교체 중 재시작을 재개한다. 사용한 grant를 지우기 전에 발급 응답을 저장한다.
- 이 복구 검사는 프로세스/컨테이너 중단 범위다. 호스트의 강제 전원 손실 내구성까지 검증한 결과는 아니다.
- CA가 grant를 소비했지만 응답이 유실된 최초 발급은 자동 재권한 부여로 숨기지 않는다. 발급 결과가 저장되지 않았다면 새 승인 grant가 필요할 수 있다.
- 재적용 실패/예상 밖 정책 변경/진행 중 disabled/후보 만료는 자동 롤백으로 구 신원을 복원하지 않고 중단 상태를 남긴다. 해당 journal의 운영자 조정이 필요하다.

정책 anti-rollback·HSM·HA·루트/중간 CA 수명 관리·키 유출 시 전체 신원 재발급·인증서 전용 운영 경보·
진행 중 업무 취소·독립 팀원 재현은 후속이다. 정상 갱신 자동화와 이 항목들의 완료를 구분한다.

## 로컬 실행과 검증

```powershell
.venv\Scripts\python.exe -m scripts.test_certificate_automation --directory runtime/c02/c04/reproduce --repeats 2
```

먼저 CA/CLI만 빠르게 확인하려면 `--ca-smoke`를 사용한다. 본 실행은 이전 I2 30개·전체 hop 43개·PEP
42개를 재사용하고 실제 자동 발급/타이머/재적용/폐기/장애를 추가로 검사한다. 생성/소비/회수 API와
탐지·정책·정규화·개선 전 품질 지표는 변경하지 않는다.

새 CA 망과 상태/인증서/ack 볼륨은 internal·UID 10001·권한 제거·호스트 포트 비공개로 실행한다.
CA/CLI는 [공식 release와 고정 SHA-256](../infra/mtls/ca-tools.lock.json)을 확인해 사용한다. 공개 release
다운로드에는 인터넷을 쓰지만 유료 서비스 호출·OS CA 설치는 하지 않는다. 이 검사는 Sigstore publisher
서명까지 검증한 결과로 확대하지 않는다. 실행기는 자기 프로젝트 자원만 정리하고 다른 Docker 작업을 중지하지 않는다.

[공개 원자료](infrastructure-results/c04-certificates-windows-20261103.json)에 실행 이미지·입력 지문·
검사·세대/만료·실제 TLS 관측·경보·정리 결과를 보존했다. **새 CA/상태로 2회 × 153개 = 306개**를
통과했다. 회당 기존 I2 30개·전체 hop 43개·인증서 수명 38개·PEP 42개다. 반복 검사 합계이며 고유
시나리오 306종이나 탐지 정확도 점수가 아니다.

회당 활성 신원 **50개**가 실제 CA 자동 발급과 타이머 갱신으로 2세대 이상에 도달했고, native Python/
NGINX/Go 서버 **14개**의 새 지문을 실제 TLS에서 대조했다. 등록된 제어면 서명키 외의 client/다른 서버
키로 발급·타 신원 폐기를 요청하면 거부됐고, 갱신 관리 신원도 업무 역할을 얻지 못했다. CA 장애 중
유효한 업무 경로는 유지하고 만료한 신원은 거부했다. client serial 폐기는 정상 갱신 대조군이 성공하는
CA 재시작 후에도 유지됐다. 기존 위험 관찰→worker 처리→회수→다음 문서 거부와 새 경보 episode의
동일 fingerprint/startsAt firing·resolved도 통과했다.

Windows 전체 **739건/기존 경고 3개**, Linux Docker 전체 **739건/기존 경고 2개**, Ruff를 통과했다.
수명/발급자/키·용도/정책 변경·중단 복구 경계 52건을 추가했다. unit의 공개 인증서/가짜 전송 검증과
Docker의 실제 CA·TLS·재적용 증거를 구분한다. 8개 시험 프로젝트의 컨테이너·볼륨·네트워크·전용 이미지
잔여는 모두 0이었다. 시작 때 실행 중이던 Docker 엔진과 다른 클러스터는 보존했다.

초기 시도는 상태 파일의 첫 조회 경합, serverAuth `/renew` 제한, X5C prototype의 audience 설정으로
중단됐다. 상태를 먼저 게시하고, 실제 버전의 용도 제한을 확인했다. 수정한 X5C prototype은 한 번의
전체 검사를 통과했으나 CA 관리 권한 검토를 위해 중단한 뒤 등록 JWK 방식으로 교체했다. 그 시도의
성공 1회나 빠른 CA 시험을 최종 2회 수치에 섞지 않았고, 중단 시 잔여 자원도 프로젝트 범위를 확인해
정리했다. 최초 unit의 잘못된 발급자 예외 분류도 보완한 뒤 전체 검사를 다시 통과했다.

실제 30초 인증서의 정적 만료와 자동 갱신을 비교하되 발급 시점 차이·한 호스트의 배경 부하가 있으므로
속도 우위나 성능 SLA를 주장하지 않는다. 테스트는 Linux Uvicorn 0.54.0·Python 3.12.15·OpenSSL 3.5.7
및 Windows unit Python 3.12.9 환경이다. 버전 변경 시 native h11/TLS 연결 계약을 다시 확인한다.

## 선정 근거

[C04 선정 기록](technology-decisions/C04-certificate-lifecycle.md)은 기존 수동 기준선과 이번 자동 구성의
요구 충족을 비교한다. `step-ca`는 로컬 HTTP/TLS 서비스에 연결할 수 있고 발급 권한·CSR 제약·갱신·DB
재시작을 직접 시험할 수 있어 선택했다. 별도 Kubernetes를 새로 운영하는 후보의 실측 비교를 완료했다는
뜻은 아니다. 공식 기능 지원과 우리 구성에서의 검증 범위를 나누어 기록한다.

근거: [provisioner와 권한](https://smallstep.com/docs/step-ca/provisioners/),
[CA 설정·만료 후 갱신 금지](https://smallstep.com/docs/step-ca/configuration/),
[고정 X.509 template](https://smallstep.com/docs/step-ca/templates/),
[CLI 갱신·X5C 흐름](https://github.com/smallstep/cli/blob/v0.31.0/command/ca/renew.go),
[X5C 인증과 범위](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/x5c.go),
[CSR fingerprint 검증](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/sign_options.go).
