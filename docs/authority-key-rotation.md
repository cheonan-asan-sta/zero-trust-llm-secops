# 로컬 CA·발급 JWK 서명키 자동 교체

후속 [CA 프로세스 고가용성](ca-high-availability.md)은 공유 PostgreSQL·CA 2대·관리 클라이언트 전환을
추가한다. 키 교체는 모든 노드의 새 issuer/JWK와 구 JWK 거부를 확인하며, 아래 단일 CA 결과는 당시
기준선으로 보존한다. DB/호스트 이중화·무중단 키 교체는 후속 범위와도 구분한다.

2026-11-03 · 기준 `aitest` `4d74f06` · `feature/chaeheeju-authority-key-rotation`

[서비스 개인키 교체](private-key-rotation.md)에 이어 **루트 CA·중간 CA 개인키와 등록된 발급용 JWK 키**를
자동 교체하는 별도 로컬 프로필이다. 기존 수동 CA·동일 키 갱신·leaf 키 교체 실행기는 기준선으로 보존한다.
Codex 도구로 구현·실행·측정하며 팀원의 수동 수행·독립 검토로 기록하지 않는다. 앱·탐지·정책·개선 전
평가 결과를 변경하지 않으며 AWS·유료 모델·실계정·OS 인증서 저장소를 사용하지 않는다.

## 구성과 키 보관

| 구성 | 접근 권한·역할 |
|---|---|
| 신뢰된 호스트 조정기 | 승인된 Docker 객체의 이름·고정 ID·이미지 SHA-256과 전용 볼륨을 지정. 공개 교체 계획·단계·영수증만 호스트 파일에 저장 |
| 네트워크 없는 custodian | 일회성 Linux 작업, `network=none`·UID 10001·read-only root·cap 제거. 암호화된 CA/JWK 보관함을 여는 유일한 자동화 작업. Docker socket 없음 |
| CA/JWK 보관함 | 루트·중간·전체 JWK 개인키를 AES-256-GCM으로 인증 암호화한 세대별 bundle. 고엔트로피 무작위 암호와 bundle을 전용 Linux 볼륨 0600으로 보관 |
| 온라인 step-ca | 현재 중간 CA 키는 암호화 PKCS8·시작 암호와 함께 자기 볼륨에 보관. 루트/JWK 보관함은 마운트하지 않음. DB는 교체·재시작 중 유지 |
| leaf 제어기 | 기존 서비스 TLS 키와 서버별 발급 JWK 사본만 관리. 루트/중간 CA 키·보관함·Docker socket 없음 |
| 서비스 | 자기 TLS 볼륨 읽기 전용. 새 CA 신뢰와 leaf 인증서를 재읽고 기존 서비스별 역할·pin·API 권한을 계속 검사 |

이 프로필에서는 자동 교체를 위해 초기 루트/중간/JWK 키를 신뢰된 호스트 RAM에서 **암호화된 Linux
보관함으로 가져온다**. 기존 C04 프로필의 “루트 개인키 RAM 전용”과 다른 명시적 보관 방식이다.
새 키는 네트워크가 없는 custodian 안에서 생성한다. 초기 가져오기·조정기 자체의 호스트 관리자 권한과
컨테이너/볼륨 접근은 신뢰 경계에 포함된다. 암호도 같은 볼륨에 있으므로 독립 secret manager/HSM이나
물리적 air gap 보호가 아니다. 일반 CA·leaf 컨테이너에 root 보관함을 연결해서 자동화하지 않는다.

현재 등록은 서비스·관리 client/server bootstrap JWK **52개**와 서버 갱신 JWK **14개**, 합계 **66개**다.
모든 등록 키를 교체하되 provisioner 이름·서비스 이름·SAN·EKU·CA 갱신/만료 정책은 유지한다. bootstrap
서명키는 암호화된 보관함에만 두며, 시험용 CSR 결합 grant도 고정 신원/용도로 발급하고 업무 pin을 추가하지 않는다.
서버별 JWK 사본 14개만 제어기 전용 Linux 볼륨 0600에 배포한다. 관리용 mTLS 키와도 별개다.

## 교체 순서

1. leaf 제어기를 pause하고 진행 중 publication이 끝났다는 ack를 기다린다. 호스트 조정기는 단일 파일 잠금으로
   동시 실행을 막고, 만료·회수·disabled 신원을 제외한 승인된 활성 신원 목록을 고정한다.
2. 각 타이머와 만료 여유를 확인한다. 루트를 바꿀 때는 중간 CA도 바꾸고, 중간 CA·JWK만 별도로 바꿀 수도 있다.
   새 키 bundle을 먼저 인증 암호화해 저장한다. 중단 후 같은 후보를 읽으며 이미 준비한 키를 다시 생성하지 않는다.
3. 이전 루트 키로 새 루트/중간·JWK 공개키·고정 발급 범위·연속 세대를 담은 계획에 서명한다. 조정기와 leaf
   제어기는 기존 루트·이전 계획 해시·다음 세대·서명·CA 제약·키 변화·경로·정책 불변 조건을 검증한다.
4. 관리 목록의 CA bundle에 기존/신규 루트·중간 인증서를 겹쳐 배포한다. NGINX/Go의 재읽기 ack와 기존
   서비스의 실제 TLS를 확인한다. 부분 배포 중 중단되면 최초 공개 bundle snapshot으로 이어간다.
5. 발급을 멈춘 상태에서 CA 설정의 중간 키·신뢰 루트·JWK 공개키를 한 설정으로 바꾸고 지정 CA를 재시작한다.
   새 CA 서버 인증서의 발급자를 TLS에서 확인하고 새 bootstrap JWK로 고정 CSR 발급도 확인한다.
6. leaf 제어기의 현재 issuer·서버 JWK 경로·`authority_epoch`을 전환하고 발급을 재개한다. 기존 유효한
   clientAuth는 mTLS rekey, serverAuth는 해당 서버의 새 JWK로 새 CA 인증서를 받는다. 모든 활성 leaf의
   새 발급자·세대, 서버의 실제 TLS 지문과 reload ack를 확인할 때까지 기존 신뢰를 남긴다.
7. 다시 pause/ack를 확인한 뒤 관리 목록 전체의 이전 루트/중간 신뢰를 제거하고 CA도 현재 루트만 신뢰하도록
   재시작한다. 모든 신원의 새 issuer·실제 TLS와 정상 CA 연결을 다시 확인한다.
8. 이전 JWK 66개로 각각 **현재 시각·새 CSR·새 nonce**의 JWT를 만들어 실제 CA에 요청하고 모두 거부되는지
   확인한다. 만료 토큰이나 연결 장애를 키 폐기의 증거로 쓰지 않는다. 이후 정상 CA 연결도 확인한다.
9. 후속 암호화 bundle의 개인키/공개키 일치와 현재 CA·서버 키 파일을 대조하고, 예상한 구 파일의 해시를
   확인한 뒤 이전 암호화 bundle·중간 키·서버 JWK 사본을 제거한다. 별도 `committing` 단계로 재개하므로
   CA 보관함이 이미 전환된 뒤 응답이 유실돼도 새 키를 구 키로 오인해 검사하지 않는다.

JWK 교체는 **발급 pause + 원자적 등록 교체**다. 같은 이름을 중복 등록하거나 구 JWK를 계속 허용하는
grace 기간을 만들지 않는다. client 인증서 갱신은 고정 버전의 `LoadByCertificate`가 provisioner **이름**을
찾는 동작을 이용해 기존 신원을 유지한다. 이름을 바꿔 옛 client 갱신을 끊는 방식과 구분한다.

## 장애·운영 경계

- CA 장애에는 현재 단계와 겹침 신뢰를 유지한다. 이미 유효한 서비스 인증서로 정상 업무는 계속할 수 있다.
  교체 계획·정책·bundle·키 파일이 예상과 다르거나 일부 신원이 이행하지 않으면 신뢰 제거/키 삭제를 중단한다.
- 재시작은 공개 단계 journal과 암호화된 pending bundle에서 이어간다. 후보 생성·trust 일부 배포·CA 전환·
  leaf 활성화·최종 비밀 정리의 경계를 나눠 두며 자동 롤백으로 과거 권한을 복원하지 않는다.
- 완료된 신뢰 제거는 관리 목록의 bundle·CA 설정을 대상으로 한다. OS·브라우저·미등록 서비스·외부 조직·
  백업에 복사된 신뢰까지 자동으로 제거하는 전사 PKI 작업이 아니다. 새 서비스 등록도 단일 조정기 운영 절차를 따라야 한다.
- 구 루트 거부 검증은 새 TLS 연결을 대상으로 한다. 이미 성립한 TLS 연결이나 진행 중 업무를 강제로
  취소하는 기능은 아니다. 기존 요청별 leaf pin/권한 검사와 Go/NGINX의 CA/SAN 신뢰 경계를 구분한다.
- 루트/중간이 이미 만료됐다면 자동 재등록으로 숨기지 않고 명시적 복구가 필요하다. 단계별 시간 초과도 기존
  키/신뢰를 무조건 삭제하지 않는다. 진행 중 종료할 때에는 다음 실행으로 journal을 먼저 재개한다.
- 주기가 아직 오지 않았으면 보관함을 해독하지 않는다. 조정기는 다음 예정 시각을 캐시하며, 기본 300초의 정책
  재확인 한도 내에서 정책 변경을 확인한다. 실험 프로필만 1초로 가속한다.
- 정상 주기 교체와 키 유출 사고 대응은 다르다. 특히 루트 키 유출 시 이전 루트 서명 자체를 독립 승인으로
  신뢰할 수 없으므로 별도 신뢰 채널·사고 복구가 필요하다. 중간 CA만 바꾸고 루트를 유지하면 훔친 구 중간 키의
  체인을 active CRL/OCSP로 막은 것이 아니다. leaf pin·만료·루트 신뢰 제거의 보호 범위를 구분한다.
- 파일 unlink는 디스크·메모리·열린 descriptor·백업의 복구 불가능한 소거가 아니다. 초기 시험 키는 호스트 드라이버
  RAM에도 존재한다. HSM·HA·분산 합의·저장소 rollback 방지·강제 전원 손실 내구성·무중단 SLA는 미완료다.

## 설정과 재현

```powershell
.venv\Scripts\python.exe -m scripts.test_authority_key_rotation --directory runtime/c02/c04/authority-reproduce --repeats 2
```

빠른 CA·서비스 검증은 `--smoke`를 쓴다. 실행기는 신뢰된 초기 등록과 암호화 보관함·공개 host profile을
만들고 자기 Docker 실험 자원을 정리한다. 배포 준비된 프로필을 계속 운영할 때의 조정기 명령은 다음과 같다.

```powershell
.venv\Scripts\python.exe -m scripts.authority_rotation_coordinator once --profile runtime/c02/c04/approved/profile.json
.venv\Scripts\python.exe -m scripts.authority_rotation_coordinator run --profile runtime/c02/c04/approved/profile.json
```

`tick`은 한 단계만 실행해 외부 supervisor에서 재개할 수 있다. 공개 profile은 초기 루트 인증서·프로젝트 식별자·
고정 이미지 SHA-256·CA/leaf 컨테이너의 이름/ID·전용 볼륨 이름을 담는다. 비밀이나 임의 Docker 객체를 넣지 않는다.
초기 보관함 생성은 `authority_custodian.seed_files`를 사용하는 승인된 가져오기 작업이며, 실험 실행기가 이를
자동으로 수행한다. 이것을 범용 운영 CA 가져오기/승인 제품으로 표현하지 않는다.

운영 정책 예시는 루트 365일·중간 30일·JWK 1일, 인증서 수명은 루트 730일·중간 90일과 별도 만료 여유다.
[예시](../infra/mtls/authority-policy.example.json)는 승인된 보관함 초기화의 정책이며 실제 배포 설정은 아니다.
시험은 첫 전체 교체 뒤 중간/JWK 1초, 이후 JWK만 1초로 가속해 독립 타이머 세 종류를 검증한다.

## 검증 기록

[공개 실행 원자료](infrastructure-results/c04-authority-rotation-windows-20261103.json)와
[검사 계약](../infra/mtls/authority-rotation-contract.json)에 실제 결과를 보존했다. 서로 다른 초기 루트와
상태로 **2회 × 197개 = 394개**를 통과했다. 회당 I2 30개·전체 hop 43개·인증서 38개·leaf 키 21개·
authority 23개·PEP 42개다. 반복 assertion 수이며 고유 위협 394종이나 정밀도·재현율 점수가 아니다.

| 검증 | 실제 결과 |
|---|---|
| CA/JWK 교체 | 회당 3 epoch: 루트+중간+JWK → 중간+JWK → JWK만. 각 단계의 키 변화·불변과 고정 발급 범위 확인 |
| JWK 폐기 | 매 epoch 구 JWK 66개로 새 시각·새 nonce·새 CSR의 요청을 만들고 모두 401/403 확인. 두 전체 실행에서 396개 구 키 발급 요청 거부 |
| 신뢰/leaf 이행 | 회당 활성 신원 48개가 새 issuer/epoch으로 이행. 의도적으로 만료/회수한 canary 2개는 계속 제외. native Python/NGINX/Go 서버 14개의 실제 TLS 확인 |
| 관리 경계 | custodian UID 10001·인터페이스 lo만·비밀 파일 0600·socket 없음. 온라인 CA/leaf의 root 보관함 마운트 없음 |
| 오류/중단 | 변조된 계획·이행 전 신뢰 제거 거부. 같은 암호화 후보를 재사용하고 조정기 프로세스 재시작으로 journal 재개. CA 장애 동안 단계/겹침 신뢰와 정상 업무 유지 |
| 업무/경보 | CA/JWK 교체 후 문서 접근·M3 위험 관찰→worker→권한 회수→다음 문서 거부, 실제 scrape와 동일 episode firing/resolved 통과 |
| 비밀 정리 | 활성 후속 bundle/파일을 검증한 뒤 구 sealed bundle·온라인 issuer 키·서버 JWK 사본 제거. 마지막 CA/JWK 파일만 남은 상태 확인 |
| 별도 루트 반복 | 신원 3개의 별도 환경에서 루트1→루트2를 이전 루트 서명으로 검증. JWK를 유지한 root-only 타이머(중간도 함께 교체) 통과. 구 루트1 client는 새 TLS에서 거부(status 0), 현재 루트2 client는 HTTP 200. 위 394개에 포함하지 않은 보조 검사 3건 |
| 전체 회귀 | Windows **818건/기존 경고 3개/137.82초**, Linux Docker **818건/기존 경고 2개/102.43초**, Ruff 통과 |
| 정리 | 전체·보조·초기 5개 시험 프로젝트의 컨테이너·볼륨·네트워크·전용 이미지 태그 잔여 0. 단위 이미지 2개도 제거. 기존 Docker/다른 작업 보존 |

단위 검사 **52건**을 추가했다. 단위 검사에서는 개인키를 RAM에서만 다루고 서명·권한 범위·후속 키 일치·타이머·
중단·신뢰 부분 배포·단일 writer를 검사한다. 실제 step-ca·CA/JWK 거부·파일/인터페이스·TLS·업무/경보는
Docker 통합으로 확인했다. 실행 이미지 안의 핵심 8개 소스와 호스트/가져온 소스의 지문을 실행 전에 대조했고,
실행 후 전체 입력 지문도 다시 확인했다. 앱·탐지·정책·개선 전 품질 원자료는 변경하지 않았다.

초기 신원 3개 빠른 검증은 최종 검증 강화 전에 실행했다. 첫 전체 시도는 루트 전환까지 통과한 뒤, 상속된
TLS 설정 `self.policy`와 타이머 갱신 함수의 이름 충돌로 중단됐다. 함수 이름을 분리하고 같은 조건의 회귀
검사를 추가했다. 첫 별도 루트 반복도 전환 후 정상 대조 요청의 Host 허용 설정이 맞지 않아 중단됐다.
smoke fixture의 호스트를 명시한 뒤 새 소스/이미지로 전체 두 회와 별도 반복을 다시 통과했다. 초기 시도는
최종 합계에서 제외하며 실패·이미지/입력 지문·정리 결과를 원자료에서 분리한다.

Linux Python 3.12.15/OpenSSL 3.5.7/Uvicorn 0.54.0과 Windows Python 3.12.9에서 도구로 수행했다.
배경 부하를 통제하지 않은 한 호스트의 기능 검증이며 성능 SLA·운영 배포·팀원 독립 재현 완료로 기록하지 않는다.

근거: [공식 CA 교체·운영 고려](https://smallstep.com/docs/step-ca/certificate-authority-server-production/),
[복수 루트 설정](https://smallstep.com/docs/step-ca/configuration/),
[고정 버전 JWK 토큰 식별·검증](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/jwk.go),
[고정 버전 인증서의 provisioner 이름 조회](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/collection.go).
