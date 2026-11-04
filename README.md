# zero-trust-llm-secops

## 2026년 11월 4일 후속 부모 Docker 데몬 재시작 복구

[부모 데몬 복구](docs/parent-docker-recovery.md)는 장애 전에 보관한 Engine ID/anchor를 대조하고,
같은 데이터 영역의 정지한 전환을 `recover-daemon`으로 이어갑니다. 완료 단계는 양 기록·owner·고정
worker를 먼저 확인해 정지한 worker만 시작하며 새 보안 상태를 되복제하지 않습니다. 살아 있는 미완료
실행기나 사본 충돌은 거부합니다. 실제 격리 데몬 실험·회귀·한계는 연결 문서에 기록합니다.
실제 데몬 재시작 **12회·16개 검사**, 전체 **Windows 1,381 통과·2 건너뜀/Linux 1,383 통과**와 Ruff를 확인했습니다.
일시정지·생존 작업 거부, 완료 후 합성 상태 보존을 검증했고 시험 자원을 정리했습니다. AWS·유료 LLM 호출은 없습니다.
동료 수집기 PR #21을 보존 결합한 최신 회귀는 **Windows 1,465 통과·2 건너뜀/Linux 1,467 통과**와 Ruff 통과입니다.
기존 데몬 실험 이미지와 최신 결합 입력을 구분해 기록했으며, 데몬 핵심 코드 8개는 동일합니다.

## 2026년 11월 4일 후속 전환 실행기 컨테이너 유실 복구

[컨테이너 유실 복구](docs/actor-container-recovery.md)는 기존 실행기 ID의 실제 부재, 남은 전환 기록과
상대 사본·owner·예약 자원의 일치를 확인한 뒤 `recover-takeover`로 같은 작업을 이어갑니다.
전환 ID/epoch는 유지하고 이전 실행기 ID 이력을 남깁니다. 완료 상태는 다시 복제하지 않아 이후의
토큰 소비를 보존합니다. 기존 `resume-takeover`의 같은 컨테이너 재시작과 구분합니다.
검증 수치와 자원 정리 결과는 연결 문서의 공개 원자료에 기록합니다. 같은 PC/부모 Docker/생존 저장소 조건입니다.
동료 상시 mTLS PR #19를 보존한 결합 회귀는 **Windows 1,354 통과·2 건너뜀/Linux 1,356 통과**와 Ruff 통과입니다.
새 CA 환경의 **43개 통합 검사·컨테이너 실제 삭제 16회**에서 같은 전환 재개와 새 토큰 소비 보존을 확인했고,
시험 전용 자원을 정리했습니다. AWS·유료 LLM 호출 없이 로컬에서 검증했습니다.

## mTLS 기반 로컬 지속 실행

app·수집기·worker·watchdog와 기존 보호 자원 경로를 별도 Docker 프로젝트의 9개 서비스로 실행합니다.
공유 정책 DB와 전용 수집기 spool을 보존하고, 외부 공개 포트 없이 내부 mTLS 경로를 사용합니다.
[실행·상태·종료·장애 검증과 정적 인증서 수명](docs/continuous-mtls-runtime.md)을 확인합니다.
이 프로필의 임시 CA는 정적이며 C04 자동 갱신·교체 통합은 후속 범위입니다.

## 2026년 11월 4일 후속 관리 호스트 전환 실행기 재개

[전환 실행기 중단 복구](docs/executor-transition-recovery.md)는 같은 고정 컨테이너의 PID 1을 다시 시작해
부분 복제·owner 설치·실행기 생성을 이어갑니다. 미완료 전환은 일반 관리 작업을 막고, 완료 후 재실행은
새 상태를 복제 전 시점으로 되돌리지 않습니다. 같은 PC/생존 journal/고정 actor가 남는 명시적 재개입니다.
새 CA 환경에서 operator **30개**·실행기 **15개**·관리 저장소 제거 **2개** 검사와 실제 actor 종료 **16회**를
검증했습니다. 별도 사전 검사는 8+14개이며, Windows 1,152 통과·2 건너뜀/Linux 1,154 통과와 Ruff를 확인했습니다.
완료 후 새 토큰 소비를 보존했고 시험 프로젝트 자원을 정리했습니다. 동료 수집기 PR #16을 보존해 합친 뒤
결합 회귀도 **Windows 1,223 통과·2 건너뜀/Linux 1,225 통과**했습니다. 캠페인과 결합 결과를 구분해 기록합니다.
동료의 세션 재검증 PR #17까지 합친 최신 결합 회귀는 **Windows 1,275 통과·2 건너뜀/Linux 1,277 통과**입니다.
동료 앱 변경과 CA 캠페인 당시 이미지/지문을 구분해 보존했습니다.

## 로컬 관측의 지속 수집

로컬 JSONL의 새 관측을 별도 프로세스가 계속 읽고 SQLite 커서·서명 봉투·접수 확인 상태를 보존합니다.
identity/device 권한을 나누어 기존 M3 수신 API로 전달하며, 재시작·응답 유실에는 저장한 입력을 재전송합니다.
수집기의 202 접수 확인과 서버 worker의 정책 완료는 구분합니다.
접수 확인된 본문은 중복 방지 이력으로 정리하고 완전히 포착한 입력을 회전하며, pending과 중복 이력은 자동 삭제하지 않습니다.
[초기화·공개키 등록·실행·상태 조회와 제한](docs/continuous-signal-collector.md)을 따릅니다.

## 주기적 세션 재검증

별도 watchdog가 요청 없이도 서명 증명 만료를 보류하고, 출처·키 폐기와 등록 변경을 회수 상태로 기록합니다.
새 허용이나 자동 정상화를 만들지 않으며, 같은 DB·공개 등록을 쓰는 local/test 프로세스로 실행합니다.
[실행 명령·상태 전이·감사와 운영 한계](docs/periodic-session-revalidation.md)를 따릅니다.

## 2026년 11월 4일 후속 관리 호스트·전환 기록 이중화

[관리 실행 호스트 이중화](docs/executor-host-high-availability.md)는 신뢰된 실행기 두 개와 별도
journal/owner 저장소를 구성합니다. 대기 우선 저장, 이전 실행기 정지 확인, 새 실행 epoch와 생존 기록
기반 재개를 연결합니다. Windows 캐시 없이 공개 anchor와 지정한 생존 볼륨으로 복원합니다.
같은 PC의 로컬 Docker 장애 시험이며 물리 호스트 HA·자동 선출과 구분합니다.
새 CA 클러스터의 실행기 검사 **15개·관리 저장소 제거 2개**, 별도 사전 실험 **8개**를 통과했습니다.
호스트 전환 2회·옛 실행 저장소 4개/관리 볼륨 18개 삭제 후 같은 키 계획·새 토큰 소비/폐기를 보존했습니다.
Windows 전체 **1,087 통과·1 건너뜀**, Linux 전체 **1,088 통과**와 Ruff를 확인했고, 시험 전용 자원을 정리했습니다.

## 2026년 11월 4일 후속 관리 전환 중단 복구

[관리 전환 재개](docs/control-transition-recovery.md)는 전환 도중 조정기 프로세스가 종료돼도 기록한
대상·단계·객체를 확인하고 같은 전환을 이어갑니다. 미완료 전환 중 일반 관리 작업은 차단하며,
접속 재개 이후에는 새 토큰 소비/폐기 상태를 초기화하지 않습니다. 살아 있는 호스트와 로컬 journal이
필요한 명시적 재개이며 물리 호스트 HA·자동 선출과 구분합니다.
새 클러스터의 **35개** 검사(기존 관리 20·중단 복구 15), 실제 강제 종료 **9회**, Windows 전체
**1019 통과·1 건너뜀**, Linux 전체 **1020 통과**와 Ruff를 확인했습니다. 접속 재개 뒤 새 토큰의
소비가 완료 재실행 후에도 보존됐습니다. 전용 시험 자원·이미지 태그를 정리했고 AWS·유료 모델은 호출하지 않았습니다.

## 2026년 11월 4일 후속 관리 영역 이중화

[관리 영역 이중화](docs/control-plane-high-availability.md)는 키 보관함·조정기·갱신 상태·관문 journal·
백업을 별도 볼륨 두 묶음에 보존합니다. 활성 관리자를 정지/확인하고 준비된 동일 키 교체 계획을 대기
사본에서 이어갑니다. 미완료 작업은 전환을 거부하며, 같은 PC의 로컬 명시적 이전이라는 범위를 유지합니다.
물리 호스트/관리 Docker 데몬 전체 HA·자동 선출·무중단 운영 완료를 뜻하지 않습니다.
새 클러스터의 **20개** 통합 검사, Windows 전체 **961 통과·1 건너뜀**, Linux 전체 **962 통과**와
Ruff를 확인했습니다. 관리 사본 전환 2회·이전 볼륨 18개 삭제·미만료 소비/폐기 거부·백업 인증을
검증했으며 시험 전용 자원과 이미지 태그를 정리했습니다. 비용이 드는 AWS·모델 API는 호출하지 않았습니다.

LLM 기반 지능형 제로 트러스트 보안 오퍼레이션 및 자동화 프레임워크의 시연용 웹 애플리케이션입니다.
합성·공개 보안 이벤트를 정규화·탐지·상관분석하고, 실제 시스템을 변경하지 않는 대응 미리보기를 반환합니다.

다른 AI 또는 개발자가 작업을 이어갈 때는 [프로젝트 인수인계서](AI_HANDOFF.md)에서 현재 브랜치, 폴더별 역할, 안전 원칙, 검증 절차를 먼저 확인합니다.

## 2026년 11월 4일 CA DB·서비스 호스트 복구

[공유 DB·호스트 이중화와 복원](docs/ca-db-host-recovery.md)은 별도 로컬 프로필에서 CA/DB를
독립 Docker 엔진 두 개에 나누고 PostgreSQL 동기 복제, 정지 확인 후 승격, 새 저장소 재가입,
암호화 백업과 최신 토큰 소비·인증서 폐기 체크포인트 대조를 연결합니다.
물리 PC·관리 영역 전체 손실과 앱 서버 전체의 이중화는 후속이며, AWS·유료 모델을 호출하지 않습니다.

새 클러스터의 **33개** 통합 검사와 Windows/Linux 전체 **각 917건**을 통과했습니다.
봉쇄·새 저장소 재가입·writer-stop seal 뒤 두 host 손실의 복원과 양 CA의 정상/거부 대조를 확인했습니다.
복원 관측은 이미지 적재를 포함해 약 330초이며, 조건·예비 실패·운영 한계는 위 문서를 따릅니다.

## 2026년 11월 3일 후속 CA 프로세스 고가용성

[CA 프로세스 고가용성](docs/ca-high-availability.md)은 두 CA와 공유 PostgreSQL, 관리 클라이언트의
연결 장애 전환을 연결합니다. DB에는 별도 노드별 mTLS·서버 이름 검증·최소 권한·SERIALIZABLE 격리를
적용합니다. 모든 CA의 새 issuer/JWK·구 키 거부를 확인해야 자동 키 교체가 완료됩니다.
한 Docker 호스트의 CA 프로세스 장애 대응이며 DB/호스트 이중화·무중단 키 교체와 구분합니다.

```powershell
.venv\Scripts\python.exe -m scripts.test_ca_high_availability --repeats 2 --directory runtime/c02/c04/ha-reproduce
```

새 CA/DB 2회·총 **444개** 통합 검사와 Windows/Linux 전체 **각 870건**을 통과했습니다.
모든 노드의 구 JWK 요청 792개 거부와 실제 부분 배포 중단 복구도 확인했습니다.
HA 가속 canary는 정적/자동 모두 90초이며 이전 30초 실패·재현 조건·운영 한계는
[검증 기록](docs/ca-high-availability.md#검증-기록)에 구분했습니다. 시험 자원은 정리했습니다.

## 2026년 11월 3일 후속 CA·발급 JWK 키 자동 교체

[CA·JWK 자동 교체](docs/authority-key-rotation.md)는 네트워크 없는 관리 작업과 암호화 보관함을 사용해
루트·중간 CA·등록 발급 JWK 키를 별도 타이머로 교체합니다. 신뢰 겹침 배포·발급 pause·새 CA로 leaf
이행·실제 TLS 확인·구 JWK 거부·구 파일 정리를 연결합니다. HSM·물리적 air gap·운영 HA와 구분합니다.

```powershell
.venv\Scripts\python.exe -m scripts.test_authority_key_rotation --directory runtime/c02/c04/authority-reproduce --repeats 2
```

새 CA/상태 2회·총 **394개** 통합 검사, Windows/Linux 전체 **각 818건**과 Ruff를 통과했습니다.
회당 활성 신원 48개·서버 14개를 이행하고 JWK 66개를 각 epoch에 교체했습니다. 별도 루트1→루트2
반복과 새 TLS의 구 루트 거부/현재 루트 200 대조도 통과했으며, [원자료·초기 실패·한계](docs/authority-key-rotation.md)를 남겼습니다.

## 2026년 11월 3일 후속 서비스 개인키 자동 교체

[개인키 자동 교체](docs/private-key-rotation.md)는 새 키·인증서 세대를 준비하고 profile/config 전환·
실제 TLS 확인·구 pin/serial 폐기·구 파일 정리를 연결합니다. 관리용 mTLS 키도 대상이며 CA와 등록 JWK
서명키 교체는 별도입니다. 기존 동일 키 인증서 갱신 경로를 보존합니다.

```powershell
.venv\Scripts\python.exe -m scripts.test_private_key_rotation --directory runtime/c02/c04/rekey-reproduce --repeats 2
```

새 CA/상태로 2회·총 **348개** 통합 검사, Windows/Linux 전체 **각 766건**과 Ruff를 통과했습니다.
회당 활성 신원 48개가 세 차례 이상 키를 교체하고 서버 14개가 새 TLS 인증서를 제공했습니다.
실험 자원은 정리했으며 [원자료·초기 실패·운영 한계](docs/private-key-rotation.md)를 함께 기록했습니다.

## 2026년 11월 3일 후속 인증서 자동 발급·갱신

[인증서 수명 자동화](docs/certificate-automation.md)는 선택한 mTLS 경로에 로컬 step-ca·타이머·지문 배포·
서비스 재적용을 연결합니다. clientAuth 자체 갱신과 서버별 별도 신원으로 제한한 serverAuth 재발급을
구분하며, 만료/폐기/CA 장애에 권한을 자동 복원하지 않습니다. 기존 수동/HTTP 비교 구성은 보존합니다.

```powershell
.venv\Scripts\python.exe -m scripts.test_certificate_automation --directory runtime/c02/c04/reproduce --repeats 2
```

실제 결과·초기 실패·키/운영 범위와 [C04 선정 근거](docs/technology-decisions/C04-certificate-lifecycle.md)를 확인합니다.
새 CA로 2회·총 306개 통합 검사와 Windows/Linux 전체 각각 739건을 통과했습니다. 활성 신원 50개의
자동 발급/갱신과 서버 14개의 새 TLS 인증서를 확인했고, 시험 자원은 정리했습니다.

## 2026년 11월 3일 후속 전체 통신 mTLS

[선택한 로컬 운영 경로 전체 mTLS](docs/all-hops-mtls.md)는 프록시·core·문서 자원·수집기와
Prometheus/Alertmanager 관측 경로, 관리 조회까지 암호화·상호 인증합니다. core도 TLS를 직접 받으며
평문 gateway backend나 관리 포트를 남기지 않습니다. 기존 사용자/API 키·서명·grant 판단은 유지합니다.

```powershell
.venv\Scripts\python.exe -m scripts.test_all_hops_mtls --directory runtime/c02/all-hops/reproduce --repeats 3
```

기존 `compose.yaml`과 C01/C02 후보 비교 명령은 **HTTP 재현 기준선**입니다. 해당 실행을 mTLS 적용
상태로 오해하지 않도록 구분합니다. 위 보안 프로필의 실제 결과·조건·운영 과제는 연결 문서를 확인합니다.
Windows/Linux Docker 각각 전체 687건과 통합 반복 검사 460개(그래프 기준 3회 + 실제 수집기 최종 1회)를
통과했습니다. 실제 위험 관찰의 mTLS 접수→network=none worker 처리→다음 문서 접근 거부를 확인했습니다.

## 2026년 11월 3일 후속 HTTP 접근 집행

후속 [I2 서비스 mTLS](docs/i2-service-mtls.md)는 이 흐름의 PEP→인가 API 경계에 인증서·서비스별 경로·
기존 API 키 검사를 함께 적용합니다. 인증서 교체/폐기와 TLS 실패 시 우회 없는 거부를 로컬에서 시험합니다.
전체 hop 암호화나 운영 CA 배포 완료를 뜻하지 않습니다.

[C02 비교](docs/technology-decisions/C02-http-pep.md)는 기존 단일 사용 grant API와 위험 신호 worker를
재사용해 NGINX/Envoy와 별도 합성 문서 서버를 연결합니다. 직접 접근·헤더 위조·회수·재사용·장애 때
실제 문서가 전달되지 않는지 검증합니다. 로컬 시험이며 운영 채택·TLS·실제 신원 연동·독립 재현은 후속입니다.

## 2026년 11월 3일 후속 관측·경보

[C01 비교](docs/technology-decisions/C01-observability.md)에 기존 viewer 요약 API를 재사용한
읽기 전용 exporter와 공통 경보, Prometheus/Alertmanager 및 VictoriaMetrics/vmalert/Alertmanager의
격리 실행기를 추가했습니다. 지연된 신호·수집 실패·수집기 중단·처리 실패와 복구를 로컬에서 확인합니다.
앱 탐지/정책은 보존하며 경보의 운영 채택·독립 재현은 후속입니다.

## 2026년 11월 3일 후속 공급망 비교·모델 계약

PR #2를 `aitest`에 병합하고 `feature/chaeheeju-c03-supply-chain`에서
[C03 로컬 공급망 비교](docs/technology-decisions/C03-supply-chain.md)와
[M6/C10 후보·평가 계약 초안](docs/m6-evaluation-contract.md)을 추가했습니다.
고정 출처·서명/지문의 두 검사 구성을 같은 이미지에서 비교하며, 새 모델은 실제 호출하지 않았습니다.
도구의 운영 채택·독립 재현·모델 성능 검증은 후속 작업입니다. 기존 탐지 기준선은 보존합니다.

## 2026년 11월 3일 인프라 재현·측정

희주 담당 변경은 `feature/chaeheeju-m3-infra-validation`에서 진행하며
`aitest`를 대상으로 PR 기록을 남깁니다. [담당자 브랜치·PR 절차](docs/contribution-workflow.md)를 따릅니다.
기존 M3 기능을 재사용해 Windows 파일 권한 검사 차이를 보완하고 시험 개인키를 메모리에서만
사용합니다. worker의 네트워크를 제거하고 같은 자원 제한에서 반복 실행·자원·지연 원자료를
남기는 [인프라 측정 실행기](docs/m3-infrastructure-measurement.md)를 추가했습니다.
실제 결과·표본 수·제한은 해당 기록을 확인합니다. 탐지 규칙과 개선 전 품질 결과는 유지합니다.

## 2026년 11월 2일 로컬 개발 변경

`feature/m3-durable-signals`에서 김택희의 이번 주 M3/I1 최소 경로를 구현했습니다.
관찰 종류별 수집기 권한을 검사하고 SQLite에 저장한 뒤 접수하며, 별도 worker가 같은
사용자 또는 기기에 연결된 세션의 허용을 제한·회수합니다. 중복·실패·재시작과 마지막
처리 시도의 완료 기록 유실을 복구하고, 무관한 세션은 유지합니다. 정상 관찰이 새 허용이나
MFA 성공을 증명하지 않으며 위험 제한 해제는 별도 검토 대상으로 남습니다.

입력·오류 예시, 지표, 실행 방법과 M6/M7 평가 계약은
[지속 신호 수신·처리 명세](docs/m3-durable-signals.md)에 있습니다.
[검증 결과](docs/m3-validation-results.md): Python 3.12·3.14에서 각각 전체 518건 통과,
Ruff·Compose 구성 검사 통과. 이후 실제 Docker 앱·worker의 회수·중복·재시작 통합 검사
11개와 Linux 컨테이너의 전체 524건을 검증했습니다. 실행 환경·재현 명령·원자료는
[Docker 검증 기록](docs/m3-docker-validation.md)에 있습니다.
이 변경은 `71cbfc0`을 기반으로 로컬에서 구현·검증했습니다. 실제 IdP/EDR 연동과 AWS 배포는 후속 작업입니다.
아래 v0.17 설명과 이전 인수인계 기록의 상시 수신 미구현 표기는 이 변경 전의 기준선입니다.

## 현재 구현 범위

v0.17은 지속 세션 검증과 로컬 모의 자원 집행에 Ed25519 수집기 서명 검증과 재인증 요청 결합을 추가합니다. 등록된 출처·사용자·기기·역할·키·유효기간을 검증하고, 현재 재인증 요청에 연결된 새 서명이 있어야 허용을 복구합니다. 수집기 설정 변경·키 폐기와 위험 변화는 다음 접근에서 기존 허용을 거부합니다. 대시보드에서 서명 세션의 출처와 재인증 상태를 조회할 수 있습니다. 설정·시연·검증·한계는 [제로 트러스트 운영 구현 명세](docs/zero-trust-operations.md)에 정리했습니다. 서명은 실제 IdP 인증이나 EDR 증명을 대신하지 않으므로 새 경로는 `local`·`test`에서만 제공하며 `production`에서는 비활성화됩니다.

- 제로 트러스트 판단에 필요한 공통 이벤트 모델
- 정상 3건과 위협 5건으로 구성된 합성 이벤트
- ATT&CK 기법·관찰 신호·정상 예외를 포함한 3주차 위협 시나리오 카탈로그
- 설명 문자열과 분리된 실행 가능한 시나리오 탐지 조건
- 승인자·유효기간·대상·용량 범위를 검증하는 정책 예외
- 규칙 기반 위험 분석기
- 확신이 낮은 사례만 LLM으로 교차 검토하는 하이브리드 분석기
- 10개 Few-shot 예시와 OpenAI Structured Outputs 기반 선택형 LLM 분석기
- 정책 안전장치와 대응 미리보기
- 담당자·검토 메모·상태 전환이 포함된 분석가 검토 흐름
- 재시작 후에도 복원되는 JSONL 감사 기록
- AWS 배포 시 DynamoDB에 보존되는 감사 기록
- 단건·최대 20건 병렬 분석과 시나리오 자동 매칭 API
- 정확도·F1·JSON 유효율·평균/P95 응답시간 평가 API
- 제한 병렬 반복 평가와 P50·P95·P99·처리량 측정
- 오류 유형·혼동 행렬·시나리오별 품질 진단
- OIDC·해시 기반 API 키 인증과 역할 기반 접근 제어
- 인증된 테넌트별 분석·감사 결과 격리
- 요청 추적 ID, 보안 헤더, 본문 크기·분석 동시성 제한
- Prometheus 메트릭과 JSONL 감사 로그 해시 체인
- OCSF 1.9.0 Authentication·API Activity 정규화와 원본·매핑 SHA-256 변환 이력
- Sigma 2.1 YAML 규칙의 버전·승인·시험 메타데이터 및 실패 폐쇄형 로컬 탐지 엔진
- 위협 5건·정상 3건 재생 시험과 분석 결과의 규칙집·입력 해시 증적
- 커밋·라이선스·SHA-256이 고정된 Splunk RDP·AWS 인증 실패 및 Microsoft Sentinel 정상 로그 오프라인 재생
- 사용자·IP·기기·자원·탐지 규칙 엔터티 그래프와 5분·30분·24시간 창 기반 OCSF Incident Finding 상관분석
- 동일 증거가 여러 시간창에서 재발견될 때 가장 짧은 창 결과만 남기는 결정적 사고 중복 제거
- 규칙별 혼동행렬·Precision·Recall·F1·오탐률, 파싱 성공률, OCSF 매핑률과 실패 폐쇄형 품질 게이트
- 공개 데이터셋별 사건 Precision·Recall·F1·오상관률, 시간창·그래프·중복 제거 정확도와 재현 지문
- 상관분석 결과를 테넌트별 사고 케이스로 보존하고 신규→분류→조사→봉쇄→해결→종결 순서를 강제하는 수명주기
- 담당자·변경 메모·불변 증거 지문·전체 이력과 낙관적 버전 잠금을 갖춘 케이스 저장소
- 모든 케이스 버전을 결정적 ID의 CloudEvents 1.0 이벤트로 투영하는 테넌트별 연동 아웃박스
- 전달 대기·지수 백오프 재시도·전달 완료·실패 보관 상태, 누락 이벤트 복구와 해시 체인 무결성 검증
- 공공·기업 보안 기준 18개를 구현·부분 구현·계획으로 구분한 기계판독 통제대장
- 완료 통제의 코드·구성·자동 시험 증거를 강제하는 보증 검증기와 준비도 API
- 천안아산역 콘셉트의 한국어 관제 대시보드
- FastAPI 엔드포인트와 자동 테스트
- AWS 계정 보호 장치가 포함된 Lambda 컨테이너 배포 정의
- API 키 없이 전체 검증 가능한 로컬 Docker·Compose 경로

실제 계정 차단, 권한 변경, 세션 격리는 수행하지 않습니다.

## 개발 주차 산출물

수행계획서의 목표와 실제 코드·검증 근거를 연결한 3~14주차 기록은 [주차별 산출물 색인](docs/README.md)에서 확인할 수 있습니다. 기업 적용을 위한 보안 기준선과 남은 운영 검증 항목은 [기업 적용 준비도](docs/enterprise-readiness.md), 실제 사례·논문과 다음 구현 순서는 [고도화 딥 리서치](docs/deep-research-enterprise-secops.md), 국내외 공공기관·금융권·표준·기업 실무 자료와 추가 논문은 [기업·공공부문 참고자료 카탈로그](docs/reference-catalog-enterprise-public-sector.md)에 정리했습니다.

## 기업용 보안 모드

로컬 Docker는 비용 없는 개발 편의를 위해 인증이 꺼진 `local` 환경으로 실행됩니다. 실제 조직 환경에서는 `APP_ENVIRONMENT=production`과 `AUTH_MODE=oidc`를 사용해야 하며, 인증을 끈 프로덕션 설정은 시작 단계에서 거부됩니다.

```dotenv
APP_ENVIRONMENT=production
AUTH_MODE=oidc
OIDC_ISSUER=https://identity.example.com
OIDC_AUDIENCE=zero-trust-secops
OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
ALLOWED_HOSTS=secops.example.com
```

OIDC 토큰은 RS256 서명, 발급자, 대상, 만료시간과 필수 사용자·테넌트·역할 클레임을 확인합니다. 역할은 `viewer`, `analyst`, `responder`, `admin`이며 조회, 분석, 검토 처리, 품질 평가 권한을 분리합니다. 서비스 연동용 API 키 모드도 제공하지만 실제 키 대신 SHA-256 해시만 설정에 보관합니다.

현재 구현은 기업 도입을 위한 기술 기준선입니다. 18개 통제의 요약은 조회 권한으로 볼 수 있지만, 코드·테스트 위치가 포함된 상세 증적은 관리자에게만 공개됩니다. 통제 구현률은 인증이나 규정 준수 선언이 아닙니다. v0.15의 아웃박스는 외부 전송을 기본 비활성화한 로컬 전달 상태 머신이며 실제 SIEM·ITSM으로 네트워크 요청을 보내지 않습니다. 실제 운영 전에는 조직 IdP 연결, API Gateway/WAF 기반 분산 속도 제한, 목적지별 인증·재전송·보존 정책, 장애 복구 훈련과 외부 침투시험을 완료해야 합니다.

## 빠른 시작

PowerShell에서 다음 명령을 실행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

브라우저에서 다음 주소를 엽니다.

- 관제 대시보드: http://127.0.0.1:8000/
- API 문서: http://127.0.0.1:8000/docs
- 상태 확인: http://127.0.0.1:8000/health

테스트는 아래 명령으로 실행합니다.

```powershell
pytest -q
```

## 비용 없는 Docker 실행과 검증

로컬 Docker는 `rule` 모드만 사용하므로 OpenAI API와 AWS 비용이 발생하지 않습니다. 컨테이너는 비루트 사용자, 읽기 전용 파일 시스템, Linux capability 제거, 추가 권한 획득 금지 설정으로 실행됩니다.

```powershell
docker compose up --build
```

브라우저에서 http://127.0.0.1:8000/ 을 열고 사용할 수 있습니다. 종료할 때는 다음 명령을 실행합니다.

```powershell
docker compose down
```

로컬 감사·사고 케이스·연동 아웃박스 기록까지 함께 지우려면 `docker compose down --volumes`를 사용합니다.

Docker 내부 코드 검사·단위 테스트와 실제 API 스모크 테스트를 한 번에 실행하려면 다음 스크립트를 사용합니다. 테스트 컨테이너는 성공 여부와 관계없이 자동으로 제거됩니다.

```powershell
.\scripts\test-docker.ps1
```

## 분석 모드

### 규칙 기반 모드

별도 API 키 없이 실행됩니다. 기본값이므로 초기 개발과 API 연동 시험에 사용합니다.

```powershell
$env:ANALYZER_MODE="rule"
uvicorn app.main:app --reload
```

### OpenAI 모드

프로젝트 루트의 `.env.local`에 환경변수를 설정한 뒤 서버를 다시 시작합니다.
이 파일은 Git에서 제외되며 키는 코드나 저장소에 기록하지 않습니다.

```dotenv
ANALYZER_MODE=openai
OPENAI_API_KEY=발급받은_키
OPENAI_MODEL=gpt-5.4-mini
```

OpenAI SDK는 환경변수의 키를 자동으로 읽으며, 분석 결과는 Pydantic 모델에 맞춘 구조화 출력으로 받습니다.

### 하이브리드 모드

규칙 분석의 신뢰도가 기준값 이상이면 즉시 결과를 반환하고, 애매한 사례만 OpenAI로 교차 검토합니다. API 호출량과 지연을 줄이면서 LLM 호출 실패 시 규칙 결과와 사람 검토 전환으로 안전하게 복구합니다.

```dotenv
ANALYZER_MODE=hybrid
OPENAI_API_KEY=발급받은_키
HYBRID_CONFIDENCE_THRESHOLD=0.85
HYBRID_LLM_TIMEOUT_SECONDS=2.5
```

## 주요 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/health` | 서버와 분석 모드 확인 |
| GET | `/health/live` | 공개 가능한 최소 생존 확인 |
| GET | `/health/ready` | 감사·통제대장·OCSF·Sigma·상관분석·공개 재생·연동 아웃박스 무결성을 포함한 준비 상태 |
| GET | `/assurance/summary` | 통제 구현·증적·검토기한 요약 |
| GET | `/assurance/controls` | 관리자 전용 통제·근거·증적 목록 |
| GET | `/assurance/controls/{control_id}` | 관리자 전용 개별 통제 상세 |
| GET | `/scenarios` | 준비된 합성 시나리오 목록 |
| GET | `/scenarios/{scenario_id}` | ATT&CK 매핑과 관찰 신호를 포함한 시나리오 정의 |
| POST | `/events/simulate` | 합성 이벤트 생성 |
| POST | `/events/normalize` | 입력을 OCSF 1.9.0 이벤트와 변환 이력으로 정규화 |
| POST | `/detections/evaluate` | OCSF 정규화 후 승인된 Sigma 규칙 재생 |
| GET | `/detections/rules` | 규칙 상태·버전·해시·시험 사례 목록 |
| POST | `/incidents/correlate` | 최대 100개 이벤트를 다중 시간창·엔터티 그래프로 연결해 OCSF Incident Finding 생성 |
| POST | `/cases/from-events` | 이벤트 상관분석 후 중복 없는 테넌트별 사고 케이스 생성 |
| GET | `/cases` | 현재 테넌트의 최근 사고 케이스와 상태 조회 |
| GET | `/cases/metrics` | 전체·진행 중·미배정 사고 케이스 집계 |
| GET | `/cases/{case_id}` | 증거 지문과 변경 이력을 포함한 케이스 상세 조회 |
| PATCH | `/cases/{case_id}` | responder 권한으로 버전 확인 후 승인된 다음 상태로 전환 |
| GET | `/integrations/outbox/metrics` | 현재 테넌트의 전달 대기·재시도·완료·실패 보관 집계 |
| GET | `/integrations/outbox` | 상태·처리 가능 시각으로 필터링한 CloudEvents 1.0 전달 기록 |
| POST | `/integrations/outbox/reconcile` | admin 권한으로 케이스 이력의 누락 이벤트를 중복 없이 복구 |
| GET | `/integrations/outbox/{event_id}` | 연동 이벤트와 전달 시도 이력 조회 |
| POST | `/integrations/outbox/{event_id}/attempt` | responder 권한으로 목적지 전달 결과를 기록하고 재시도 또는 실패 보관 처리 |
| GET | `/replay/public/datasets` | 고정된 공개 공격·정상 데이터셋의 출처·라이선스·해시 조회 |
| POST | `/replay/public/run` | 공개 로그 12건의 탐지·오탐·사고 상관분석 회귀시험 |
| POST | `/replay/public/{dataset_id}` | 지정한 공개 데이터셋만 오프라인 재생 |
| GET | `/evaluation/detection-quality` | 공개 정답 표본의 전체·규칙별 탐지 품질과 회귀 게이트 조회 |
| GET | `/evaluation/incident-quality` | 공개 정답 표본의 사건 분류·시간창·그래프·중복 제거 품질 게이트 조회 |
| POST | `/analysis` | 이벤트 위험 분석과 정책 검토 |
| POST | `/analysis/batch` | 최대 20개 이벤트 제한 병렬 분석 |
| POST | `/scenarios/evaluate` | 구조화 조건으로 시나리오 일치도 계산 |
| POST | `/evaluation/run` | 반복 사례 정확도·오류·혼동 행렬·시나리오별 성능 측정 |
| POST | `/response/preview` | 실제 조치 없는 대응 미리보기 |
| GET | `/metrics` | 누적 분석 현황 요약 |
| GET | `/results?limit=20` | 최근 분석 결과 목록 |
| GET | `/results/{event_id}` | 최근 분석 결과 조회 |
| GET | `/internal/metrics` | 관리자 전용 Prometheus 메트릭 |

## 폴더 구조

```text
app/
  analyzers/       규칙 기반 및 OpenAI 분석기
  data/            기계판독 통제대장, Sigma 규칙, 고정 공개 로그 표본
  services/        정책·감사·보증·OCSF·Sigma·공개 재생·탐지 품질·사고 상관분석·케이스·연동 아웃박스 관리
  config.py        환경변수 설정
  main.py          FastAPI 엔드포인트
  models.py        이벤트 및 분석 결과 모델
  scenarios.py     합성 이벤트 8건
  static/           관제 대시보드 화면
tests/             API와 정책 테스트
runtime/           실행 중 생성되는 감사·사고 케이스·연동 아웃박스 기록
docs/week03/       3주차 위협 모델·이벤트 스키마·아키텍처 산출물
docs/week04/       정책 예외·조건 평가·가속 개발 산출물
docs/week05/       비용 없는 로컬 Docker 검증 산출물
docs/week06/       합성 로그·Few-shot·구조화 출력 산출물
docs/week07/       1차 분석 프로토타입 산출물
docs/week08/       하이브리드 분석·감사 저장 산출물
docs/week09/       대응 JSON·정책 실행 엔진 산출물
docs/week10/       리스크·안전 조건·예외 검증 산출물
docs/week11/       통합 API·평가·배포 검증 산출물
docs/week12/       대시보드·분석가 검토·MVP 완료 산출물
docs/week13/       반복 성능 측정·제한 병렬화 산출물
docs/week14/       오류 진단·품질 대시보드 고도화 산출물
docs/enterprise-readiness.md  기업 적용 보안 기준선과 운영 전 검증 게이트
infra/             ECR·Lambda·DynamoDB CloudFormation
scripts/           대상 계정 검증이 포함된 AWS 배포 스크립트
```

## AWS 배포

배포 대상 계정은 `172585182454`, 기본 리전은 서울(`ap-northeast-2`)이다. 배포 스크립트는 현재 AWS 자격 증명의 계정 번호가 다르면 이미지 업로드나 리소스 생성을 시작하기 전에 중단한다.

```powershell
.\scripts\deploy-aws.ps1 -Profile 대상_계정_프로필
```

기본 배포는 API 비용이 들지 않는 `rule` 분석 모드다. `openai`와 `hybrid` 모드는 키를 코드나 명령행 평문으로 전달하지 않고 AWS Secrets Manager의 비밀 ARN을 사용한다.

```powershell
.\scripts\deploy-aws.ps1 `
  -Profile 대상_계정_프로필 `
  -AnalyzerMode hybrid `
  -OpenAIApiKeySecretArn arn:aws:secretsmanager:ap-northeast-2:172585182454:secret:이름
```

배포 구성은 ECR 이미지 스캔, AWS IAM 인증이 필요한 HTTPS Lambda 함수 URL, 최소 권한 실행 역할, 암호화·시점 복구·삭제 방지를 적용한 테넌트 인식 DynamoDB 감사 테이블을 만든다. 모든 분석 모드가 IAM 인증을 요구하며 실제 기업 이벤트나 개인정보를 사용하는 운영 배포에는 별도 OIDC/API Gateway 통합이 필요하다.

## 안전 원칙

- `ground_truth`는 평가 전용이며 분석기 입력에서 제외합니다.
- 이벤트 안의 자유 텍스트는 지시가 아닌 데이터로 취급합니다.
- 고위험 결과와 낮은 신뢰도 결과는 사람 검토로 전환합니다.
- 대응은 허용 목록 안에서 선택하며 결과만 미리보기로 반환합니다.
- API 키와 실제 기업 로그는 저장소에 포함하지 않습니다.
- 구현 완료 통제는 코드 또는 구성과 자동 시험 증거를 모두 요구합니다.
- 통제 준비도는 현재 증거의 상태이며 인증·규정 준수 판정을 대신하지 않습니다.

## 참고한 공식 문서

- [OpenAI API Quickstart](https://developers.openai.com/api/docs/quickstart)
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [OCSF 1.9.0 Incident Finding](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/events/findings/incident_finding.json)
- [Splunk Attack Data](https://github.com/splunk/attack_data)
- [Microsoft Sentinel Sample Data](https://github.com/Azure/Azure-Sentinel/tree/master/Sample%20Data)
