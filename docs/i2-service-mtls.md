# I2: PEP에서 인가 API로 가는 서비스 인증

2026-11-03 · 기준 `aitest` `87f24f6` · `feature/chaeheeju-i2-mtls`

채희주 담당 인프라 범위에서 Codex가 작성·실행·측정한다. 기존 김택희 담당 API·worker를 재사용하며 팀원의 수동 실행이나 독립 검토 완료로 기록하지 않는다. AWS·유료 모델·실계정 변경 없이 로컬에서 검증한다.

## 기존 C02에서 발전한 점

[C02](technology-decisions/C02-http-pep.md)는 프록시와 별도 합성 문서 서버의 단일 사용 집행을 연결했으나 서비스 간 통신은 내부 HTTP였다. 이번에는 **PEP bridge → 인가 API 전용 gateway 구간에 실제 mTLS**를 추가한다. 인증서가 있다는 이유만으로 앱 권한을 주지 않고 서비스 신원·호출 범위와 기존 API 키·테넌트·세션·grant 검사를 모두 통과해야 한다.

```text
클라이언트 → NGINX → PEP bridge
                        ├─ mTLS → 전용 gateway → 격리된 backend망 HTTP → 기존 core API
                        └─ core 허용 후 기존 일회용 handoff
NGINX → 별도 문서 서버 → 기존 서비스 비밀의 handoff 소비
```

bridge는 backend망에 연결하지 않는다. `core`의 평문 주소로 직접 접근할 수 없고, gateway만 mTLS frontend망과 backend망을 잇는다. 시험용 접수·회수·상태 확인은 호스트 권한의 Docker exec 제어 경로이며 이 경로까지 mTLS로 바뀌었다고 표시하지 않는다. 다른 서비스 hop도 아직 HTTP다.

## 검사와 권한 경계

mTLS는 통신 서비스의 인증이다. 이벤트의 Ed25519 출처 서명이나 사용자 MFA를 대신하지 않으며,
수집기 source/key/tenant·신호 신선도 검사는 기존 core가 계속 수행한다.

- Python/OpenSSL의 TLS 1.2 이상, CA 체인·유효기간·인증서 용도(EKU) 검사를 사용한다. 서버 DNS 이름과 서버 leaf 인증서 SHA-256 pin도 검사한다. 올바른 pin만으로 잘못된 이름·만료·용도를 우회할 수 없다.
- 클라이언트는 **서버 체인·이름·pin을 검증한 다음에** API 키와 요청 본문을 전송한다. 리다이렉트·재시도·평문 fallback이 없다.
- gateway는 CA가 유효한 클라이언트도 leaf 지문이 등록되지 않았으면 거부한다. 지문을 서버 소유 `pep-bridge` 또는 `collector` 신원에 매핑한다. 인증서의 CN 문자열이나 요청의 사용자·테넌트·서비스 헤더가 권한을 정하지 않는다.
- `pep-bridge`는 POST `/zero-trust/protected-access`만 호출한다. `collector`는 POST `/zero-trust/signals/evaluate`와 `/zero-trust/signals/inbox`만 호출한다. bridge의 세션 회수·무서명 평가·경로/메서드 별칭은 차단한다. 기존 앱 API 역할은 그대로 별도 적용한다.
- HTTP 처리기가 `//` 경로를 정규화하는 점을 발견해 권한 범위는 실제 요청 행의 원래 target으로 검사한다. API 키 중복·부정확한 길이·전달 인코딩을 거부하며 core에는 필요한 API 키와 JSON 본문만 전달한다.
- 매 연결마다 TLS context를 만들고 매 HTTP 요청마다 서비스 pin 정책을 다시 읽는다. 정책 JSON은 원자적으로 교체하며, 새 인증서/key 파일을 먼저 쓴 뒤 profile을 바꾼다. 세션 재사용·티켓에 의한 오래된 신원 캐시를 사용하지 않는다.
- 새 client pin 등록 → 구/신 인증서 중첩 확인 → 구 pin 제거 → 다음 요청 거부를 시험한다. 서버 인증서 교체 후 구 pin 클라이언트는 API 키를 전송하지 못하며, 명시적으로 새 pin을 배포한 클라이언트만 다시 연결한다. 설정 복구가 폐기한 신원을 자동 복원하지 않는다.

이 폐기는 **해당 gateway의 leaf pin 인가 취소**다. CA의 CRL/OCSP나 조직 전체 폐기 시스템을 구현한 것이 아니다. 이미 허용·전달된 업무의 취소나 분산 트랜잭션도 아니다. C02의 core grant 소비 시점과 handoff TTL 경계는 유지한다.

## 재현과 증거

[계약](../infra/mtls/contract.json), [TLS 경계](../scripts/mtls_transport.py), [실행기](../scripts/test_mtls_infrastructure.py), [PKI fixture](../scripts/mtls_fixtures.py), [회귀](../tests/test_mtls_transport.py)를 확인한다.

```powershell
.venv\Scripts\python.exe -m scripts.test_mtls_infrastructure --directory runtime/c02/i2/reproduce --repeats 3
```

Docker Desktop Linux 엔진이 필요하다. C02 실행기의 기본 HTTP 실험은 유지하고, 별도 I2 실행기가 TLS transport hook을 제공한다. 같은 고정 NGINX와 앱 이미지로 반복하며 독립 Envoy 비교를 다시 수행한 것으로 표시하지 않는다. 반복마다 임시 CA·인증서·DB·볼륨·망을 새로 만든다.

CA 개인키는 메모리에서만 사용한다. leaf 개인키는 메모리와 해당 실험의 Linux 볼륨 0600 파일에만 두며 호스트 키 파일·OS 인증서 저장소·`.env.local`을 사용하지 않는다. unit test의 TLS socket은 신원 stub을 사용하므로 비밀 키를 쓰지 않는다. **실제 암호화/핸드셰이크 증거는 Docker 통합 시험**이다.

모든 망은 internal, 호스트 포트/socket 공개 없음, UID 10001·읽기 전용 root·capability 제거·권한 상승 금지다. gateway 상태 카운터는 컨테이너 loopback 8444에서만 읽는다. 인증서 오류의 상태 코드뿐 아니라 gateway가 HTTP 요청을 받았는지, 실제 core로 전달했는지를 대조한다. 정상 transport 시험의 존재하지 않는 grant는 앱의 기존 403이 기대값이며, 이 403은 TLS 실패와 구분한다.

### 실제 결과

[공개 원자료](infrastructure-results/i2-mtls-windows-20261103.json)에 초기 시도·최종 검사·설정/소스 지문과
프록시 자원 표본을 보관했다. 최종 **3회 × (인증 30개 + C02 42개) = 216개 검사 모두 통과**했다.
실제 정상 문서 전달, 서명된 위험 관찰 처리 후 거부, 무관 사용자 유지, 만료·회수·장애·재시작도 이 TLS
구간을 통과한다. 기존 C02 HTTP 기준선과 Envoy 비교 결과는 과거 기록으로 보존한다.

| 검증 | 실제 결과 |
|---|---|
| 서비스 인증·인증서/설정 교체·범위·직접 접근 | 90개 통과 |
| 기존 PEP 상태·본문 해시·자원 전달 수 대조 | 126개 통과, 정상 전달 총 12건, 거부 검사에서 추가 전달 0건 |
| 관측 TLS / cipher | TLSv1.3 / TLS_AES_256_GCM_SHA384 |
| TLS 진단 중 실제 core 인증 요청 시도 | 24건. 나머지는 gateway 또는 TLS/네트워크 경계에서 거부 |
| 신규 경계 회귀 / 전체 pytest | 25건 추가. Windows 655건·기존 경고 3개, Linux Docker 655건·기존 경고 2개 통과 |
| 코드 검사 / 자원 수집 오류 | Ruff 통과 / 0건 |

환경은 Windows 11·Python 3.12.9·Docker Desktop 엔진 29.8.2·WSL2 Linux다. 같은 앱 이미지로 3회
실행했고 source/정책/설정 SHA-256을 커밋 전 재확인했다. CA와 leaf 키는 반복마다 새로 만들었다.
기존 자동 재개된 control-plane 컨테이너 등 공유 호스트 배경 부하는 통제하지 않았다. 전용 성능 시험이 아니다.
모든 실험 컨테이너·볼륨·망과 자체 시험 이미지 태그를 정리했다. Docker Desktop도 시작 전 종료 상태로 복귀한다.

unit test의 peer socket은 stub이고 실제 TLS 주장은 Docker 통합 결과에 근거한다. 이 통과 수는 탐지
정밀도·재현율·F1/오탐률 목표 달성과 별개다. 앱 탐지·정규화·정책·개선 전 품질 자료는 그대로다.

첫 예비 시험은 13개 이후 중단했다. 기존 core가 없는 세션에 403 `GRANT_INVALID`를 반환하는데 시험 실행기가 404로 예상한 오류였다. 기대값만 기존 API 계약에 맞췄으며 core 동작은 바꾸지 않았다. 단위 시험에서 발견한 `//` 정규화 문제도 보완했다. 예비 시험은 최종 반복 집계에 섞지 않는다.

## C04 인증서 자동화 도입 판단

이번은 수동 발급의 **격리 로컬 기준선**이다. 발급 대상과 수명이 제한된 단일 호스트 시험이므로 step-ca 상시 서비스 설치는 보류한다. 자동 발급/갱신·CA 키 보호·발급 권한·만료 경보·대규모 배포 요구가 확정되면 정적 CA와 step-ca를 같은 조건으로 비교한다. 실제 step-ca 비교나 최종 채택 완료로 표시하지 않는다.

step-ca의 기본 passive revocation은 갱신을 막으며 기존 인증서는 만료까지 유효할 수 있다. 따라서 CA 도입만으로 요청별 접근 취소가 완료되지 않는다. 이번 pin 취소는 그와 구분되는 실험이며 운영 CRL/OCSP 설계는 남아 있다. [공식 폐기 설명](https://smallstep.com/docs/step-ca/revocation/).

## 한계와 후속

collector 인증서는 목적별 호출 범위를 나누는 대조군이다. 실제 수집기의 통신 경로를 TLS로 교체하는
작업이나 collector 전체 수신 파이프라인의 TLS 통합 완료를 뜻하지 않는다.

설정 복구 시험은 **최신 폐기 상태를 포함한 정책**을 다시 올리는 경우다. 과거 허용 정책으로 되돌리는
anti-rollback 방어·서명된 정책 배포·HA 노드 간 동기화는 구현하지 않았다. 관리자가 오래된 pin 목록을
복원하면 폐기했던 인증서가 다시 허용될 수 있어 I4 복원 계약과 운영 정책 버전 관리에서 해결해야 한다.
기록되는 Docker stats는 C02와 같은 프록시 대상이며 gateway 자원/처리량 비교나 SLA 시험이 아니다.

실험용 stdlib gateway이며 인터넷 공개용 서버로 채택하지 않는다. gateway→core는 격리망 HTTP, 다른 C02 hop도 HTTP다. 실제 IdP/기기 증명·운영 TLS 배포·CA 자동화/회전·CRL/OCSP·HA·부하 한계·장기 스트리밍·진행 중 업무 취소·독립 팀원 재현은 미완료다. 서버 pin 배포가 늦으면 정상 클라이언트도 차단되며 무중단 교체 SLA를 주장하지 않는다. OS 시각 신뢰와 키 배포 권한 보호도 운영 전제다.

기존 소스/설정 지문은 실제 입력 바이트 기준이며 Git 줄바꿈과 의존성 재빌드에 따라 달라질 수 있다. 같은 앱 이미지를 반복 사용한 결과와 바이트 동일 재빌드 입증을 구분한다. 탐지 규칙·임계값·정규화·정책·개선 전 낮은 품질 결과는 변경하지 않는다.

다음은 나머지 통신 hop의 신원 경계, 수집기 등록/폐기 운영, 백업·복원 후 회수 상태 보존이다. 김택희의 후속 검토는 API/저널 상태와 새 전송 경계의 대조·독립 재현이며 이번 기록을 검토 완료로 쓰지 않는다.

공식 구현 근거: [Python 3.12 SSL](https://docs.python.org/3.12/library/ssl.html), [HTTP client](https://docs.python.org/3.12/library/http.client.html), [cryptography X.509](https://cryptography.io/en/latest/x509/tutorial/). 암호화 primitive를 직접 구현하지 않고 라이브러리 검증을 사용한다.
