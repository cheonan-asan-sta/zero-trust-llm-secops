# 로컬 서비스 개인키 자동 교체

2026-11-03 · 기준 `aitest` `e8e7867` · `feature/chaeheeju-private-key-rotation`

[C04 인증서 자동화](certificate-automation.md)의 기존 동일 키 갱신을 보존하고, 명시적으로 활성화하는
**서비스 TLS leaf 개인키 자동 교체**를 추가한다. Codex 도구로 구현·실행·측정하며 팀원 수동 수행이나
독립 검토로 기록하지 않는다. 탐지·정책·정규화·개선 전 평가 결과는 변경하지 않는다.

## 달라진 동작과 범위

| 항목 | 기존 인증서 갱신 | 개인키 교체 모드 |
|---|---|---|
| 개인키 | 기존 키 유지 | 새 EC P-256 키 생성, 공개키 SHA-256이 달라야 함 |
| clientAuth | 유효한 기존 인증서로 mTLS `/renew` | 유효한 기존 인증서로 mTLS `/rekey`, 새 키 CSR |
| serverAuth | 서버별 등록 JWK 서명키로 제한된 `/sign` | 같은 승인 경로에 새 서버 키 CSR 전달, SAN·serverAuth 유지 |
| 서비스 반영 | 동일 경로의 인증서 교체 | 변경 불가능한 세대별 키·인증서 파일 준비 후 profile/config 참조 전환 |
| 이전 신원 처리 | 구 leaf pin 제거 | 구 pin 제거, 구 client serial 자체 폐기 확인, 유예 후 구 파일 제거 |
| 재시작 | 인증서 후보와 publication journal 재사용 | 새 키 파일 경로를 쓰기 전에 journal 기록, 같은 pending 키로 복구 |

대상은 선택한 로컬 mTLS 그래프의 workload와 **관리용 mTLS 인증서 개인키**다. CA 루트/중간 키와
서버 발급을 승인하는 **등록 JWK 서명키**는 이번 자동 교체에서 제외한다. 관리용 mTLS 키와 CA 등록
서명키를 별도 파일로 분리하므로 관리 인증서가 바뀌어도 CA 발급 권한의 공개키 등록은 유지된다.
관리 인증서의 만료·disabled·inhibited를 검사하는 제어기 보호와, CA가 등록 JWK를 승인하는 보호를
구분한다. 관리 인증서 폐기만으로 등록 JWK 권한이 폐기되는 것은 아니다. 해당 권한은 CA 측에서 별도 폐기해야 한다.

제어기는 여러 leaf 키와 전용 등록 서명키에 접근하는 신뢰된 중앙 제어면이다. 독립 workload attestation,
서비스별 키 격리 agent, HSM/외부 secret manager, 운영 Kubernetes PKI를 구현한 것으로 표현하지 않는다.

## 자동 처리와 실패 경계

1. 인증서 만료 전 갱신 조건 또는 `key_rotation.interval_seconds`에 따라 등록된 유효 신원을 선택한다.
   최초 발급이 일부 실패했다면 최초 발급을 먼저 끝낸다. 만료·disabled·기존 binding 제거 신원은 복원하지 않는다.
2. 새 파일 경로를 private journal에 먼저 기록하고 Linux 전용 볼륨에 새 키를 0600으로 저장한다.
   재시작·CA 오류 재시도는 같은 pending 키를 쓴다. CSR/상태에는 개인키 PEM을 넣지 않는다.
3. 실제 CA에서 새 키의 인증서를 받고 발급자 서명·키 일치·SAN·단일 EKU·기간·CA 권한 부재를 검사한다.
   새 키·인증서는 세대별 새 경로에 준비한다. 활성 키나 인증서를 한쪽씩 덮어쓰지 않는다.
4. 새 pin을 겹쳐 등록한 뒤 JSON profile의 키·인증서 참조를 한 파일로 전환한다. NGINX와 Go의 설정도
   동일한 세대의 경로를 가리키도록 전환한다. 여러 서비스의 전환은 분산 원자 트랜잭션이 아니다.
5. 설정과 설정이 참조하는 키·인증서의 해시를 이용해 reload ack를 확인하고 서버별 실제 TLS 지문을 대조한다.
   reload 확인 전에는 구 pin과 구 키 파일을 제거하지 않는다. 준비/전환 도중 중단되면 journal에서 이어간다.
6. 구 pin 제거 후 구 client serial을 기존 인증서의 mTLS로 자체 폐기한다. 일반 client에 다른 serial을 폐기하는
   관리 권한을 주지 않는다. 명시적인 `already revoked` 응답만 재시도 성공으로 처리한다. 원인을 모르는
   403을 폐기 성공으로 취급하지 않는다. CA가 이미 폐기했지만 응답이 유실되고 일반 403만 반환한다면
   확인을 위해 운영자 조정이 필요하다. 이 응답 분기는 단위 검사이며 실제 응답 유실을 주입한 결과는 아니다.
7. 폐기 확인·cleanup 유예 후 관리 목록의 구 키·인증서 파일만 제거한다. 삭제 전 내용이 예상한 구 신원인지
   대조하며 파일이 바뀌었다면 중단한다. 세대·공개키 해시·오류 상태를 공개 상태에 남긴다.

CA 장애 중에는 기존 유효 키/인증서를 유지하며 정상 업무를 계속한다. 활성 키를 자체 서명 키로 바꾸거나
평문으로 우회하지 않는다. CA 복구 후 같은 pending 키로 재시도한다. 폐기 응답 확인이 안 되면 새 세대로
업무를 제공하되 `revoking` 단계와 구 파일을 유지한다. 구 인증서가 만료되어 더 이상 CA 재발급에 쓸 수
없으면 만료 상태를 기록하고 정리할 수 있다. CA의 만료 후 갱신 금지 설정을 전제로 한다.

설정/정책 변경은 단일 publisher와 운영자 pause/ack 규칙을 따른다. 외부 동시 편집·disabled 변경·후보
만료·키 변조·reload 실패는 자동 롤백으로 구 신원을 복원하지 않는다. 중단된 journal의 운영자 조정이
필요할 수 있다. 이전 버전에서 생성한 `assets` 없는 상태는 자동 추측하여 교체하지 않고 명시적 이관이 필요하다.

## 설정과 재현

[설정 예시](../infra/mtls/key-rotation.example.json)는 승인된 서비스 등록·볼륨·CA가 준비된 상태를 전제로 한다.
실제 키/발급 권한은 포함하지 않는다. 기본 동일 키 갱신 실행기는 그대로 유지한다.

```powershell
.venv\Scripts\python.exe -m scripts.test_private_key_rotation --directory runtime/c02/c04/rekey-reproduce --repeats 2
```

시험은 먼저 기존 C04 153개 검사를 실행해 최초 발급·정적 만료·회수·CA 장애·경보 동작을 확인한다.
그 뒤 이전 단계에서 만료/회수한 canary 2개를 계속 제외하고 나머지 신원에 개인키 교체 모드를 적용한다.
운영 예시의 교체 주기는 600초, cleanup 유예는 3초이며 20분 leaf의 로컬 프로필용 예시일 뿐이다.
시험은 60초와 8초로 가속한다. 실제 운영의 키 수명·여유 시간·인증서 수명·부하는 별도 결정해야 한다.

실행기는 호스트 공개 포트 없이 내부 Docker 망/전용 Linux 볼륨·UID 10001·read-only 서비스 TLS 마운트를
사용한다. 개인키와 발급 JWT를 Windows 파일/명령 인수/공개 결과에 쓰지 않는다. 루트 키는 RAM에만 유지한다.
공식 고정 바이너리 다운로드 외에 AWS·유료 모델 호출·실계정 변경·OS CA 설치는 없다. 자기 실험 자원만 정리한다.

## 검증 기록

[공개 실행 원자료](infrastructure-results/c04-key-rotation-windows-20261103.json)와
[개인키 교체 계약](../infra/mtls/private-key-rotation-contract.json)에 실제 결과를 보존했다.
새 CA/상태로 **2회 × 174개 = 348개**를 통과했다. 회당 기존 I2 30개·전체 hop 43개·C04 수명 38개·
개인키 교체 21개·PEP 42개다. 반복 assertion 수이며 고유 공격 348종이나 탐지 정확도 점수가 아니다.

| 검증 | 실제 결과 |
|---|---|
| 교체 대상 | 회당 활성 신원 48개. 기존 50개 중 의도적으로 만료/회수한 canary 2개는 계속 제외 |
| 실제 키 교체 | 모든 대상이 세 차례 이상 교체. 이전/다음 공개키 SHA-256 차이·복제본/인증서 일치·0600 확인 |
| 서비스 적용 | 회당 native Python/NGINX/Go 서버 14개의 새 지문을 실제 TLS에서 대조 |
| 구 키 처리 | 관리 목록의 구 키/인증서 파일 제거, 구 client 인증서로 CA rekey 요청 시 거부 |
| 중단/장애 | reload ack를 막은 활성화 단계에서 실제 제어기 중단·재시작. 같은 pending 키/인증서로 복구. CA 장애 중 현재 키와 업무 유지, 복구 후 교체 완료 |
| 기존 업무/보안 | 교체 후 문서 전달, 위험 관찰→worker→권한 회수→다음 문서 거부, 실제 scrape와 동일 경보 episode의 firing/resolved 유지 |
| 관리 키 분리 | 관리 TLS 키와 14개 등록 JWK 서명키가 다름을 확인. TLS 키 교체 동안 JWK 등록 키 유지 |
| 별도 범위 검사 | 2차 CA에서 다른 서버의 실제 등록 JWK로 교차 발급 요청 시 401. 위 348개에 포함하지 않은 별도 도구 검사 1건 |
| 전체 회귀 | Windows **766건/기존 경고 3개/135.83초**, Linux Docker **766건/기존 경고 2개/96.41초**, Ruff 통과 |
| 정리 | 전체/빠른/초기 3개 시험 프로젝트의 컨테이너·볼륨·네트워크·전용 이미지 태그 잔여 0. 단위 시험 이미지 3개도 제거. 기존 Docker 엔진/다른 클러스터는 보존 |

수명/파일 전환 검사 **27건**을 추가해 해당 단위 검사는 기존 52개에서 79개가 됐다. private PEM은
RAM으로 가로채며 실제 파일의 journal/profile/config 전환·쓰기 전 intent·변조·중단을 검사한다.
실제 CA·키 파일 권한·TLS·NGINX/Go 적용·회수·업무·경보는 Docker 통합으로 확인했다. 두 전체 실행의
입력 지문이 검증 후 현재 소스와 일치함을 재확인했고 앱·탐지·정책·개선 전 품질은 바꾸지 않았다.

초기 전체 시도는 검증 실행기가 초기 `key_generation: null`을 숫자와 비교한 TypeError로 중단됐다.
검증기를 수정한 뒤 실제 신원 3개의 빠른 교체/폐기 시험을 통과하고, 최종 두 전체 실행을 진행했다.
초기/빠른 시험은 위 348개 수치에 섞지 않았고 자원 정리·별도 이미지·소스 지문을 원자료에 남겼다.
도구 보조 실행이며 팀원의 수동 실행이나 독립 재현 완료로 기록하지 않는다.

Linux Python 3.12.15/OpenSSL 3.5.7/Uvicorn 0.54.0과 Windows Python 3.12.9에서 확인했다. WSL Docker의
한 호스트에서 배경 부하를 통제하지 않은 기능 검증으로, 고부하 성능·운영 무중단 SLA를 측정한 결과는 아니다.

## 남은 한계

- 파일 제거는 논리적 unlink다. 디스크 복구 불가능한 소거, 열린 descriptor·프로세스 메모리·백업/스냅샷의
  구 키 제거까지 보장하지 않는다. 제어기와 서비스의 메모리 내 키 취급도 HSM 수준이 아니다.
- 구 client serial의 passive revocation은 CA 갱신/재키잉을 막는다. 기존 TLS 세션을 강제 종료하거나
  Go/NGINX의 CA/SAN 신뢰 구간에 정확한 leaf pin·active CRL/OCSP를 추가한 것은 아니다.
- 구 profile을 읽은 요청이 유예 이후 구 파일을 열면 실패 폐쇄할 수 있다. 모든 요청 무중단이나 기존
  연결의 강제 키 재협상을 보장하지 않는다. 실제 업무/경보 재검증과 전사 서비스 가용성 SLA는 구분한다.
- 루트/중간 CA·등록 JWK 서명키 교체, 실제 workload attestation, HSM·HA·분산 정책 writer·anti-rollback,
  전원 손실 내구성·독립 팀원 재현·운영 배포는 후속이다. 키 유출 사고의 전면 신원 재등록 절차와 정상
  주기 교체도 구분한다.

근거: [공식 rekey 명령](https://smallstep.com/docs/step-cli/reference/ca/rekey/),
[고정 CA 버전의 mTLS/CSR rekey 처리](https://github.com/smallstep/certificates/blob/v0.30.2/api/rekey.go),
[고정 CA 버전의 serial 자체 폐기](https://github.com/smallstep/certificates/blob/v0.30.2/api/revoke.go),
[고정 CLI 버전의 새 키 생성·출력 분리](https://github.com/smallstep/cli/blob/v0.31.0/command/ca/rekey.go).
