# CA 준비 상태와 최초 발급 순서 보장

2026-11-06 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.

[지속 실행 leaf 개인키 교체](persistent-key-rotation.md)의 후속이다. 최초 인증서39개를 발급할 때
CA 초기화가 끝나기 전에 grant를 만들 수 있던 순서를 보완한다. 앱·탐지 판정·평가 데이터는 유지한다.
이 문서의 검사 수는 정밀도·재현율·F1·오탐률 측정이 아니다.

## 실패 기록과 확인한 원리

PR37의 최종 병합 전 CI42181443167/attempt1은 호스트2170/skip2·Docker2172,
앱 전체 복구24·관측72·CA29·rekey22를 통과했다. 병합99bf0ca는 해당 PR head와 Git tree가 같다.
그러나 병합 후 CI42185498165/attempt1은 CA `Runtime.up`에서 `runtime_wait_timeout`으로 실패했다.
첫 CA assertion 전이어서 CA 검사는0개이고 rekey 단계는 실행되지 않았다. 소유 자원은 모두0이다.

실패 진단에는 신원39개가 모두 generation0, 게시 단계 없음, CA/controller와 모든 서비스가 running,
OOM·재시작 없음, reload digest 일치가 남았다. 따라서 이 실행에서 게시 완료 뒤 실패했다고
설명하지 않는다. 초기 PR37 CI42168186247/attempt1의 기동 실패와 별도 Ubuntu 장시간 실행의
만료 대조 실패도 [기존 원자료](infrastructure-results/persistent-key-rotation-20261106.json)에 보존한다.

고정 step-ca v0.30.2는 초기화 종료 시각을 기록하고, JWT의 `iat`가 그보다 이르면 DB의 사용 이력
확인 전에 거부한다. 기존 Compose 기동 반환 직후의 grant 생성에는 CA 준비 완료 경계가 없었다.
근거는 [초기화 시각 설정](https://github.com/smallstep/certificates/blob/v0.30.2/authority/authority.go#L805)과
[발급시각 검사](https://github.com/smallstep/certificates/blob/v0.30.2/authority/authorize.go#L79)다.

로컬 대조에서는 서명·유효기간이 정상인 CA 기동 전 `iat` 토큰의401과 해당 거부 이유를 확인했고,
CA health 경계 뒤 생성한 grant로39개 초기 발급·서버11개 실제 TLS 반영을 확인했다.
이는 누락된 경계와 실패 가능한 메커니즘의 재현이다. 실패 CI의 원문 HTTP 응답은 확보하지 않았으므로
그 CI의 정확한 오류 문구까지 직접 관측했다고 주장하지 않는다.

## 구현한 경계

1. CA를 포함한 기존 서비스를 시작하고 CSR inventory를 만든다. 아직 grant는 만들지 않는다.
2. CA 컨테이너 안에서 고정 root를 사용하는 TLS로 `ca:9000/health`를 조회한다.
   인증서 체인·호스트명 검증과 TLS1.2 이상을 유지하고 credentials는 보내지 않는다.
3. HTTP200·정확한 `status=ok`·1KiB 이내 응답과 UTC Date를 요구한다. Date와 컨테이너 시계는
   5초 이내여야 한다. 연결2초·실행5초·전체 준비 대기30초로 제한한다.
4. 인증된 CA Date를 `iat`로 사용해 기존300초 grant를 만든 뒤 제한 서명키를 메모리에서 지운다.
   그 후 controller를 시작하고 기존180초 초기 발급 검사를 수행한다.
5. 준비를 확인하지 못하면 고정 `authority_health_unavailable`로 중단한다. grant 생성이나 controller
   기동으로 넘어가지 않는다. 이미 초기화한 정상 재시작은 이 절차를 반복하거나 재등록하지 않는다.

`disableIssuedAtCheck`를 사용하지 않는다. TLS·CSR 결합·nonce·DB 재사용 차단, leaf 수명,
90초 관측 대기와180초 발급 대기를 늘려 통과시키지 않는다. CA의 Date는 신뢰하는 CA와 같은
시계 영역에서 확인하는 최초 발급 기준이며, 외부 시간원 검증·악성 CA 관리자 방어의 증거는 아니다.
[고정 버전 health 구현](https://github.com/smallstep/certificates/blob/v0.30.2/api/api.go#L305)을 따른다.

## replay 검사의 양성 대조 보강

CA 재시작 뒤 옛 토큰을 그대로 보내면 DB를 잃어도 오래된 `iat` 때문에 거부될 수 있다.
이 결과만으로 사용 이력이 보존됐다고 결론내리지 않는다. 인수 실행기만 collector 한 신원의 제한
서명키를 시험 프로세스 RAM에 보관해 다음 두 요청을 같은 CSR·현재 유효한 시각으로 재서명한다.

| 대조 | jti | 기대 결과 |
|---|---|---|
| 발급 가능 양성 | 새 nonce | 201 |
| 사용 이력 음성 | 실제 최초 발급에 소비한 nonce | 400/401/403 |

두 요청의 차이는 `jti`뿐이다. 고정 JWK provisioner의 replay 식별자는
[`claims.ID`인 jti](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/jwk.go#L61)다.
최초 발급 직후와 실제 CA/DB 재시작 뒤에 모두 검사하며, 모의 DB 유실 시 검사가 실패하는 단위
대조도 추가한다. 운영 Runtime은 제한 서명키를 계속 보관하지 않는다.

추가 실제 대조는 아직 만료되지 않은 기동 전 토큰을 거부한 뒤 같은 nonce·CSR·나머지 claim에서
`iat`만 현재 CA 시각으로 바꾼 요청을201로 허용해야 한다. 기존 CA29개에 이 검사1개를 더해30개다.
기존 실행29개를30개 성공으로 소급하지 않는다.

## 재현과 검증 기록

```powershell
.venv/Scripts/python.exe -m pytest -q tests/test_ca_bootstrap_readiness.py tests/test_authority_mtls_runtime.py tests/test_authority_diagnostics.py
.venv/Scripts/python.exe -m scripts.test_authority_mtls_runtime --directory runtime/c02/ca-bootstrap-readiness01
```

집중69개(신규18개)와 고정 Ruff0.17.3 검사가 통과했다. 실제 CA30·전체 Linux 회귀 및 정확한
PR head/병합 후 CI의 최종 결과는 [공개 원자료](infrastructure-results/ca-bootstrap-readiness-20261106.json)와
후속 PR 기록을 따른다. 완료 전 실행은 성공으로 기록하지 않는다. 키·JWT·원문 CA 로그는 공개하지 않는다.
소유 프로젝트만 정리하며 기존 kind 컨테이너와 사용자 ZIP은 보존한다. AWS·유료 LLM 호출은 없다.

수정 소스의 최종 로컬 결과: **집중69/신규18, 고정 Linux2190통과·기존 경고2/Ruff 통과,
실제 CA30/30·소유 컨테이너/볼륨/망0**. Linux test image의 app/scripts/pyproject/tests211개
소스 지문도 대조했다. CA30은 DB 원본 복원 뒤 정상 갱신 가능/폐기 이력 보존과 정상 재시작을
포함한다. 이 실행은 base99bf0ca의 커밋 전 작업 트리이며 정확한 clean head CI로 확대하지 않는다.
PR37의 개인키 교체22·관측72와 이번 로컬 CA30을 같은 소스의 실행으로 합산하지 않는다.

CA/JWK 서명키 교체·HA/공유 DB 복구를 이 지속 실행 프로필에 연결하는 일, 실제 앱 JSONL 경로의
정지 경계 연결, native 즉시 폐기 집행·공급망 최종 선정·팀원 독립 인수는 남아 있다.
김택희는 앱 권한/수신함/소비 상태의 독립 재현을 맡으며, 이 실행을 독립 검토 완료로 기록하지 않는다.
기존11/29 기능 동결·12/6 제출 가능본 일정과3주차의 남은 인수 범위를 유지한다.
