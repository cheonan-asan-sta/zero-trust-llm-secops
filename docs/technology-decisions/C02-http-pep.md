# C02: 독립 문서 서버의 HTTP 접근 집행 비교

11/8 3주차 잔여 묶음: [인프라 조건부 선정·현재 mTLS 부하/복구](../infrastructure-selection-acceptance.md). 채희주가 동시성1/4/8·3반복의576요청(153허용/423거부), gateway장애3회 전달0·새 grant복구, 인증된 관측·37개 인수와 Linux2560개를 검증했다. 과거 후보 비교 지문과 현재 실행 증거를 연결해 C01/C02는 로컬 조건부, C03는 현재 이미지 재검사/앱 영향 독립 대조 전 보류한다. 운영 승인·대안 후보의 현재 부하 새 비교·팀원 독립 재현·3주차 전체 완료와 구분하며 정확한 head/병합 후 CI는 PR을 따른다.

11/6 후속 [지속 실행 경로 고정](../runtime-release-lock.md): 잠정 선택한 NGINX digest와
현재 앱/정책·빌드/실행 구조를 고정하고 재시작 전 불일치를 거부한다. 아래 11/3 비교는 당시
근거로 보존하며 현재 통합 인수·운영 채택·독립 검토를 완료한 것으로 바꾸지 않는다.

작성일: 2026-11-03 · 기준 `aitest` `9f61f35` · `feature/chaeheeju-c02-pep`

채희주 담당 인프라 범위에서 Codex가 도구로 구성·코드 작성·실행·측정을 수행한 기록이다.
팀원의 수동 실행이나 독립 검토 완료로 소급하지 않으며 실제 계정 기록은 PR에 남긴다.

## 기존 구현에서 발전한 점

기존 `/zero-trust/protected-access`는 SQLite 트랜잭션 안에서 현재 세션·호출자·테넌트·자원/행위·정책/출처 지문·키·유효기간·재사용을 검사하고 모의 내용을 반환했다.
이번에는 이 API와 탐지/정책을 그대로 재사용하면서 **별도 프로세스의 합성 문서 서버** 앞에 실제 NGINX `auth_request`와 Envoy HTTP `ext_authz`를 각각 연결한다. 같은 API 안의 모의 내용 반환을 넘어서 프록시와 자원 서버 사이의 집행 경계를 시험하는 로컬 실험이다.

멘토링 반영 계획의 “누가 어떤 자원에 무슨 행위를 하고, 위험 신호 이후 어디서 차단되는가”를 실행 결과와 연결한다. 수집 → 내구 접수 → 기존 worker 처리 → 관련 세션 제한 → 다음 HTTP 접근 거부와 무관 사용자 접근 유지를 연결한다. 실제 멘토의 추가 검토·확인을 받은 것으로 기록하지 않는다.

## 범위와 신뢰 경계

```text
클라이언트 → NGINX 또는 Envoy: GET /documents
               ↓ 매 요청 인증 헤더·세션·단일 사용 grant
             auth bridge → 기존 core API /protected-access
               ↓ core의 허용 트랜잭션 성공 때만 3초짜리 일회용 handoff
프록시 → 별도 문서 서버 → bridge의 서비스 인증된 /consume
          ↑ handoff 원자적 소비 성공 때만 고정 합성 문서 반환

서명된 위험 관찰 → core 내구 inbox → network=none worker → 세션 제한
```

- 자원/행위는 서버가 `zt-demo-documents`/`READ`로 고정한다. 클라이언트의 사용자·테넌트·자원 헤더는 권한을 선택하지 못한다. API key는 기존 core에서 실제 호출자에 매핑한다.
- 원래 grant는 **core에서 한 번 소비**된다. bridge는 같은 정책을 복제하거나 새 권한을 발급하지 않는다. HTTP 200·`allowed is True`·`ACCESS_GRANTED`·정수 버전·local 모드가 모두 맞아야 전달용 난수 handoff를 만든다. 오류·리다이렉트·잘못된 응답에 재시도/허용하지 않는다.
- handoff는 원문을 저장하지 않는 최대 1,024개 RAM 맵, 3초 TTL, GET/path 결합, 잠금 아래 단일 소비 방식이다. 잘못된 경로로 소비하면 해당 handoff도 소모된다. bridge 재시작은 미사용 handoff를 폐기한다.
- 프록시는 고객이 보낸 handoff를 인가 응답으로 덮어쓴다. 문서 서버도 별도 서비스 비밀로 bridge 소비 API를 호출해야 하며, 위조된 허용 헤더만으로 내용을 주지 않는다. 클라이언트 인증 정보는 문서 서버로 전달하지 않도록 설정한다.
- client/auth/core/resource/consume 망은 모두 Docker internal이다. 호스트 포트·관리 포트·Docker socket을 공개하지 않는다. Docker exec 표준입력으로만 시험 요청을 전달한다. UID 10001, 읽기 전용 root, 모든 capability 제거, 권한 상승 금지, CPU/메모리 상한을 검사한다.
- 서명 개인키와 grant는 실행기 RAM에만 있다. 서비스 비밀은 임시 Linux 전용 볼륨의 0600 파일이며 bridge/resource만 읽는다. 공개 등록 파일만 호스트에 저장한다. 기존 `.env.local`을 사용하지 않는다.

## 비교 계약과 재현

[기계 판독 계약](../../infra/pep/contract.json), [고정 이미지](../../infra/pep/tools.lock.json),
[NGINX 설정](../../infra/pep/nginx.conf), [Envoy 설정](../../infra/pep/envoy.yaml),
[bridge/자원 서버](../../scripts/pep_lab.py), [실행기](../../scripts/compare_pep.py)를 함께 확인한다.

```powershell
.venv\Scripts\python.exe -m scripts.compare_pep --directory runtime/c02/reproduce --repeats 3
```

Docker Desktop의 Linux 엔진이 먼저 실행되어 있어야 한다. 외부 이미지를 받는 준비 단계 뒤 실제 서비스는 내부망만 사용한다. 반복마다 새로운 DB·공개키·비밀·세션을 만들고 동일한 앱 이미지와 후보 이미지 지문을 재사용한다. NGINX 1.30.6의 auth_request 빌드 포함 여부도 실제 검사한다. Envoy 1.40.2는 HTTP 인가이며 gRPC 시험이 아니다.

프록시는 각각 CPU 1개·256 MiB·worker 1개다. 공통 지원 서비스 자원은 후보 프록시 자원과 구분한다. 각 후보 3회, 시작 순서를 교대한다. 42개 검사 각각 HTTP 상태, 보호 문서 본문 SHA-256, 실제 자원 서버 전달 수의 전후 차이를 대조한다. 동시 8요청은 정확히 1건만 문서를 받아야 한다. 정상 문서 grant TTL 60초를 바꾸지 않고 만료를 기다리며, 서명 증명 만료와 별도로 시험한다.

시험에는 인증 누락/오류/중복, grant 위조, 미등록 세션, 다른 자원 grant, 타 테넌트·타 운영자, 메서드/쿼리/인코딩·별칭 경로, 헤더 위조, 단일 소비/재사용/동시성, 수동 회수, 서명된 위험 관찰 처리 후 회수, 무관 사용자 유지, 키 폐기, 직접 접근, core/bridge 장애·timeout·재시작이 포함된다.

## 실측과 결정

[공개 실행 증거](../infrastructure-results/c02-windows-20261103.json)에 최종 6회와 준비 과정, 이미지 ID,
소스/정책/설정 지문, 모든 검사와 Docker stats 원자료를 보관한다. 원래 상세 파일은 `runtime/c02/final`이며
서명 개인키·API key·grant·handoff·서비스 비밀은 공개 증거에 포함하지 않는다.

Windows 11 / Python 3.12.9 / Docker Desktop 엔진 29.8.2 / WSL2 Linux, VM CPU 18개·메모리 약 7.55 GiB에서
**각 후보 3회 × 42개 = 총 252개 검사 모두 통과**했다. 각 후보당 검사 요청 시도 147개에는 직접 접근과
자원 내부 probe도 포함한다. 12개만 보호 문서를 받았고 모든 거부 검사는 추가 문서 전달 0건이었다.
지원 서비스는 동일하며 아래 자원 값은 프록시 컨테이너만의 값이다.

| 항목 | NGINX 1.30.6 | Envoy 1.40.2 |
|---|---:|---:|
| 통과 검사 / 반복 | 126 / 3 | 126 / 3 |
| 허용 HTTP 시간 표본 | 12 | 12 |
| 허용 HTTP p50 / p95 | 42.04 / 240.84 ms | 38.01 / 156.15 ms |
| 관측 메모리 최대 추정 | 2.45 MiB | 18.71 MiB |
| 관측 CPU 최대 | 0.38% | 2.16% |
| Docker 자원 표본 / 수집 오류 | 99 / 0 | 100 / 0 |

지연은 동시 단일 소비 시험의 허용 요청도 포함한다. n=12의 p95는 최대값과 같으며, 순차 기능 부하와
고의 장애가 섞인 짧은 실험이다. CPU/메모리는 Docker CLI 표시값을 환산한 관측치다. 처리량·부하 한계·
실서비스 SLA 또는 통계적으로 확정된 우열을 뜻하지 않는다. **이번 관측 지연은 Envoy가 낮았다**는 결과도 보존한다.

후속 로컬 통합의 잠정 후보는 **NGINX auth_request**로 제안한다. 두 후보 모두 같은 안전 조건을 통과했고,
현재 범위가 고정 HTTP GET 자원 하나여서 작은 구성과 낮게 관측된 프록시 메모리 사용을 우선한다.
Envoy는 지연 관측에서 유리했고 향후 gRPC/서비스 간 집행 요구가 실제 생기면 다시 비교한다.
공통 bridge와 RAM ticket의 가용성/운영 부담은 두 후보 모두 남는다. 운영 채택은 확정하지 않았다.

설정 부담은 NGINX의 비기본 auth_request 빌드 여부와 읽기 전용 temp 경로, Envoy의 typed 설정·확장자·
인가 헤더 덮어쓰기·실패/route cache 설정에서 확인했다. 재시작 시험은 미사용 handoff 폐기·grant 환불 없음·
재사용 거부를 검증했으며 복구 시간 SLA나 자원 업무의 분산 원자성을 입증하지 않는다.

신규 경계 회귀 39건을 포함한 전체 **Windows 630건 / Linux Docker 630건**과 Ruff를 통과했다.
기존 경고는 각각 3개/2개다. 이 통과 수는 탐지 정밀도·재현율·F1 95% / 오탐률 5% 목표와 별개이며,
개선 전 탐지 결과·규칙·임계값·정규화·앱 정책은 변경하지 않았다. 시험 컨테이너·볼륨·망은 모두 정리했다.

### 준비 과정에서 확인한 문제

| 구간 | 확인한 문제와 조치 | 최종 반복과의 구분 |
|---|---|---|
| Windows 단위 시험 | 잘못된 서비스 인증 요청에서 본문을 읽기 전에 연결을 닫으면 응답 대신 연결 종료가 관찰됐다. 1 KiB 이내 본문을 읽은 뒤 거부하도록 보완 | 인증 실패가 ticket을 소비/허용하지 않는 회귀 포함 |
| `pilot` | NGINX가 읽기 전용 `/var/cache/nginx/fastcgi_temp`를 만들려다 시작 실패. 모든 temp 경로를 `/tmp`로 고정 | 후보 준비 실패, 유효 반복 0회 |
| `pilot2` | HTTP 서버가 없는 worker에 API-key 모드만 전달해 시작 불가. 기존 C01과 같이 network=none worker만 HTTP 인증 모드를 비활성 | NGINX 34개 후 중단; 통과 반복에 미포함 |
| `pilot3` | NGINX 예비 42개 후 Envoy 시작 실패. YAML을 `.conf`에 마운트하면 JSON으로 해석하는 실제 동작 확인 | 원래 확장자를 유지하도록 수정; 유효 최종 반복에 미포함 |
| `pilot4` | 수정된 Envoy 42개와 구체적인 거부 사유 대조 성공 | 연결 확인용 1회, 최종 3회에 미포함 |

만료 시험은 기존 60초 정책을 유지하면서 grant용 세션을 후반에 발급해, 110초 증명 유효기간 안에서 `GRANT_EXPIRED`를 직접 대조한다. `SIGNAL_PROOF_EXPIRED`는 별도 세션이다. timeout·재시작에 소비한 grant를 재발급하지 않는다. 읽기 전용 Linux 시험 실행기의 Ruff 캐시는 `/tmp`로 지정한 후 전체 검증을 수행했다.

## 한계와 남은 작업

Docker 시작 때 기존 control-plane 컨테이너도 자동 재개됐다. 실험 중 해당 컨테이너를 종료/삭제하지 않았고
후보 자원 통계에 포함하지 않았다. Windows/공유 VM의 배경 부하는 통제하지 못했으므로, 이 실험을 전용
성능 시험으로 해석하지 않는다. 실험 후 Docker Desktop은 시작 전의 종료 상태로 돌리며 기존 자원은 보존한다.

시험 도구는 컨테이너별 Docker exec 표준입력/출력 파이프를 유지하며 요청을 순서대로 구분한다.
이는 클라이언트 실행 준비 비용을 줄이는 방식이고, 지연 값은 해당 프로세스 안의 HTTP 시작부터 응답까지다.
포트 공개·우회 경로를 만들지 않으며 timeout에 재시도하지 않는다. 같은 앱 이미지로 반복하지만 기존
Dockerfile의 base tag와 의존성 범위는 다음 재빌드에서 달라질 수 있다. 실제 이미지 ID와 앱 정책/규칙을
포함한 소스·설정 SHA-256을 확인하며, 바이트 동일 재빌드를 입증한 것으로 사용하지 않는다.

**인가 시점은 기존 core의 SQLite 허용 소비 트랜잭션이다.** 회수가 이 시점보다 먼저 확정되면 다음 인가가 거부된다. 이미 허용된 요청은 최대 3초의 handoff 유효기간 안에 전달될 수 있다. 회수와 자원 업무를 한 분산 트랜잭션으로 처리하거나 진행 중 요청/스트림을 강제 취소하는 구현은 아니다. 전달 실패에도 소비한 grant를 환불하거나 자동 재허용하지 않는다.

합성 파일 1개를 반환하는 로컬/test 실험이다. 앱의 `production` 모드에서 `/zero-trust` 경로가 열리게 바꾸지 않았다. 실제 IdP/EDR, 운영 TLS/mTLS·OIDC 신원 매핑, HA·다중 bridge ticket 저장소, 큰 파일/스트리밍·업무 쓰기 트랜잭션, 장기 부하·실서비스 SLA, 영속 자원 감사, 독립 팀원 재현은 미완료다. 두 프록시의 기본 오류 상태는 다를 수 있고, 안전 조건은 모두 **비-2xx·보호 내용 없음·전달 0건**이다.

채희주 담당 인프라 실행·측정과 기존 김택희 담당 API/worker의 재사용 경계를 유지한다. 김택희의 후속 검토는 API reason code/저널과 자원 전달 기록 대조, 회수 전후 동시성 의미·운영 통합 계약·독립 재현이다. 이번 작업을 팀원 검토 완료로 기록하지 않는다.

## 공식 근거

- [NGINX auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html): 2xx 허용, 401/403 거부, 나머지는 오류라는 상태 계약과 별도 모듈 포함 확인의 근거.
- [NGINX 배포판](https://nginx.org/en/download.html), [공식 Docker 구성](https://github.com/nginx/docker-nginx): 버전·출처 확인. 실제 사용 플랫폼 manifest SHA-256은 lock에 고정한다. 이미지 서명/출처 증명 전체를 검증했다는 의미는 아니다.
- [Envoy 1.40.2 Docker](https://www.envoyproxy.io/docs/envoy/v1.40.2/start/docker): 공식 이미지·읽기 전용/비-root 실행 근거.
- [Envoy 1.40.2 ext_authz 계약](https://www.envoyproxy.io/docs/envoy/v1.40.2/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto): 실패 허용 비활성, 인가 응답 헤더 덮어쓰기, 재시도 미설정의 근거. route cache를 변경하는 후속 필터와 경로별 인가 해제를 추가하지 않는다.
