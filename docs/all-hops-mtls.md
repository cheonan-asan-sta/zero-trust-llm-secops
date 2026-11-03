# 선택한 로컬 운영 경로 전체의 mTLS

2026-11-03 · 기준 `aitest` `f7fc48d` · `feature/chaeheeju-mtls-all-hops`

채희주 담당 인프라 범위에서 Codex가 구성·코드 작성·로컬 실행·검증한다. 기존 김택희 담당 앱 API·판단·worker를 재사용하며 팀원의 수동 실행·독립 검토 완료로 소급하지 않는다. AWS·유료 모델·실계정·OS CA 저장소는 사용하지 않는다.

## 이번에 확대한 범위

[이전 I2](i2-service-mtls.md)는 bridge→gateway만 mTLS였고 gateway 뒤와 다른 경로는 HTTP였다.
이번에는 **선택한 NGINX·Prometheus·Alertmanager 로컬 운영 프로필의 모든 서비스 네트워크 연결**에
mTLS를 적용한다. 이전 HTTP 비교 실행기·기본 Compose는 재현용 기준선으로 보존하며 보안 운영 프로필과
구분한다. Envoy·VictoriaMetrics·vmalert의 과거 후보 비교를 mTLS로 재시험한 결과는 아니다.

```text
시험 클라이언트 ─mTLS→ NGINX ─mTLS→ 인증 bridge ─mTLS→ gateway ─mTLS→ native core API
                         └─mTLS→ 문서 자원 ─mTLS→ bridge의 handoff 소비
서명된 수집기 ─mTLS→ gateway ─mTLS→ native core API
exporter ─mTLS→ native viewer API
Prometheus ─mTLS→ exporter
Prometheus ─mTLS→ Alertmanager ─mTLS→ 알림 수신기
관리 probe ─mTLS→ 각 서비스 / 상태 조회
network=none worker ─파일 IPC→ 기존 공유 SQLite·공개 신호 등록
```

core는 Uvicorn에서 TLS를 직접 받는다. HTTPS 앞단 뒤에 평문 core 포트를 남기는 방식이 아니다.
HTTP protocol의 실제 SSL peer를 전송 guard에 넘기고, 호출자 헤더 대신 검증된 인증서 지문으로 서비스
역할·메서드·원래 경로를 검사한다. 앱의 API 키·역할·테넌트·서명·신선도·grant 판단은 그대로 유지한다.
worker의 파일 IPC와 호스트 Docker exec 파이프는 네트워크 TLS 대상이 아니며 worker에는 네트워크가 없다.

## 구간별 신원과 검사

| 통신 | 상호 인증과 추가 권한 검사 | 주요 증거 |
|---|---|---|
| 클라이언트→NGINX | client CA/시간/EKU, 서버 CA/이름/pin. 실제 client 인증서는 인증 subrequest를 통해 bridge의 SHA-256 등록 목록과 대조 | 임의 client 헤더가 실제 인증서를 대체하지 못함. 구 client 등록 해제 후 다음 인증서로 동일한 미소비 grant 사용 |
| NGINX→인증 bridge | 양방향 CA·이름 검증, bridge에서 `proxy-auth` leaf pin/GET 범위 | 호출 인증서 등록 해제 시 core 소비 전 거부 |
| bridge→gateway | 기존 I2의 CA/시간/EKU/서버 이름/pin·서비스 scope·API 키 | 기존 인증/회전 검사 30개 재사용 |
| gateway→core | core 자체 TLS, `api-gateway` leaf pin 및 native ASGI guard, 기존 API 인가 | 서버 pin 오류에 평문 fallback 없음, core peer 등록 해제 후 grant 미소비 |
| NGINX→문서 자원 | 양방향 CA·이름 검증, 자원의 `proxy-resource` leaf pin | TLS 신원 실패 시 내용 전달 0건, 이미 소비한 core grant 환불 없음 |
| 문서 자원→consume bridge | 서버 이름/pin, `resource-consumer` leaf pin과 기존 서비스 Bearer, 일회용 handoff | 신원 등록 해제 시 내용 전달 0건·grant 재허용 없음 |
| 수집기→gateway→core | collector 인증서 scope와 기존 Ed25519 세션/관찰 신호·API 키 | 실제 수집기 `_post`로 정상 입력 평가와 위험 관찰 접수. network=none worker 처리 후 회수·다음 문서 거부 |
| exporter→viewer API | 서버/클라이언트 신원, `metrics-reader` GET scope, 별도 viewer API 키 | 쓰기 거부, 인증 실패에 collection=0·오래된 수치 미제공 |
| Prometheus→exporter | 서버 CA/이름, exporter에서 `scrape-agent` leaf pin, 기존 scrape Bearer | scrape 신원 등록 해제 시 up=0, 정상 read-only 서비스는 유지 |
| Prometheus→Alertmanager | native Go mTLS와 CA/SAN 허용 목록 | 실제 경보 접수 확인, 무인증·잘못된 서비스 SAN 거부 |
| Alertmanager→수신기 | 서버 CA/이름 검증, 수신기에서 `alert-manager` leaf pin과 기존 Bearer | client 등록 해제·잘못된 서버 이름 때 전송 차단. 복구 뒤 같은 경보의 firing/resolved 대조 |
| 관리 상태 조회 | 각각 별도 인증서와 조회 scope. gateway 주 정책과 독립된 mTLS 상태 endpoint | 잘못된 주 TLS 정책에서도 평문 관리 포트 없이 거부 원인 카운터 대조 |

NGINX와 native Go 도구의 서버 인증은 CA와 DNS/SAN 검증이다. Python 호출자는 추가로 서버 leaf pin을
검사한다. Python listener는 leaf pin을 역할에 매핑하며 매 요청 재확인한다. native Go의 CA+SAN 인증을
개별 leaf pin이나 API별 RBAC와 동일하게 표현하지 않는다. 같은 SAN 재발급의 구분·CRL/OCSP·이미 열린
Go TLS 연결의 즉시 종료는 별도 운영 과제다. 고의로 등록을 복구하는 fault 시험과 자동 권한 복구를 구분한다.

## 실행과 재현

[실행기](../scripts/test_all_hops_mtls.py), [native TLS listener](../scripts/mtls_native.py),
[NGINX 설정](../infra/mtls/all-hops-nginx.conf), [기계 판독 계약](../infra/mtls/all-hops-contract.json)을 따른다.

```powershell
.venv\Scripts\python.exe -m scripts.test_all_hops_mtls --directory runtime/c02/all-hops/reproduce --repeats 3
```

Docker Desktop Linux 엔진이 필요하다. 스크립트는 임시 CA와 서비스별 키·등록·데이터·망을 만들고 시험 후
해당 자원만 정리한다. Docker Desktop 전체 종료는 다른 작업과의 충돌을 피하기 위해 실행기 안에서 자동으로
하지 않는다. 이번 실행에서는 시작 전의 종료 상태로 별도 복귀시킨다.

별도 `scripts.local_signal_collector`의 전송 코드도 `--tls-profile`을 지원한다. HTTPS origin이 profile의
host/port와 일치해야 하며 CA·서버 이름·leaf pin 확인 전에 신호를 쓰지 않는다. 설정/인증 실패에
HTTP fallback·자동 재시도·redirect를 하지 않는다. `demo`는 수집기 신호 제출과 접근 소비를 함께
시험하므로 `--access-tls-profile`로 별도 `pep-bridge` 신원을 요구한다. collector 자체의 접근 범위를
넓히지 않는다. TLS profile 없이 실행하는 기존 HTTP demo는 loopback에만 허용한다.

통합 시험은 실제 수집기 `_post`를 컨테이너 안에서 호출해 서명 세션과 지속 관찰을 전송한다.
기존 CLI `init/demo` 전 과정을 새 CA로 자동 재현한 결과로 확대하지 않는다. 지속 관찰은 기존 M3
접수·처리 순서를 그대로 유지하고, 접수 경로만 operator 직접 호출에서 수집기 mTLS로 교체한다.

서명/CA 개인키는 메모리, TLS leaf 개인키는 메모리와 전용 Linux 볼륨 0600 파일에만 둔다. Windows 키
파일·환경 파일·OS trust store를 사용하지 않는다. 호스트 포트·Docker socket 공개가 없고 모든 시험 망은
internal, UID 10001·읽기 전용 root·capability 제거·권한 상승 금지·자원 상한을 적용한다.
신원 검사를 네트워크 분리와 독립적으로 확인하려고, 고의 공격 시험 컨테이너 하나만 여러 내부망에 연결한다.
일반 클라이언트의 core/자원 IP 접근 차단은 별도로 검사한다.

운영 CA나 유료 외부 서비스를 새로 만들지 않는다. 준비 때 공개 공식 release를
HTTPS와 고정 SHA-256으로 확인하며, 이미 검증된 C01 archive를 재사용한다. 이 공개 외부 다운로드에
우리 client 인증서를 요구하는 구조는 아니다. 실제 모델/AWS 통신은 수행하지 않는다.

## 검증 결과

[공개 실행 원자료](infrastructure-results/all-hops-mtls-windows-20261103.json)에 단계별 입력 지문·실행
이미지·검사·경보·정리 결과를 보존했다. 반복마다 새 CA·leaf·DB로 I2 30개 + 새 구간 43개 + 기존
PEP 42개를 실행했다. 전체 mTLS 그래프 기준 3회 **345개**를 통과한 뒤, 실제 수집기 `_post`와
지속 관찰 전송을 연결한 최종 1회 **115개**도 통과했다. 합계 **460개 반복 검사**이며 고유 시나리오
460종이나 탐지 정밀도·재현율 점수를 뜻하지 않는다. 앞선 3회를 최종 수집기 구현의 3회 반복으로
소급하지 않는다. 별도 예비 성공 실행도 이 합계에서 제외했다.

Windows 전체 **687건/경고 3개**, Linux Docker 전체 **687건/경고 2개**, Ruff를 통과했다.
기존 655건에 native guard·backend fallback 20건과 수집기 경계 12건을 추가했다. 경고는 기존
의존성의 폐기 예정 안내다. 실제 수집기 세션 평가 200·지속 관찰 접수 202는 TLSv1.3에서 관측했고,
worker 처리 뒤 해당 세션 거부·무관 사용자 허용을 확인했다. 최종 실행들의 자원 수집 오류와
시험 컨테이너·볼륨·망 잔여는 0이었다. 전용 이미지 태그도 제거하고 Docker Desktop을 종료했다.
기존 공유 클러스터는 삭제하지 않았고 배경 부하를 통제하지 않았으므로 성능 SLA를 주장하지 않는다.

처음 예비 실행은 I2가 교체한 gateway 서버의 새 pin을 수집기 profile에 배포하지 않아 중단했다. 인증 실패를
평문으로 우회하지 않고 시험 구성의 명시적인 새 pin 배포를 보완했다. 예비 실행과 최종 반복은 구분한다.
수집기 HTTPS 지원 중 기존 HTTP loopback 거부 안내의 문구가 바뀌어 회귀 검사 1건이 실패했다.
엄격한 목적지 검사를 유지하며 안내 호환성을 복구한 후 전체 687건을 다시 통과했다.
unit test의 ASGI/peer guard는 실제 공개 인증서와 가짜 전송을 쓰며 비밀 키 파일을 만들지 않는다.
실제 TLS·NGINX·Go 도구·경보 전송의 주장은 Docker 통합 시험에 근거한다.

경보는 이번 장애 구간 이후의 startsAt과 job/instance, fingerprint를 묶어 검증한다. 이전 startup 경보나
다른 장애의 알림으로 통과하지 않는다. 복구 알림도 같은 fingerprint/startsAt이어야 한다. 단순 403 대신
전송 guard 거부, core 사유, grant 소비 상태와 실제 문서 전달 수를 함께 확인한다.

## 남은 운영 과제

전체 mTLS는 선택한 단일 호스트 로컬 실행 프로필의 범위다. 기본 HTTP 비교 구성은 별도로 남아 있다.
실제 운영 배포·조직 IdP/기기 증명·자동 CA 발급/갱신·정책 anti-rollback·HA·장기 부하·실패 없는 키 배포·
진행 중 업무 취소·독립 팀원 재현은 완료되지 않았다. 기존 core의 원자적 grant 소비와 자원 업무를 하나의
분산 트랜잭션으로 바꾸지 않았고, 전송 실패에 이미 소비한 grant를 환불하지 않는다.

native API의 Uvicorn h11 protocol에서 실제 SSL peer를 연결하므로, Uvicorn 버전 변경 때 이 계약을
재검증해야 한다. 실제 Docker TLS 실행은 Uvicorn 0.54.0/Python 3.12.15/OpenSSL 3.5.7이고,
Windows unit 환경은 Uvicorn 0.52.4/Python 3.12.9/OpenSSL 3.0.15다. 두 환경의 unit 통과를
Windows native 서버의 TLS 실측으로 확대하지 않는다. mTLS가 기존 API 권한·Ed25519 출처 증명·사용자 MFA를 대체하지 않는다. 탐지 규칙·
임계값·정규화·앱 정책과 개선 전 낮은 탐지 품질 결과는 보존한다.

구성·키·망·실행 증거는 채희주 담당 범위다. 김택희의 후속 검토는 앱/저널 상태 대조와 독립 재현이며
이번 결과를 팀원 검토 완료로 기록하지 않는다.

공식 근거: [NGINX upstream TLS](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify),
[Python SSL context/SNI](https://docs.python.org/3.12/library/ssl.html#ssl.SSLContext.sni_callback),
[Prometheus TLS 설정](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#tls_config),
[Prometheus exporter-toolkit web TLS](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).
