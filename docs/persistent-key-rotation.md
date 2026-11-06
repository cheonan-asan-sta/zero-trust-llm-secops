# 3주차 지속 실행 환경의 개인키 교체 통합

2026-11-06 · 채희주 인프라 구성·실행·측정, Codex 도구 보조. 로컬 Docker에서 수행한다.

[CA 발급·동일 키 갱신 인수](ca-runtime-acceptance.md)에 이어 기존
[leaf 개인키 교체](private-key-rotation.md)를 업무·관측 지속 실행 경로에 연결한다.
선택형 `scripts.rekey_mtls_runtime`을 사용하며 16서비스·9개 내부망·31개 named volume을 유지한다.
기본9·관측14·동일 키 갱신16 프로필은 별도로 유지하고 과거 descriptor를 자동 이관하지 않는다.

## 무엇이 발전했는가

| 경계 | 기존 CA 프로필 | 이번 선택형 프로필 |
|---|---|---|
| leaf 갱신 | 같은 개인키로 인증서 갱신 | 신원39개의 새 P-256 개인키·CSR·인증서 쌍 생성 |
| 설정 경로 | 고정 `.pem/.key` 파일 | journal에 기록한 세대별 파일로 profile·NGINX·Go 설정의 쌍 전환 |
| 서비스 반영 | 인증서 reload·실제 TLS 확인 | 설정과 참조한 키/인증서 digest ack 및 서버11개의 실제 TLS 지문 확인 |
| 정리 | 구 pin 제거 | 구 pin 제거·구 client serial 폐기 확인·유예 후 관리 볼륨의 구 키/인증서 삭제 |
| 서버 발급 권한 | 관리 TLS 신원의 기존 키 사용 | 서버별 제한 JWK 서명키11개를 leaf 키와 분리하여 유지 |
| 정상 재시작 | 고정 파일 지문 대조 | 원래 설정에서 journal이 허용한 완전한 cert/key 쌍의 치환만 허용 |

새 프로필은 기존 controller/rotation publisher를 재사용한다. 앱·탐지·정책과 개선 전 평가 데이터,
정밀도/재현율/F1/오탐률 임계값은 바꾸지 않는다. 이 문서의 인프라 검사 수를 탐지 품질로 환산하지 않는다.

## 키 교체와 복구

1. 파일 이름을 journal에 먼저 저장하고 키를 생성한다. 같은 신원의 여러 볼륨에는 같은 새 키를 쓴다.
2. clientAuth는 기존 신원의 mTLS `/rekey`, serverAuth는 해당 서버에 제한한 JWK `/sign`을 사용한다.
   이름·SAN·용도·issuer·유효기간과 인증서/키 일치를 기존 검증기로 확인한다.
3. 새 pin 겹침 → profile/config의 키·인증서 쌍 전환 → reload ack → 실제 TLS 확인 순서로 게시한다.
4. 구 pin 제거와 구 client serial의 CA 폐기 확인을 거친 뒤 관리 볼륨의 구 파일을 지운다.
   알 수 없는403을 폐기 성공으로 취급하지 않는다. CA 폐기와 업무 peer pin 회수는 별도 경계다.
5. CA 중단 때 현재 키를 유지하며 준비한 키를 재사용한다. 게시 중 controller 종료 시 journal에서
   같은 작업을 재개한다. reload 대상이 준비되지 않으면 구 키를 먼저 지우지 않는다.

기본 키 교체 간격은600초, 게시 후 정리 유예는3초다. 인수 시험은15초 간격으로 가속하고
호스트 재시작 검사 전에 봉인한600초/3초 설정으로 복구한다. 운영 조직의 교체 정책으로 확정한 값은 아니다.
`disabled` 신원은 교체하지 않으며, 관리자가 회수한 peer pin을 재생성하지 않는다.

구 serial의 passive 폐기는 CA의 갱신/재키잉을 막는다. Python의 구 leaf pin 거부와 구분하며,
CA/SAN을 신뢰하는 Go/NGINX 구간의 모든 구 인증서를 즉시 차단하거나 기존 TLS 세션을 강제
종료하는 기능은 아니다. 해당 구간의 active CRL/OCSP·정확한 leaf 제약/연결 종료 인수는 남아 있다.
정상 교체와 구 관리 파일 삭제를 유출된 구 키의 모든 접근 권한 즉시 회수로 표현하지 않는다.

이번 연결 과정에서 이전 CA 프로필의 reload group 경로가 실제 `*-tls` 볼륨 경로와 다른 점도
발견했다. 경로를 맞춰 ack 검사가 실제 대상에 적용되게 보완한다. 이전 결과에 실제 TLS 지문
확인이 있었다는 사실과 별개로, 이전 실행을 올바른 경로의 ack 검사 결과로 소급하지 않는다.

## 재시작 전 변경 거부

NGINX와 Prometheus/Alertmanager의 원본 설정은 release 입력으로 고정한다. 재시작할 때
원본과 정확히 같은 설정이거나 journal이 기록한 동일 역할·동일 볼륨의 완전한 cert/key 쌍으로만
치환된 설정인지 검사한다. 임의의 새 파일·섞인 세대·다른 역할·검증 해제·추가 지시문은 거부한다.
참조 파일의 issuer·신원·유효기간·키 일치·0600·현재/준비 지문도 확인한다.
참조한 leaf의 만료도 시작 거부 대상이며, 만료 신원을 자동 재등록하지 않는다.
정상 교체 후 설정을 새 기준으로 다시 봉인하지 않는다. 고정 JWK 공개 지문도 별도 대조한다.

이 검사는 신뢰된 로컬 관리 호스트의 시작 전 검사다. 악성 Docker 관리자, journal/descriptor 전체를
함께 바꾸는 공격, 승인 서명/정책 anti-rollback을 보장하지 않는다. 중앙 controller는 TLS 키와
관측 볼륨의 scrape/notify 토큰을 읽을 수 있으며 CA 서명키·업무 DB/API 키·Docker socket은 없다.

## 관측 실패 진단

이전 PR35 CI 첫 시도의 `monitoring_previous_alert_not_cleared` 원인은 여전히 미확정이다.
재시도 성공을 원인 해결로 기록하지 않는다. 이번에는 관측 대기 실패의 정리 전에 최대20초 예산으로 다음만 남긴다.

- 고정 job의 `up`, C01 경보의 `ALERTS`·규칙 상태/health·평가 오류 유무
- 소유 프로젝트 서비스의 running/restarting/OOM·exit code·restart count
- 수집 시각·제한/수집 불가 여부

원문 규칙 오류·로그·요청·Docker 환경·임의 metric label·API 키·토큰·개인키는 내보내지 않는다.
표본/서비스/규칙 수도 제한하고 Docker 각 호출에 timeout을 둔다. 진단 실패가 원래 실패를 바꾸지 않는다.
기존 경보 판정과90초 대기 기준은 유지한다. 실제 exporter 중단 순간의 up=0·firing 경보·중지 상태를
대조하는 검사를 기존 관측 인수에 추가한다. 진단 추가 자체가 간헐 경보 문제의 수정 증거는 아니다.

## 로컬 재현과 인계

```powershell
.venv/Scripts/python.exe -m scripts.rekey_mtls_runtime up --directory runtime/c02/my-rekey
.venv/Scripts/python.exe -m scripts.rekey_mtls_runtime status --directory runtime/c02/my-rekey
.venv/Scripts/python.exe -m scripts.rekey_mtls_runtime down --directory runtime/c02/my-rekey
.venv/Scripts/python.exe -m scripts.test_rekey_mtls_runtime --directory runtime/c02/rekey-acceptance01
```

down은 저장 볼륨을 보존하며 `down --purge`만 검증한 소유 프로젝트 자원을 지운다.
키·CA 상태는 전용 Linux 볼륨에 두고 호스트에는 공개 descriptor/검증 결과만 남긴다.
폐기 대조에 필요한 시험용 구 collector 키 사본도 시험 전용 Linux 상태 볼륨 안에서만 보관하고
종료 시 소유 볼륨 전체를 정리한다. 관리 볼륨의 구 파일 제거와 시험 사본 보존을 구분한다.

CA/JWK 서명키 자동 교체·CA HA/공유 DB 호스트 복구의 이 프로필 연결, 전체 JSONL 저장 계약,
Go 도구 공급망 검토/운영 채택·김택희의 독립 재현은 후속이다. 3주차 전체 완료로 표시하지 않는다.
기존 11/29 기능 동결·12/6 제출 가능본 일정과 역할 분담은 유지한다.

## 검증 기록

최종 집중104개(신규37개)가 통과했다. 첫 집중 실행은 시험 fixture의 허용 디렉터리와 Windows
경로 구분자 단언 때문에101통과/3실패였으며, 시험 fixture/단언만 바로잡아104개를 재검증했다.
이를 앱·탐지 판정 수정으로 기록하지 않는다.

| 실행 | 결과 |
|---|---|
| 새 지속 실행 rekey 실제 Docker 인수 | 22/22, 소유 컨테이너·볼륨·망 각각0 |
| 기존 관측/mTLS 프로필 회귀 | 72/72, 장애 진단 대조1개 추가, 소유 자원 각각0 |
| 기존 동일 키 CA 프로필 회귀 | 29/29, 올바른 reload 경로 적용, 소유 자원 각각0 |
| 고정 Linux Docker 전체 회귀 | 2,087통과·기존 경고2, Ruff 통과 |
| 기존 Windows `.venv` 전체 회귀 | 2,083통과·4skip·경고3, Ruff 통과 |

Windows 개발 환경과 고정 Docker의 설치 버전/경고를 혼합하지 않는다. Windows의 Ruff는0.16.6이며
Docker/CI는 기존 wheel hash lock의0.17.3을 사용한다. Windows 환경 버전·경고 수와 Linux 원문 로그
지문, 실행별 소스/설정·release 입력/image payload·공식 도구 지문은
[공개 원자료](infrastructure-results/persistent-key-rotation-20261106.json)에 남긴다.
세 실제 프로필은 별도 실행이며 검사 수를 하나의 탐지 품질 표본으로 합산하지 않는다.

로컬 인수는 커밋 전 작업 트리의 공개 release payload로 실행했다. 정확한 clean PR head와
병합 후 head의 CI 대조는 PR 기록에 별도로 남긴다. 김택희의 독립 재현은 미완료다.
