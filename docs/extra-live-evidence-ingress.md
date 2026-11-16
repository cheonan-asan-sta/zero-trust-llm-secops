# 실행 주체·호출 신원·VPN 기기 결속 수집 — v103

**후속 v104:** [수집 근거를 실제 보조 위험 판정과 명시적 폐기 탐지에 적용](extra-evidence-risk-refinement.md). 아래 v103은 수집·연결 당시 기록이며 최신 판정/검증은 후속 결과를 따른다.

2026-11-16 · 채희주 담당의 로컬 수집·연결 개선. 기존 공개 로그에 없는 실행 주체나 기기 권한을 소급 생성하지 않는다. **새 로컬 관측 경로를 구현했으며, 기존 탐지 목표 충족과는 별도로 검증한다. 목표 충족 전 push·새 CI·병합은 보류한다.**

## 이번에 연결한 경로

| 대상 | 새로 읽는 실제 근거 | 연결·검증 | 판정에 미치는 범위 |
|---|---|---|---|
| 공유 감사 | systemd MainPID·부팅 ID·invocation, `/proc`의 시작 tick·실행 파일/명령 해시·실제/effective UID | 별도 SHA로 고정한 실행 허용 목록과 서비스 registry의 정책 SHA·최소 버전 일치, 독립 runtime/authorization 서명, 완료 시 재검증 | 현재 실행이 명시적 정책에 어긋나면 기존 실행 위험 refiner에 경보·검토를 추가. 허용은 기존 경보/검토를 지우지 않음 |
| 인증 | 기존 native journal 수집기의 서명된 PAM 열기 기록 + 동일 프로세스의 현재 kernel snapshot | tenant/server/unit/boot/invocation, 정확한 cursor·PID·시작 tick·UID·실행 파일/명령, 관측 시간 확인. 선택한 OIDC broker receipt는 같은 request·event·서비스 증거 digest에 결속 | 동일한 살아 있는 실행의 현재 정책 위험을 PAM 관측에 연결. 호출자 확인과 실행 허용을 구분하며 자동 권한 부여 없음 |
| VPN | 실제 인증된 서버 측 TLS socket의 peer 주소/포트·클라이언트 인증서 SHA·채널 binding SHA·수집 시간 | 기존 VPN bridge의 nonce, 서명된 신원/기기 상태/업무 승인, 현재 certificate enrollment·리소스 정책 검증에 전달 | 새 TLS 메타데이터 관측에 검증 근거를 연결. TLS 성공만으로 정상 기기·MFA·업무 권한을 추정하지 않음 |

구현은 [실행/PAM ingress](../scripts/f1_lab/live_execution_context.py), [TLS ingress](../scripts/f1_lab/vpn_gateway_collector.py), [실제 systemd 인수 실행기](../scripts/run_live_evidence_controls.py)를 따른다. 앱·대시보드 코드와 기존 탐지 임계값/모델은 변경하지 않았다. VPN fixture builder의 선택적 `gateway_observation` 인자로 실제 수집된 연결을 기존 서명·정책 검증 경로에 넣는다. 이 builder의 신원·상태·승인 서명은 로컬 시험용이다.

```text
trusted systemd collector
  → collect_service(joiner, pinned_execution_policy, runtime_key, policy_key, ...)
  → 실제 event + 서명된 runtime/authorization proofs + 현재 실행 facts
  → refine_service(previous, facts)

native journal capture + 같은 살아 있는 실행 proofs
  → collect_pam_context(..., cursor_sha256=정확한_관측,
        caller_registry=고정된_인증원, request=원래_요청, receipt=브로커_영수증)
  → refine_pam(previous, context)

authenticated TLS server socket
  → collect_connection(socket, ...현재_세션_범위...)
  → VPNConnection + 별도의 새 메타데이터 관측
  → 기존 VPNTrustBridge / VerifiedVPNRisk
```

키와 콜백은 신뢰된 수집기 설정이다. 요청자가 정책 결정·키·프로세스 JSON을 제출하는 공개 API로 노출하지 않는다. 기존 systemd 메모리 credential 경계에서 키를 공급하는 운영 연결은 별도로 인수해야 한다.

## 잘못된 결속을 막는 기준

- PAM과 실행의 PID만 비교하지 않는다. 부팅·서비스 실행 ID·시작 tick·실행 파일/명령·UID가 모두 맞아야 한다. 자식/인접 sudo 행을 원래 호출자로 붙이지 않는다. 이미 종료되었거나 교체된 프로세스는 연결 불가다.
- PAM 원래 시각과 cursor를 보존하며 30초 이내 관측만 연결한다. journal monotonic 시각과 proc의 부팅 기준 시작 tick 비교는 suspend 후 보수적으로 실패할 수 있다. 불확실한 연결을 허용하는 보정값은 추가하지 않았다.
- `policy_basis=current_running_process`다. **현재 살아 있는 프로세스에 적용한 정책**이며 PAM 열기 당시에도 같은 정책이 적용됐다고 주장하지 않는다. 현재 정책을 바꾼 뒤의 위험 검증을 과거 PAM 공격 라벨로 바꾸지 않는다.
- OIDC receipt는 현재 고정된 인증원·활성 person 항목·서명·request/event/evidence 결속·만료를 다시 확인한다. UID0, PAM opener 이름, 부모 PID는 사람 인증으로 승격하지 않는다. `local_oidc`는 로컬 인증원 기능 시험이며 실제 사람/기관 SSO 검증이 아니다.
- VPN은 서버 측 `CERT_REQUIRED`, **재개하지 않은 ECDHE TLS1.2, session ticket·재협상 금지** 조건에서 실제 peer 인증서·채널을 읽고 완료 때 같은 연결인지 확인한다. 현재 Python3.12는 `tls-unique`만 노출하므로 이 adapter는 TLS1.3 결속을 거부한다. TLS1.3의 표준 `tls-exporter` 연결은 별도 gateway 작업이다. 기존 mTLS 통신 설정을 TLS1.2로 변경하지 않았다. [Python SSL 문서](https://docs.python.org/3.12/library/ssl.html#ssl.SSLSocket.get_channel_binding), [RFC9266](https://www.rfc-editor.org/rfc/rfc9266.html).
- socket 모양의 제출 객체, 미인증 TLS, 다른 연결의 서명 묶음은 사용할 수 없다. 인증서 enrollment 폐기·기기 불일치·현재 정책 변조/만료·승인 누락도 정상 근거가 되지 않는다.
- 새 VPN metadata 관측은 원래 OpenVPN 오류/인증 로그를 대체하지 않는다. 원래 로그의 독립 위험 신호와 기존 검증기의 경보 보존 규칙은 유지한다.

## 검증 결과와 전후 비교

최종 묶음 결과는 [공개 결과 JSON](infrastructure-results/extra-live-evidence-v103-20261116.json)에 기록한다. Linux 집중 테스트, 실제 systemd/PAM/caller 인수와 기존 1,681,815행의 v102 대비 비교를 구분한다. Windows 테스트는 Linux 집중 테스트에 포함되는 부분집합이므로 합산하지 않는다.

실제 systemd 시험은 UUID로 한정한 서비스에서 고정된 sudo 명령만 실행한다. 실제 journal/PID/start/boot/invocation 연결과 로컬 OIDC receipt를 확인하고, 현재 정책을 명시적으로 교체한 뒤의 실행 위험·PAM 연결 및 인증 권한 폐기를 검증한다. 시험 컨트롤러가 여러 fixture 키를 보유하므로 기관의 독립 보안 주체 분리·원격 attestation을 입증하지 않는다.

과거 공개 자료의 공유 SERVICE_START/STOP에는 여전히 실행 명령·호출자 근거가 없고, 미탐 PAM 행에는 PID가 없다. VPN 정상 경보에도 현재 certificate enrollment/기기·업무 승인이 없다. 새 수집기로 이 과거 근거를 만들어 넣거나 기존 오류 행을 제외하지 않는다. 새 로컬 정책·인증 제어의 통과율을 독립 공격 탐지 F1에 합산하지 않는다.

### 평가 입력 노출에 대한 정정

검토 과정에서 이전 전체 소스 묶음에는 과거 성능 문서가, 원래 preparation/source manifest에는 정상·위협 건수와 특징 집계가 들어 있음을 확인했다. 예측 함수가 그 집계를 특징으로 읽지는 않았지만, 이전의 “라벨 집계 미마운트” 표시는 전체 파일의 물리적 가용성까지 입증하지 못했다. 당시 결과와 원본 영수증을 보존하고 **기존 관측 개발 결과**로만 취급한다.

v103의 최종 비교에는 문서·테스트·정답 파일이 없는 별도 예측 컨테이너를 사용한다. preparation은 `completed`, `inputs_contain_truth`, 원본 manifest의 projection SHA, pair별 `raw_member/raw_sha256/rows`만 허용한다. 원본 manifest도 완료 상태·시간 기준·pair별 원본 경로/SHA와 시뮬레이션 시작·종료 시각만 남긴다. 정상/위협 건수·특징 집계·annotation·label 경로는 제공하지 않는다. 원본과 projection 각각의 SHA를 별도로 남기며 실제 원문·행 순서·case ID·모집단·모델·라벨은 바꾸지 않는다. 함수 테스트485건과 실제 systemd11조건은 같은 Python 코드의 지문이 일치하는 별도 기능 인수 영수증이며, 예측 컨테이너 삭제 뒤 연결한다.

이 입력 분리 보강도 이미 관측한 자료를 새 독립 holdout으로 만들지는 않는다. 새 자료·출처/세션 분리·독립 라벨 검토가 여전히 필요하다.

### 최종 로컬 결과

코드 `3a7162c531bc72423d08722c3331e2a114f7933d`의 같은 Python 코드를 고정해 Linux 집중 **485건 통과**, 실제 systemd/sudo/PAM/caller **11조건 통과**, Ruff 통과를 확인했다. 기존 숫자 시각 거부 시험의 Pydantic serializer 경고1건이 있으며 실패·skip은0이다. 별도 Windows 새 테스트43건은 부분집합이며 합산하지 않는다. 전체 프로젝트 회귀 수천 건을 이번 코드에서 새로 실행했다는 뜻은 아니다.

| 종류 | TP/FP/FN/TN (전→후 동일) | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---|---:|---:|---:|---:|---:|
| 공유 감사 | 0/24/6/2328 | 0.0000% | 0.0000% | 0.0000% | 1.0204% | 100.0000% |
| 웹 감사 | 47/21/0/7398 | 69.1176% | 100.0000% | 81.7391% | 0.2831% | 0.0000% |
| 인증 | 29/0/3/1082 | 100.0000% | 90.6250% | 95.0820% | 0.0000% | 9.3750% |
| VPN | 84/208/0/18166 | 28.7671% | 100.0000% | 44.6809% | 1.1320% | 0.0000% |

R/S/F 1,259,637행과 이미 관측한 Harrison 422,178행을 합친 **1,681,815행**에서 v102 대비 추가 TP0·제거 FP0·새 FP0·기존 TP 손실0·추론 오류0이다. 웹 감사에서 직전에 회수한 TP47도 유지됐다. 과거 자료에 새 근거를 꾸며 넣지 않아 성능 수치는 유지됐으며, **목표는 계속 미달**이다. 인증도 F1만95%를 넘었을 뿐 재현율90.625%·미탐률9.375%로 미달이다.

소스 tar SHA256 `d088bcb30106a83226f65d99cf7ad00d5b7273a579fe3532e1e0daaa1aef362b`, v102 report SHA256 `e46fe891faaa41bf158a31e0d4ac3a610e75dc88cd08362c04db21008609a15c`. 최종 비교는 문서·테스트·정답 파일을 제외한 코드 전용 컨테이너에서 수행했다. 준비/원본 manifest에서도 정상·위협 건수와 특징 집계를 제거한 고정 projection을 사용했고 예측 봉인·컨테이너 삭제 뒤에 채점했다. 소스/입력 지문 유지, OOM0, 소유 컨테이너·UUID 서비스/프로세스·Linux 추출 소스 정리를 확인했다. AWS/유료 API0, 새 push/CI/병합0, 장기 soak 유예다.

초기 실행의 Docker 엔진 종료와 완성 전 archive 지문 불일치는 유효한 성능 결과에 포함하지 않았다. Docker Desktop을 실행하고 완성된 archive의 SHA로 재시도했다. TLS 표준 검토 뒤 protocol guard를 보강했다. 전체 소스 묶음의 문서와 원본 메타데이터에 과거 라벨 기반 집계가 함께 있었던 점도 확인해 해당 예측 시도를 중단·삭제하고, 코드/필수 관측 메타데이터만 허용한 별도 컨테이너로 최종 전체행 비교를 다시 검증했다. Linux485건/실제11조건의 기능 영수증은 같은 Python 코드의 지문을 확인하고 예측 컨테이너 삭제 뒤에 연결했다. 이전 전체 소스 비교를 라벨 집계가 물리적으로 없었던 시험이라고 주장하지 않는다. 수치 조정·오류 제외·분모 변경으로 통과시키지 않았다.

## 운영 연결에서 남은 일

실제 조직의 OIDC/SSO·MDM/EDR 기기 상태 발급원과 승인 주체는 아직 연결하지 않았다. VPN 구현은 로컬 TLS gateway 수집 adapter이며 OpenVPN native management/plugin 설치 완료가 아니다. 기존 session/identity/posture/permission 발급원과 실제 gateway hook을 연결해야 한다. 공유 감사도 host 전체의 모든 시작/중지·자식 exec를 수집하는 시스템이 아니다.

신뢰 경계는 현재 호스트의 kernel/systemd·수집기·운영자가 별도로 고정한 registry와 정책이다. root 변조·호스트 rollback·독립 원격 witness·실제 다중 호스트 재해 복구·기관 SSO 실인수는 이 시험으로 완료되지 않는다. 8/12시간 soak는 사용자 요청대로 계속 유예한다. 원래 6개 보안 영역의 새 독립 평가도 별도로 필요하다.

직전 성능 개선과 미달 근거는 [v102 비교](extra-ordered-audit-review.md), 게시 보류 기준은 [로컬 성능 우선 순서](local-performance-before-ci.md)를 따른다.
