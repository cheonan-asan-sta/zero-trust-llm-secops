# extra 개발: 실제 서비스 실행 근거와 LLM 분석 연결

> 후속 상태: 같은 날 [HTTP 분석·감사 연결](extra-native-http-audit-20261118.md)을 추가했다. 아래는 내부 어댑터를 먼저 구현한 `1bcd2d9` 시점의 결과와 범위다. 새 HTTP 경로와 현재 남은 작업은 후속 문서를 기준으로 한다.

2026-11-18. 발표와 별개인 후속 개발이다. 기준 main은 PR #91이 병합된 `e058bcac05753a873ca00d68eb0a0533308057a2`다. 기존 extra에 고유 커밋이 없어 전용 worktree에서 최신 main으로 fast-forward했다. 이번 변경은 **로컬 extra**에만 저장한다. 원격 push·CI·main/aitest 병합·AWS 배포는 하지 않는다.

## 구현

기존 LLM은 앱 세션과 Cowrie/CloudTrail 형식의 실행 근거를 읽을 수 있었지만 실제 systemd/ptrace 실행 기록과 호출자 영수증은 별도 흐름에 있었다. 이번에는 **동일 요청·호출자·앱 권한 사용·실제 실행 관측**이 일치할 때만 LLM 입력에 추가하는 내부 어댑터를 구현했다.

| 단계 | 검증과 동작 | 구현 |
|---|---|---|
| 앱 세션 | 서명된 최신 입력·요청자·tenant·버전·현재 정책·출처·유효기간 | 기존 `collect_session_evidence` |
| 실행 근거 | 런타임/인가 서명 2개와 원래 이벤트·명령 해시·수집원 범위·시각. 이미 기록된 관측만 허용 | `ServiceEvidenceJoiner.inspect` |
| 호출 신원 | pinned 등록부와 broker 서명 영수증의 요청·이벤트·근거 해시, 현재 요청자의 issuer/tenant/subject 참조 | 기존 `verify_receipt` |
| 권한 사용 | 현재 grant가 그 실행 요청에 사용됐는지 버전·자원·행위·요청자·내부 grant 참조까지 대조 | `ZeroTrustOperations.analysis_execution_access` |
| LLM 입력 | boot/invocation/PID/start ticks, 실행 파일·명령 해시, 출처·영수증·앱 사용 기록 | `collect_service_analysis_evidence` |
| 분석 반환 | 호출 전후 현재 권한 재검증. 소비된 권한의 ALLOW 권고를 기존 서버 가드로 HOLD 처리. 위협 분류 자체는 변경하지 않음 | `review_service_execution`, 기존 OpenAI/Hybrid grounded 어댑터 |

새 입력은 `verified_session.native_execution`이다. systemd 원본을 Cowrie/CloudTrail 이벤트로 바꾸거나 미관측 네트워크 목적지를 추정하지 않는다. 실행 파일 해시가 맞는다는 이유로 별도의 위협 탐지를 없애지 않는다.

서비스 근거 조회는 SQLite `mode=ro`와 `query_only`를 사용한다. 관측 등록·clock 갱신을 하지 않으며 DB가 없으면 새로 만들지 않고 거부한다. 앱 조회도 권한 발급·재사용·환불·정책 변경을 하지 않는다. 토큰이나 내부 grant hash는 반환하지 않는다.

스냅샷은 원래 이벤트에 묶이며 수명은 모든 근거 중 가장 짧은 만료 시점, 실행 후 최대 30초다. 추론 도중 만료·철회되면 결과를 반환하지 않는다. 신뢰된 서버의 `caller_authority_check`를 전달하면 계정 설정 철회도 전후 확인한다.

## 검증 결과

| 검증 | 결과 | 해석 |
|---|---|---|
| WSL Linux 관련 회귀 | **572건 통과** | 새 어댑터, 기존 실행/신원/세션·정책/LLM 경로 포함 |
| 새 신뢰 경계 회귀 | **45건 통과**, 위 572건에 포함 | 별도 합산 금지 |
| 실제 systemd·ptrace 인수 | **15조건 통과** | 실제 커널 exec 관측 + 로컬 신원 fixture + 모델 응답 stub |
| Ruff, `git diff --check` | 통과 | 코드/공백 점검 |
| 유료 API / AWS 호출 | **0 / 0** | 새 모델 성능 측정 아님 |

원본 실행 결과: [검증 요약·소스 해시](infrastructure-results/extra-native-execution-llm-20261118.json), [실제 systemd 결과](infrastructure-results/extra-native-execution-llm-20261118-systemd.json).

새 테스트는 잘못된 boot/invocation/tenant·명령·nonce·영수증·서명, 미등록/삭제된 근거 DB, 역행 시각, 다른 세션/요청자, 만료/철회된 출처·정책·계정·세션, 추론 중 철회, 비밀값 미전달, 조회의 무변경, 기존 위협 분류 보존을 확인한다.

실제 systemd 인수는 짧게 종료된 프로세스의 근거·동일 invocation·앱 grant 소비·LLM 입력 연결·읽기 전용 조회·재실행 거부를 확인했다. UUID 소유 unit/임시 키·실행 파일과 임시 의존성 복사본은 제거했다.

Windows 확대 시험은 252통과·11실패·2skip이었다. 11건은 기존 Linux 전용 `fork`/`SIGCHLD` 테스트의 Windows API 부재로 실패했다. 통과로 재분류하지 않았으며, 해당 실행 경로는 Linux 회귀에 포함해 검증했다. 전체 프로젝트 테스트를 새로 전부 실행한 것은 아니다.

## 재현

프로젝트 dev 의존성이 설치된 Python으로 실행한다. Linux 기준:

```sh
python -m pytest tests/test_service_analysis_evidence.py tests/test_exec_history_binding.py tests/test_service_caller_identity.py tests/test_shared_execution_evidence.py tests/test_shared_execution_collector.py tests/test_systemd_request_launcher.py tests/test_execution_analysis_evidence.py tests/test_execution_analysis_runner.py tests/test_session_analysis_evidence.py tests/test_grounded_prompting.py tests/test_policy.py tests/test_zero_trust_operations.py tests/zero_trust -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --llm-evidence
```

마지막 명령은 systemd가 PID1인 Linux root 인수용이다. `PYTHONPATH`의 프로젝트/의존성이 unit의 `ProtectHome=yes` 환경에서도 읽혀야 한다. 이번 로컬 실행에서는 `/run` 전용 임시 디렉터리의 의존성 복사본을 사용한 뒤 정리했다. `--llm-evidence`는 실제 API를 호출하지 않으며 기존 OpenAI 어댑터의 prompt/schema/근거 검증 코드를 명시적인 모델 응답 stub으로 시험한다.

## 범위와 남은 작업

- 실제 관리형 systemd unit의 **첫 성공 exec** 대상이다. 일반 PAM 세션·호스트 전체 감사·후속 자식 프로세스 전체 추적은 이번 범위가 아니다.
- 추가 native 근거에는 원문 명령·인자·JWT·nonce·서명 원문·개인키·grant token/hash를 넣지 않는다. 필요한 해시와 참조만 사용한다.
- `local_oidc`는 로컬 신원 fixture다. 실제 기업 SSO·사람의 로그인·이벤트 대상자의 MFA를 검증했다고 주장하지 않는다. 영수증은 실행 요청자만 연결한다.
- 서명은 등록된 수집원·broker의 주장에 대한 출처 근거다. 물리적 attestation이나 호스트 관리자에 대한 원격 변조/rollback 방어를 의미하지 않는다.
- **신뢰된 내부 분석 진입점**까지 구현했다. 새 공개 HTTP 입력에서 임의 파일 경로·근거·등록부를 받지 않는다. 향후 HTTP 연동은 기존 감사 저장·반환 직전 재검증 경로를 함께 사용해야 한다.
- 모델 응답을 stub으로 시험했으므로 새 탐지 성능 향상이나 실제 모델의 native 근거 해석 능력을 입증한 것은 아니다.

다음은 신뢰된 서버 수집 경로의 HTTP 분석·감사 연결, 실제 운영 인증원 연동, 새 native 실행 사례의 라벨 근거·독립성 확보, 고정 기준/후보의 실제 API 비교 순서다. 발표용 문서는 당시 main 기준 결과를 유지하며 extra의 후속 개발과 혼합하지 않는다.

## 기존 성능 유지

정답·원본 평가자료·탐지 로직·임계값을 이번 변경에서 수정하지 않았다. 기존 실제 API 개발 평가 360건은 **TP163 / FP6 / FN17 / TN174, 정밀도 96.45%, 재현율 90.56%, F1 93.41%, 보수적 오탐률 3.33%**다. 360건은 개발용 합성 자료이며 독립 실운영 성능이 아니다. 기존 native 공유 감사/VPN F1 80%와도 다른 평가다. [기존 결과와 한계](llm-operation-evidence-20261117.md)를 유지한다. 전체 목표를 달성했다고 보고하지 않는다.
