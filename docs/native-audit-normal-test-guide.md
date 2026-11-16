# 실제 정상 audit 학습 자료의 시험과 재현 — v113

2026-11-16 · 무료 로컬 · 전체 목표 미달 · 새 CI/병합 보류

목적은 정상 SSH·sudo 로그 조회를 공격으로 오인하는 사례를 줄이면서 기존 위협 탐지를 보존하는 것이다. [실제 결과와 한계](extra-native-audit-normal-review.md)를 함께 읽는다. 기능 fixture, 통제된 정상 학습 수집, 기존 개발 자료 전후 성능, 새 독립 성능 인수는 각각 다른 근거다.

## clone 후 로컬에서 가능한 검증

저장소에는 [수집 코드](../infra/f1-lab/native-audit/), [실제 원문 169행·정상 라벨·영수증](../infra/f1-lab/native-audit/captured-v113/), [동결 모델](../infra/f1-lab/frozen-audit-native-normal-v113/), 기능 시험과 [결과 JSON/JUnit](infrastructure-results/extra-native-audit-v113-20261116.json)이 있다. 이번 변경은 로컬 커밋이며 아직 원격 GitHub에 게시하지 않았다. clone으로 받을 수 있는지는 이후 게시 기록을 확인한다.

```text
python -m pytest tests/test_native_audit_training.py tests/test_audit_intent_context.py tests/test_vpn_protocol_stage.py tests/test_apparmor_causal_intent.py tests/test_web_firewall_context.py -q
python -m scripts.prepare_native_audit_training --execution infra/f1-lab/native-audit/captured-v113/execution.json --sha256 4354e58df9309542b911168d8b820a21f5fde7416e627b338191e7834d2f4195 --output runtime/f1/native-audit-reingest-01
```

출력 디렉터리는 새 경로여야 한다. 재섭취 후 raw SHA `57ef199346b1b92a8bdd183c17294f577bd5476fd5f324f59f611e7acd73481a`, preparation SHA `8d2a7a69460caa782ef7bf5623748785d85d11b4a32b9e40e2bd54769a5f5af8`, truth SHA `48aa419d4e48d00d1e9cf8522184adfba636802e30893450b058b44bd5f880aa`, 169행을 대조한다. 이 과정은 실제 커널 캡처의 보존/섭취 재현이며 새 VM 실행이나 독립 사고 라벨 검증을 대신하지 않는다.

| 시험 대상 | 만든 이유 |
|---|---|
| 8회 SSH/sudo·개별 sessionid·정책/boot/UTC·lost 0 | 허용 작업의 실제 수집과 수집 범위를 확인 |
| receipt/source 지문·전체 원문·newline | 수정되거나 잘린 자료와 GS에 의한 행 수 변경 거부 |
| ENRICHED 원본/표시 별칭 분리 | 계정 이름을 원래 숫자 신원으로 잘못 해석하지 않음 |
| 구형/신형 sudo uid·exe·PID/TTY/session | 원래 uid 보존과 다른 실행 문맥의 혼입 방지 |
| 단계별 최소 지지 5·공격 veto | 단계 합산·표본 복제·임계 완화로 통과시키지 않음 |
| 모델 쌍 pin·명시 프로필·기존 거부·방화벽 위험 | 기본 기능과 기존 위협 탐지를 보존 |

## 전체 성능 전후 비교

원래 1,681,815행과 별도 자료의 실제 예측에는 정확히 짝지어진 AIT 원본/정답, 준비 지문, 직전 v112 봉인 기준선, 기존 Python 3.12 의존성/로컬 이미지가 추가로 필요하다. 큰 자료·정답·기준선은 Git에 포함하지 않는다. clone+pytest 또는 정상 169행 intake만으로 전체 성능을 재현했다고 보고하지 않는다. 입력 준비·catalog 형식·봉인 뒤 채점은 [기존 실행 가이드](vpn-protocol-test-guide.md)와 [v112 시험 가이드](web-firewall-test-guide.md)를 따른다.

```powershell
$nativeAuditCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/native-audit-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_vpn_protocol_replay --catalog runtime/f1/native-audit-catalog.json --sha256 $nativeAuditCatalogSha --output runtime/f1/native-audit-replay-01 --profile audit-native-normal
$nativeAuditStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/native-audit-replay-01/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/native-audit-replay-01 --stage-sha256 $nativeAuditStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4 --with-network-audit-context
```

catalog은 실제 로컬 원본/준비 파일과 v112 기준선 경로로 작성해야 하며 위 예시 경로가 자동 생성되지는 않는다. `audit-native-normal`은 감사/인증 원문과 동결 base+supplemental 모델만 추가로 제공하고 학습 원문/정답을 예측기에 제공하지 않는다. 자동 pull/build는 하지 않는다. 실행 완료·모든 입력/코드 불변·예측 봉인 SHA·이미지 자료 차단·컨테이너 제거를 확인한 후 `scripts.f1_lab.transfer_evaluation.score`로 정답을 결합한다. 기존 사건 ID·순서·오류를 유지하고 새 FP/기존 TP 손실 0과 전체 행 수를 확인한다.

새 수집을 하려면 게스트 도구·공식 이미지 검증·사전 정책·격리/종료 제어를 별도로 준비해야 한다. 포함된 수집 recipe만으로 부모 Docker 네트워크 격리/receipt가 자동 구성되지는 않는다. 이번 캡처를 복제해 세션 수를 늘린 것으로 세거나 과거 공개 로그에 이번 정상 정책을 소급 적용하지 않는다. 반복 학습 표본 확보와 새 독립 평가 표본 확보를 구분한다.
