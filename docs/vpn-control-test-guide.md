# VPN 제어 메시지 시험과 재현 — v114

2026-11-16 · 무료 로컬 · 목표 미달 · push·새 CI·병합 보류

정상 PUSH 제어 메시지에 남아 있는 이력 경보를 줄이는 후보를 검증한다. [실제 결과·판정 범위·한계](extra-vpn-control-review.md)를 함께 읽는다. 원래 모든 로그 행의 탐지 성능과 기능 fixture·같은 접속의 여러 단계·별도 자료를 혼합하지 않는다.

```text
python -m pytest tests/test_vpn_control_review.py tests/test_vpn_protocol_review.py tests/test_vpn_attack_evidence.py tests/test_vpn_protocol_stage.py -q
```

새 제어 시험 43건과 staging 1건은 앞선 TLS 단계, 연결/순서/시각, 파서 모호성, 현재 거부/과거 실패, 모델 지지/공격 veto, 원문/의존성 결속, 기본 비활성 및 오류 보존을 검증한다. 위 명령은 관련 묶음이며 전체 Linux 776건의 명령과 동일한 범위라고 주장하지 않는다. 전체 실행 결과는 [JUnit](infrastructure-results/extra-vpn-control-v114-20261116.xml)을 따른다.

가중치·실행 코드·시험은 [동결 묶음](../infra/f1-lab/frozen-vpn-control-v114/), [학습기](../scripts/train_vpn_control.py), [판정기](../scripts/run_vpn_protocol_review.py), [staging](../scripts/stage_vpn_protocol_replay.py)에 포함했다. 이번 버전은 로컬 커밋만 했고 아직 GitHub에 게시하지 않았다. 저장소 clone만으로 큰 원본/정답·v113 기준선 예측을 얻을 수는 없다.

전체 성능 재현에는 정확히 짝지어진 AIT 원본·정답, preparation 지문, v113 봉인 기준선, 준비된 Python 3.12 의존성과 캐시 이미지가 필요하다. [공통 catalog/실행 가이드](vpn-protocol-test-guide.md)를 따라 실제 파일 경로로 catalog를 구성한다. 예측기에는 원문·최소 metadata·기준선·동결 계수·코드만 제공하고 정답은 봉인/컨테이너 제거 뒤 채점한다.

```powershell
$controlCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/control-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_vpn_protocol_replay --catalog runtime/f1/control-catalog.json --sha256 $controlCatalogSha --output runtime/f1/control-replay-01 --profile vpn-control
$controlStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/control-replay-01/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/control-replay-01 --stage-sha256 $controlStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4 --with-attack-evidence
```

출력은 새 경로여야 한다. `vpn-control`은 보충 제어 모델을 포함하며 `--with-attack-evidence`는 v110 공격 유지 동작을 보존한다. 기본 `vpn` 프로필에는 제어 모델을 넣지 않는다. audit 전용 network 옵션을 VPN에 혼합하면 실패한다. 모델·기준선·source/입력 지문과 실행 격리·봉인·소유 컨테이너 제거를 확인한 뒤 `scripts.f1_lab.transfer_evaluation.score`로 채점한다. 모든 ID/순서/오류/행을 보존하고 새 FP·기존 TP 손실 0을 확인한다.

새 학습을 할 경우 `scripts.train_vpn_control`은 선언한 training 역할·정답/준비 SHA·원문 결속·원래 행 순서를 검증하며 base head와 legacy 의존성 pin도 필요하다. Fox/Wardbeck/Harrison을 학습으로 바꾸거나 임계값·정답·평가 분모를 바꾸지 않는다. 이번 학습 수치 946행은 946개 독립 접속이나 독립 위협 표본이 아니다.
