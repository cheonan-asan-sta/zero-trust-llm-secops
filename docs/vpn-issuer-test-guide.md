# VPN issuer 관계·단계별 지지 재현

무료 local/test 전용이며 실제 결과는 [검토](extra-vpn-issuer-relation-review.md)를 따른다. 원본은 AIT LDS V2.1, Landauer et al., CC BY-NC-SA4.0의 비상업 연구 자료다. 원문/정답은 Git에 추가하지 않았다. 원래 training 역할을 유지한 R/S/Shaw/Wheeler의 고정 plan·preparation·raw·truth와 v109/v114 dependency가 필요하다. 실제 위치와 SHA를 사용하며 성공한 출력은 덮어쓰지 않는다.

```powershell
.venv\Scripts\python.exe -m pytest tests/test_vpn_issuer_review.py tests/test_vpn_issuer_stage.py tests/test_vpn_protocol_review.py tests/test_vpn_protocol_stage.py -q
.venv\Scripts\python.exe -m scripts.fit_vpn_issuer_review --plan <declared-training-plan.json> --sha256 <plan-SHA256> --protocol-model infra/f1-lab/frozen-vpn-control-v114/head.json --protocol-model-sha256 61c447942522a179b398e200e0dd50e499721a90f4dca2ffb66f786153312bdd --control-model infra/f1-lab/frozen-vpn-control-v114/control.json --control-model-sha256 <actual-control-SHA256> --output runtime/f1/issuer-fit-fresh
```

현재 최종 head SHA: `56de6bc2826943a94c852b1c361963c968e8ee00d7f0929b97789af72756799b`. 단계별 정상 지지는4로 최소5 미만이며 성능 개선 모델로 채택하지 않았다.

재현 catalog는 기존9개 묶음 전부를 유지하고 **v124 봉인 예측의 after**를 before로 쓴다. catalog 안의 이전 v123 경로를 그대로 쓰지 않는다. head/model은 명시적 profile로만 적재한다.

```powershell
.venv\Scripts\python.exe -m scripts.stage_vpn_issuer_replay --catalog <catalog.json> --sha256 <catalog-SHA256> --output runtime/f1/issuer-package-fresh
.venv\Scripts\python.exe -m scripts.run_local_vpn_protocol_batch --package runtime/f1/issuer-package-fresh --stage-sha256 <actual-stage-SHA256> --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4 --with-attack-evidence
```

캐시 image가 없으면 기존 local 시험 image를 준비하고 실제 ID를 준다. 추가 공격 근거 보존과 control 모델을 생략할 수 없다. 예측 봉인 completed·소유 container 제거·원본/코드 pin 확인 뒤에만 기존 truth로 채점한다. 추가FP/TP손실0 및 원래1,681,815행/별도5개 자료 분리를 확인한다. profile2/schema2의 최소5는 **각 단계에서 별도로** 적용한다. 현재 qualified cell0이고 최종 판정은v124와 같다. 초안의 pooled10행 감소는 미채택이다. 기능 fixture는 성능 분모나 training에 합산하지 않는다.
