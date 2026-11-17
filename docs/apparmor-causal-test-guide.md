# AppArmor 실행 관측 시험·선정 근거·재현 방법

2026-11-16 · v111 · 무료 로컬

## 왜 이 시험인가

기존 공유 감사 FP는 실제 AppArmor 프로필 교체의 STATUS/인자 설명에서 나왔다. 프로필 교체를 일괄 정상 처리하면 공격 정책 변경도 지울 수 있어, 같은 원본의 현재/이전 명령 관측과 학습 공격 veto를 함께 검사한다. 이 실험은 경험적 보조 분류이며 검증된 권한을 발급하지 않는다.

| 시험 | 목적 |
|---|---|
| 첫 STATUS·AVC/SYSCALL/PROCTITLE 원본 순서 | 뒤의 명령으로 앞선 기록을 정상 처리하지 않음 |
| 동일 PID/source·5초 경계·상태로 TTL 갱신 금지 | 다른 프로세스/오래된 실행 정보를 차용하지 않음 |
| 오류/denied·삭제/완화 옵션·다른 실행 파일·중복·부팅 | 위험하거나 모호한 관측에서 연결 중단 |
| 원본/시각/순서·학습/모델 SHA·정상5/공격1 경계 | 변조·미상·적은 지지·학습 공격을 무시하지 않음 |
| profile 이름 비학습·changed/unchanged 분리 | 특정 파일 예외나 실제 변경의 no-op 오인을 피함 |
| 기존 오류·모든 행·정답 필드/이미지 사본 차단 | 모집단 축소나 평가 정답 유입 방지 |

[관측 시험37건](../tests/test_apparmor_causal_intent.py), [입력 분리 시험](../tests/test_vpn_protocol_stage.py), [기존 의도 모델/학습/판정 시험](../tests/test_audit_intent_context.py)을 함께 사용한다. 전체 관련644건의 통과율을 탐지 F1에 합산하지 않는다.

```text
python -m pytest tests/test_apparmor_causal_intent.py tests/test_audit_intent_context.py tests/test_apparmor_noop.py tests/test_vpn_protocol_stage.py -q
```

## 자료와 모델

게시자 [AIT LDS v2.1](https://zenodo.org/records/19483937)의 정확한 원본↔미러 라벨 쌍과 기존 물리 행을 사용한다. R/S/Wilson/Shaw/Wheeler는 명시적 학습 자료다. Fox/Wardbeck은 이번 표 학습에 넣지 않았지만 이전 노출/보정 이력을 유지한다. 원래1,681,815행, 별도 전이/학습 자료, 정책 fixture는 분리한다.

[동결 모델](../infra/f1-lab/frozen-apparmor-causal-v111/bundle.json)은 실제 사용한 head SHA와 학습 출처를 포함한다. 큰 원문·정답·봉인된 기준선 예측은 Git에 넣지 않으므로 clone+pytest만으로 전체 성능 재현이 완료되는 것은 아니다. 모델 바이트·라벨·행 수·목표를 재포맷/수정하지 않는다. [NOTICE](../infra/f1-lab/frozen-apparmor-causal-v111/NOTICE.md)의 비상업적 연구 자료 조건을 유지한다.

새로 학습할 때는 기존 `audit-intent-training-plan-1`에 각 준비/원본/정답 경로와 SHA·`role=training`·최소 지지5를 명시하고 다음 옵션을 사용한다. 평가 역할이나 잘못된 정답/행 순서는 거부한다.

```text
python -m scripts.train_audit_intent --plan <training-plan.json> --sha256 <실제 계획 SHA> --output <새 학습 출력> --with-apparmor-causality
```

## 같은 모집단에서 예측 후 별도 채점

catalog 형식과 이미지 차단·소스/입력 지문·채점 절차는 [기존 재현 가이드](vpn-protocol-test-guide.md)를 따른다. 각 기준선은 **직전 v110에서 봉인된 전체 예측 파일**이다. 선택한 프로필에 필요한 audit/auth 원문만 복사하며 다른 로그 종류의 기존 예측도 모두 유지한다.

```powershell
$auditCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/audit-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_vpn_protocol_replay --catalog runtime/f1/audit-catalog.json --sha256 $auditCatalogSha --output runtime/f1/audit-replay-01 --profile apparmor-causal
$auditStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/audit-replay-01/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/audit-replay-01 --stage-sha256 $auditStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4
```

위 도구 이름은 재사용된 기존 이름이며, 명시한 profile로 audit 원문과 AppArmor 모델/판정 옵션을 선택한다. 기본 profile은 기존 VPN이다. AppArmor profile과 VPN 공격 추가 옵션을 섞으면 실패한다. 캐시 이미지가 있어야 하며 자동 pull/build는 하지 않는다.

실행 완료·이미지 사본 차단·입력/소스 불변·예측 SHA·소유 컨테이너 제거를 확인한 뒤 호스트에서 기존 `transfer_evaluation.score`로 정답을 결합한다. 최초 사례부터 EOF까지 ID·순서·오류·모든 행을 보존한다. `--with-apparmor-causality`는 해당 학습 표를 사용하는 별도 로컬 판정 경로이며 운영 기본 탐지기/팀원 앱을 바꾸지 않는다.

[최종 수치와 한계](extra-apparmor-causal-review.md). 공유 감사 F1은 아직0%이며 이번 오탐 감소를 미탐 해결이나 독립95% 목표 달성으로 보고하지 않는다.
