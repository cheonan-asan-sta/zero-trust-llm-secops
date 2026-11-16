# 웹 방화벽 요청·netfilter 관측 시험과 재현

2026-11-16 · v112 · 무료 로컬

웹 서비스 저장 경로에서 요청된 방화벽 조회와 인접 netfilter 이벤트를 검토 대상으로 연결한다. NETFILTER_CFG 단독, 일반 관리자의 홈 디렉터리 작업, shell 모호성, 누락된 PAM/출처·시각 결속은 이 신호를 만들지 않는다. 프로세스 부모/사람 신원이나 명령 성공·권한을 보완하는 기능은 아니다.

| 시험 묶음 | 이유 |
|---|---|
| 실제 기록의 순서·NETFILTER/SYSCALL/PROCTITLE | 같은 audit 사건의 뒤쪽 행에만 문맥 전달 |
| PID/TTY/보고 세션·CRED_REFR/PAM 순서 | 명령 요청과 PAM 흐름을 다른 프로세스와 섞지 않음 |
| 현재/이전 행·5초·한 번 소비·여러 요청·종료/부팅 | 미래 소급·기간 연장·모호한 재사용 방지 |
| 일반 관리 경로·명령/옵션·인코딩·shell 문자 | 방화벽/커널 모듈 자체를 일괄 악성 처리하지 않음 |
| source/시각/serial/행·정답 분리·이미지 차단 | 바뀐 원문과 잘못된 순서를 성공으로 보고하지 않음 |
| 기본 비활성·기존 거부/오류·모집단 유지 | 기존 기능과 실패 사례·분모를 보존 |

[새 시험49건](../tests/test_web_firewall_context.py)과 기존 회귀를 합쳐693건이다. fixture 통과율을 탐지 F1에 합산하지 않는다.

```text
python -m pytest tests/test_web_firewall_context.py tests/test_audit_intent_context.py tests/test_apparmor_causal_intent.py tests/test_vpn_protocol_stage.py -q
```

실제 전후 성능에는 [AIT LDS v2.1](https://zenodo.org/records/19483937)의 정확히 짝지어진 원본/정답, 동일한 준비 지문·행 수, **직전 v111의 봉인된 기준선 예측**이 필요하다. 큰 자료·정답·기준선은 Git에 없으므로 clone+pytest만으로1,681,815행 성능 재현을 끝낸 것으로 보고하지 않는다. Wilson은 이미 사용한 학습 자료이며 독립 검증으로 바꾸지 않는다.

catalog 형식과 실제 이미지 준비·입력 분리·봉인 후 호스트 채점은 [AppArmor 가이드](apparmor-causal-test-guide.md)와 [공통 실행 가이드](vpn-protocol-test-guide.md)를 따른다. 모델은 v111 동결 표 그대로이고 새 규칙 학습이나 임계값 변경을 하지 않는다.

```powershell
$webAuditCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/web-audit-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_vpn_protocol_replay --catalog runtime/f1/web-audit-catalog.json --sha256 $webAuditCatalogSha --output runtime/f1/web-audit-replay-01 --profile apparmor-causal
$webAuditStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/web-audit-replay-01/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/web-audit-replay-01 --stage-sha256 $webAuditStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4 --with-network-audit-context
```

기존 도구 이름을 재사용하며 명시한 audit profile과 network 옵션을 확인한다. 옵션을 생략하면 이 새 경로는 실행하지 않는다. VPN profile과 network 옵션을 혼합하면 실패한다. 자동 pull/build는 하지 않으며 검증에 사용한 캐시 이미지와 준비된 Python3.12 의존성이 필요하다.

실행 완료·이미지 차단·source/입력 불변·예측 SHA·소유 컨테이너 제거를 확인한 뒤 기존 `transfer_evaluation.score`로 정답을 결합한다. 모든 사례 ID·순서·오류·행을 보존하고 새FP/기존TP손실을 확인한다. [실제 결과·한계](extra-web-firewall-review.md)를 함께 전달한다.
