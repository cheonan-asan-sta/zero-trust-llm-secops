# AppArmor 현재 상태 알림 시험과 재현 — v117

2026-11-16 · 무료 로컬 · 개발 비교 · 전체 목표 미달

[구현·결과·한계](extra-apparmor-status-review.md)를 먼저 읽는다. 현재 STATUS의 보고 내용을 사용하며 사람 인증이나 실제 정책 승인으로 해석하지 않는다. 경보를 낮춰도 검토가 필요하다.

```text
python -m pytest tests/test_apparmor_status_notice.py -q
python -m ruff check . --extend-select RUF100
```

첫 명령은 새 경계 시험 35건이며 전체 Linux 855건과 범위가 다르다. 전체 실행 목록과 결과는 [JUnit](infrastructure-results/extra-apparmor-status-v117-20261116.xml)을 따른다. 본 기능은 운영 기본 경로를 바꾸지 않는 명시적 로컬 프로필이다.

재적합에는 기존 audit-intent-training-plan-1의 **training 역할 소스**·준비/정답 SHA·전체 원문이 필요하다. 동결된 head와 [bundle](../infra/f1-lab/frozen-apparmor-status-v117/bundle.json)은 Git 추적 대상이다. 아래 예제의 파일과 SHA는 실제 로컬 경로·검증한 값으로 바꿔야 하며 자동 생성되지 않는다.

```text
python -m scripts.train_audit_intent --plan runtime/f1/status-training-plan.json --sha256 VERIFIED_PLAN_SHA256 --output runtime/f1/status-fit-new --with-apparmor-status
```

인과 parser 모드와 현재 status 모드를 동시에 지정할 수 없다. 이번 고정 모델은 변경/미변경의 별도 셀에 정상 20/12행·공격 0행, 최소 지지 5·공격 veto다. 원래 모델을 덮어쓰거나 평가 자료를 학습 소스로 재지정하지 않는다.

전체 성능 재현에는 원래 1,681,815행의 원문·정답과 별도 5묶음, v115 봉인된 예측, [공통 catalog 형식](vpn-protocol-test-guide.md)이 필요하다. catalog의 baseline은 v115 예측 SHA로 지정하며 journal_support는 이번 프로필에 필요 없다. 큰 원문/정답/기준선은 Git에 포함하지 않으므로 clone+pytest만으로 전체 성능 재현을 마친 것이 아니다. 코드·시험·문서·고정 head·결과는 현재 로컬 커밋이며 목표 전 GitHub 업로드는 보류다.

```powershell
$statusCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/status-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_vpn_protocol_replay --catalog runtime/f1/status-catalog.json --sha256 $statusCatalogSha --output runtime/f1/status-package-new --profile apparmor-status
$statusStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/status-package-new/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/status-package-new --stage-sha256 $statusStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4
```

출력 경로는 새 것이어야 하며 예제 image는 로컬에 이미 캐시된 시험 image다. 다른 환경에서 이미지를 준비하는 단계는 별도다. 예측 패키지는 app/scripts Python 코드, audit/auth 원문, 필요 metadata, 기존 8필드 예측, 동결 head만 허용한다. 정답·집계·문서·테스트·이전 설치 프로젝트 자료를 예측기에 제공하지 않는다. network none·출처 지문·격리 설정·입력 불변·예측 봉인·소유 컨테이너 제거를 확인한다.

그 다음 별도 호스트에서 scripts.f1_lab.transfer_evaluation.score(prediction, truth, prediction_sha256, truth_sha256)를 사용해 모든 행을 채점한다. 원래 분모 1,681,815와 별도 자료를 분리하고 새 FP·기존 TP 손실·추론 오류 0을 확인한다. 새 학습 계수와 평가 정답은 구분한다. 원래 6개 보안 영역의 독립 인수를 로그 종류별 비교로 대체하지 않는다.
