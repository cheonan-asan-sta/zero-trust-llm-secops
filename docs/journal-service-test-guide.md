# 과거 journal 실행 근거 연결의 시험과 재현 — v115

2026-11-16 · 무료 로컬 · 전체 목표 미달 · CI/병합 보류

[구현·실제 결과·제약](extra-journal-service-review.md)을 함께 읽는다. 원래 audit 행에 없는 auid·사람 신원·invocation을 채우지 않고, 같은 서비스에 대해 이미 수신된 journal 관측을 제한된 시간 창에서 추가 검토에 연결한다.

```text
python -m pytest tests/test_journal_service_review.py tests/test_journal_service_stage.py tests/test_vpn_protocol_stage.py -q
```

새 시험 44건은 원문/sidecar/호스트/부팅·unit/invocation·시각·수신 지연·새 실행·shell/UID/PID·DNS 전송 길이와 payload 조건, 기존 오류·경보 보존과 staging 정답 제외를 검증한다. 위는 관련 묶음이며 Linux 전체 820건과 같은 범위라고 주장하지 않는다. [실제 JUnit](infrastructure-results/extra-journal-service-v115-20261116.xml)을 함께 확인한다.

전체 성능에는 원래 AIT 감사 원문/정답·같은 archive의 journal binary·`journalctl -o json` 디코딩 결과, 준비 지문, v114 봉인 기준선이 필요하다. 큰 원문·journal·정답·기준선은 Git에 포함하지 않는다. 이번 코드/시험/문서는 로컬 커밋이며 아직 GitHub에 게시하지 않았다. clone+pytest만으로 1,681,815행 성능 재현을 마친 것으로 보고하지 않는다.

[공통 catalog](vpn-protocol-test-guide.md)의 각 scenario에 기존 preparation/raw/baseline SHA를 지정한다. 최상위 `journal_support`는 각 member의 `scenario`, `source_index`, `raw_source_sha256`, 원래 journal `member`, decoded `path`/`sha256`, `binary_path`/`binary_sha256`, `archive_sha256`, `hostname`을 가진 배열이다. 호스트는 공유 서버이고 원래 journal 경로의 machine ID와 일치해야 한다. 감사 원문과 journal binary가 같은 검증된 archive에서 나왔음을 별도로 대조한다.

```powershell
$journalCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/journal-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_journal_service_replay --catalog runtime/f1/journal-catalog.json --sha256 $journalCatalogSha --output runtime/f1/journal-replay-01
$journalStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/journal-replay-01/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/journal-replay-01 --stage-sha256 $journalStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4
```

실제 경로로 catalog를 작성해야 하며 위 예시 파일이 자동 생성되지는 않는다. 출력은 새 경로여야 한다. [staging](../scripts/stage_journal_service_replay.py)은 기존 audit/auth 원문과 기준선을 재사용한 뒤 journal 필수 필드만 투영하고 모든 물리 행을 유지한다. 원래 decoded/binary/archive 지문과 투영 지문을 함께 기록한다. 모델 파일은 넣지 않는다. 지원 근거 검증에 실패한 부분 패키지는 completed=false로 남겨 실행을 막는다.

[판정 CLI](../scripts/run_journal_service_review.py)는 journal catalog와 baseline/원문 지문을 검증하고 모든 원래 ID·순서·오류·행을 출력한다. 추가 경보의 `*.evidence.jsonl`에는 audit source/행, journal 투영 source/행·바이트 SHA, 수신 기준 근거 나이와 보고된 PID가 있다. 이는 현재 audit invocation/사람 신원/성공한 유출을 증명하는 파일이 아니다. 이번 자료에서는 부팅별 수신 시각 역행이 없음을 별도로 확인했으며, 운영 시계 역행 인수와 동일한 보장은 아니다.

예측 완료·예측/근거 봉인·격리 설정·이미지 자료 차단·source/입력 불변·컨테이너 제거를 확인한 다음 별도 호스트에서 기존 `scripts.f1_lab.transfer_evaluation.score`로 정답을 결합한다. 새 FP/기존 TP 손실 0과 원래 분모를 확인한다. 첫/나중 시각을 바꾸거나 사건 이후 받은 데이터를 소급하지 않는다.
