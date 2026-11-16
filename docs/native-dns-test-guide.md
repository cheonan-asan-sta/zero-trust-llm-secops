# Native DNS source-clock profile 재현 — v123

무료 로컬 전용이다. provider key·AWS·새 CI가 필요하지 않다. 실제 수치는 [검토 결과](extra-shared-native-dns-review.md)와 [근거 JSON](infrastructure-results/extra-native-dns-v123-20261117.json)을 따른다. 원본에는 AIT Log Data Set V2.1, Landauer et al., DOI 10.5281/zenodo.19483937, CC BY-NC-SA4.0의 비상업 연구 조건을 적용한다.

실제 검증은 기존 공개 원본의 같은 R audit 바이트와 full archive를 사용했다. raw/label/PCAP를 Git에 올리지 않았으므로 각 환경에서 [기존 수집·원문 준비](packet-source-test-guide.md)를 먼저 수행해야 한다. 새 출력 디렉터리를 사용하며 이미 성공한 결과를 덮어쓰지 않는다.

```powershell
.venv\Scripts\python.exe -m pytest tests/test_decoder_packet_fence.py tests/test_dns_capture.py tests/test_shared_dns_capture_intake.py tests/test_shared_dns_native_review.py tests/test_shared_dns_stage.py -q
.venv\Scripts\python.exe -m scripts.prepare_shared_dns_capture --acquisition runtime/f1/public-russellmitchell-packets-v119-20261116/acquisition.json --acquisition-sha256 674b9d1183bd9c528a18f3ddd1f1af61f202c9db93850b6edd67281537891490 --archive runtime/f1/public-russellmitchell-packets-v119-20261116/russellmitchell.zip --preparation runtime/f1/russellmitchell/preparation.json --preparation-sha256 0091ab22f3ffe3ee12773c7a7d6dfe127e78750faf6dbe4aca2550e39b2f3683 --raw runtime/f1/ait-lds-dev-pairs-20261112 --output runtime/f1/shared-dns-fresh
```

준비 파일 경로는 각자의 기존 preparation/raw 위치에 맞춘다. 위 pin은 실제 검증한 같은 bytes의 지문이며 다른 결과에 형식적으로 재사용하지 않는다.

실행 catalog는 `vpn-protocol-replay-catalog-1`의 기존 9개 자료를 모두 유지하고 baseline을 v117 봉인 예측의 **after**에 결속한다. `shared_dns_support`에 아래 구조를 추가한다. intake SHA는 성공한 원본 검증 결과의 외부 지문이며 정상/위협 라벨·기대값을 넣지 않는다.

```json
{"scenario":"russellmitchell","source_index":0,"intake":"runtime/f1/shared-dns-fresh/run.json","intake_sha256":"<completed-intake SHA-256>"}
```

```powershell
.venv\Scripts\python.exe -m scripts.stage_shared_dns_replay --catalog <catalog.json> --sha256 <catalog-SHA256> --output runtime/f1/shared-dns-package
.venv\Scripts\python.exe -m scripts.run_local_vpn_protocol_batch --package runtime/f1/shared-dns-package --stage-sha256 <stage.json-SHA256> --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4
```

stage에서 원래 capture/queries/stats/observations 4개 파일과 완성 report의 지문을 확인한다. 예측기에는 허용한 관측만 전달하고 archive·stats 원문·labels·tests/docs·학습 정답 집계를 전달하지 않는다. cached image가 없는 환경에서는 기존 로컬 시험 image를 준비하고 그 ID를 쓴다. 전체 1109건은 같은 source snapshot에서 새 145건과 기존 964건을 묶은 실행이다.

예측 성공·입력/코드 불변·image mask·소유 container 제거·봉인을 확인한 뒤에만 원래 9개 자료의 정답과 source 순서·case ID·분모·오류를 대조한다. primary 4개 자료는 1,681,815행이고 나머지 5개는 별도다. before가 v117 after와 같고 introduced_fp/lost_tp가 0이며 오류 행이 분모에 남는지 검사한다. 현재 local gate와 goal_qualified는 false다. 실패/미완료를 성공으로 세거나 조건을 완화하고 초기 시점에 나중 TLS/인증서를 넣지 않는다.

최종 score SHA는 `1ea913be4b32f0cb639c15659afcc6e5b2464634b97fbc4da121d0c58ff9be5c`. 로컬 runtime은 `runtime/f1/native-dns-batch-v123-20261117`. 이미 관측한 개발 source 비교이며 원래 6영역의 새 독립 평가가 아니다.
