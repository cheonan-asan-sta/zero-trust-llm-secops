# 패킷 원본 수집·초기 관측 시험과 실행 — v119

**후속 v121:** [시각 미승인 진단 연결·source 품질 조사](extra-vpn-frame-diagnostic.md)를 추가했다. 최신 관련 Linux 묶음은 964건이며 실제 source 수집/진단 실행/적합/성능 재평가는 미완료다. 아래 버전별 건수는 당시 기록이다.

**후속 v120:** [member 전체 검증·기존 VPN 원문 일치](extra-packet-member-verification.md)를 추가했다. 최신 Linux 관련 묶음은 929건이며 아래 908건은 v119 당시 결과다. 실제 원본 intake와 성능 평가는 아직 미완료다.

[구현 범위와 미완료 항목](extra-packet-source-acquisition.md)을 함께 읽는다. 이 절차는 공개 원본 확보이며 탐지 F1 시험이나 새 독립 성능 인수가 아니다. 대용량 다운로드가 포함되므로 먼저 여유 공간과 기존 실행의 실제 상태를 확인한다. 이미 진행 중인 같은 작업을 중복 시작하지 않는다.

```text
python -m pytest tests/test_f1_packet_archive_acquisition.py tests/test_f1_pcap_initial.py tests/test_f1_public_sources.py -q
python -m ruff check . --extend-select RUF100
```

위는 수집/PCAP 관련 91건이며 전체 Linux 908건과 범위가 다르다. 실제 묶음은 [JUnit](infrastructure-results/extra-packet-source-v119-20261116.xml)을 따른다. 모의 전송 시험을 대용량 외부 전송이나 정확도 검증으로 바꾸어 보고하지 않는다.

새 실행 예시:

```text
python -m scripts.acquire_f1_packet_archive --output runtime/f1/packet-acquisition-new --workers 4
```

고정 7,132,670,599바이트 파일만 받는다. 일반 수집기의 2GiB 경계는 그대로다. 로컬/test 환경과 약 15.3GB 이상의 초기 여유 공간이 필요하다. 최종 파일을 조립하는 동안 chunk와 archive가 함께 존재한다. 예상 소요 시간은 네트워크에 따라 달라진다. 진행 기록은 progress.json, 종료 결과는 acquisition.json이다. **진행 파일만으로 프로세스가 살아 있다고 판단하지 않는다.** 실행 handle 또는 정확한 소유 프로세스를 확인한다. 관측 timeout만으로 중지됐다고 판단해 재시작하지 않는다.

실제로 종료된 불완전 실행은 동일 recipe/코드로 다음처럼 재개할 수 있다:

```text
python -m scripts.acquire_f1_packet_archive --output runtime/f1/packet-acquisition-new --workers 4 --resume
```

source/chunk 변조나 다른 recipe는 거부한다. 최종 archive나 기존 조립 실패 파일을 덮어쓰지 않는다. 실패 파일을 임의로 성공 처리하거나 게시자 checksum 조건을 빼지 않는다.

원본 acquisition.json의 completed=true·publisher_md5_verified=true와 전체 SHA를 확인한 뒤 정확한 PCAP member의 bounded 복사·CRC/전체 SHA를 별도로 확인해야 한다. 해당 member가 실제 초기 frame 입력이 된 후 추출 예시는 다음과 같다:

```text
python -m scripts.extract_vpn_initial_frames --source runtime/f1/verified-member.pcap --sha256 VERIFIED_FULL_MEMBER_SHA256 --output runtime/f1/initial-observations-new.jsonl
```

예시 member와 SHA는 자동 생성되지 않으며 실제 검증된 자료로 바꿔야 한다. 일부 prefix를 전체 PCAP로 대체하지 않는다. 출력은 새 파일이어야 한다. 미지원 형식은 추측하지 않는다. capture timestamp는 근사 값이며 source/시간/SID 연결과 실제 검증된 기기 상태는 별도의 문제다. 이 CLI는 모델 적합·원래 로그 행 연결·권한 발급·자동 집행을 하지 않는다.


## v120: 원본 검증 완료 후 member intake

진행 중인 수집을 중복 시작하지 않는다. acquisition.json의 완료와 전체 checksum이 확인된 뒤 실제 원래 VPN source와 receipt SHA를 지정한다. 예시 경로/지문은 자동 생성되지 않는다.

```text
python -m pytest tests/test_f1_packet_members.py -q
python -m scripts.prepare_vpn_packet_members --acquisition runtime/f1/packet-acquisition-new/acquisition.json --acquisition-sha256 VERIFIED_ACQUISITION_SHA256 --archive runtime/f1/packet-acquisition-new/russellmitchell.zip --vpn-raw runtime/f1/original-pairs/pair-6-raw.source --vpn-raw-sha256 VERIFIED_ORIGINAL_VPN_SHA256 --output runtime/f1/packet-members-new
```

새 focused 시험은 21건이다. 이 CLI는 archive의 전체 SHA/게시 MD5와 원래 VPN 로그 바이트를 다시 확인하며, 지정된 PCAP 두 개만 고정 이름으로 복사해 CRC/SHA/초기 관측을 검증한다. 기존 일반 ZIP reader의 2GiB 경계는 유지한다. 최종 run.json의 completed=true와 지문을 확인하기 전에는 일부 출력 파일을 소비하지 않는다. 실제 로그 행 연결·적합·탐지 점수/권한 동작은 아직 포함하지 않는다.


## v121: 검증된 intake와 원래 VPN 행의 진단 연결

```text
python -m pytest tests/test_f1_vpn_initial_frame_link.py -q
python -m scripts.link_vpn_initial_frames --preparation runtime/f1/original/preparation.json --preparation-sha256 VERIFIED_PREPARATION_SHA256 --raw runtime/f1/original-pairs --intake runtime/f1/packet-members-new/run.json --intake-sha256 VERIFIED_INTAKE_SHA256 --output runtime/f1/wire-links-new
```

새 focused 시험은 35건이다. 예시 입력 파일/지문은 자동 생성되지 않으며 실제 완료한 intake와 기존 원문의 정확한 준비 지문이 필요하다. endpoint/SID와 기록된 시각 범위의 후보 일치만 조사한다. 출력 links.jsonl은 예측 파일이 아니며 모든 원래 VPN 행·오류·시각 역행을 보존한다. matched 비율을 탐지 정확도로 보고하지 않는다. 각 행과 report는 admitted_to_predictor=false·temporal_availability_proven=false다. 실제 이용 가능성 근거가 없는데 flag만 바꾸어 예측기/학습에 넣지 않는다.

## 실제 실행 v122와 Docker 정리

전체 checksum/실제 member intake/diagnostic 연결이 완료된 결과는 [v122](extra-vpn-packet-data-review.md)와 [집계 JSON](infrastructure-results/extra-wire-data-cleanup-v122-20261117.json)을 따른다. 기존 명령의 외부 acquisition pin은 `674b9d1183bd9c528a18f3ddd1f1af61f202c9db93850b6edd67281537891490`, intake pin은 `70802f633f09bb9cc060ae76b61d25ba3bb3eae0ae3cabf11548a3d622f88d3e`다. 출력은 새 디렉터리를 사용하고 원래 bytes·CRC/SHA·UTC/준비 manifest를 다시 확인한다. 정답 없는 진단 후 기존 R training 정답만 별도 검토했고 모든 예측기 승인 플래그는 false로 유지했다. Docker 정리는 이번 로컬 상태의 소유권/ID/사용 참조를 대조한 일회성 실행이며, 오래된 삭제 ID를 다른 머신에 그대로 재실행하지 않는다.
