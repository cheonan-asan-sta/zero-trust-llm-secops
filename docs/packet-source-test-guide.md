# 패킷 원본 수집·초기 관측 시험과 실행 — v119

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
