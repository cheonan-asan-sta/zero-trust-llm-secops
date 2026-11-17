# 패킷 원본 검증 수집기와 초기 프레임 추출 — v119

2026-11-16 · 채희주 담당 · 무료 로컬 · 수집 진행 중인 시점의 개발 기록 · 목표 active

VPN 정상·위협의 초기 로그가 기존 특징에서 겹치는 문제를 조사하기 위해 공개 패킷 근거를 준비하고 있다. **수집기·초기 프레임 추출 구현과 Linux 기능/회귀 908건은 완료**했지만 원본 전체 수집·게시자 체크섬·실제 프레임과 로그 연결·모델 적합·전체 성능 재평가는 아직 완료하지 않았다. 이 문서의 완료는 구현/기능 시험 범위다.

확정 탐지 수치는 [v117](extra-apparmor-status-review.md)의 공유 감사 TP 2/FP 0/FN 4·F1 50%, VPN TP 84/FP 42/FN 0·F1 80%다. 인증·웹 감사의 관측 P/R/F1 100%와 원래 1,681,815행을 유지한다. 새 기능 fixture 성공률을 탐지 F1에 합산하지 않는다. 이전 탐지 app/scripts의 모든 바이트가 v117 기능 시험 당시와 동일함을 확인했으며, 새 모듈은 기본 판정 경로에 연결하지 않았다.

## 원본 수집 구현

[수집 CLI](../scripts/acquire_f1_packet_archive.py)는 [AIT 공식 자료](https://zenodo.org/records/19483937)의 고정 RussellMitchell full archive만 받는다. 크기 7,132,670,599바이트·게시 MD5·record/version/license와 URL을 코드에 선언했다. 임의 URL이나 다른 파일로 변경하는 인자는 없다. 기존 일반 공개 수집기의 **2GiB 제한은 바꾸지 않았다.** 별도 고정 recipe만 8GiB 이내의 이 파일을 허용한다.

먼저 게시 metadata를 대조하고 로컬/test 환경·동시 작업 1~4개·전체 크기의 두 배 이상과 추가 1GiB 여유 공간을 검사한다. 16MiB 범위를 정확한 HTTPS origin·206·Content-Range·길이·비압축 응답으로 받는다. chunk별 SHA/범위 receipt와 진행 기록을 남긴다. 짧은 응답/통신 장애는 제한된 횟수로 재시도하고, 치명적 실패에는 나머지 작업을 취소한다. 한 실행의 제한 시간은 3시간이다.

모든 범위가 모여야 순서·개별 지문을 다시 검증하고 전체를 조립한다. 전체 크기와 게시 MD5가 맞아야 최종 ZIP 이름으로 게시하며 로컬 SHA256도 기록한다. MD5는 게시 파일과의 대조이며 전자서명으로 부르지 않는다. 완료 전의 chunk나 조립 실패 파일을 검증된 archive로 쓰지 않는다. 아카이브 내용을 실행하거나 임의 member 경로에 풀지 않는다.

재개는 recipe와 수집기 코드 바이트 지문이 같고, 완료 chunk의 크기·범위·SHA가 정확할 때만 허용한다. 기존 최종 결과나 실패한 조립 파일을 덮어쓰지 않는다. 원본 수집 중 전체 checksum은 **미검증**이다. 7.1GB 다운로드는 통신 속도에 따라 시간 단위로 걸릴 수 있으며 목표 지표 도달 시각을 뜻하지 않는다.

## 초기 프레임 추출 구현

[PCAP 관측기](../scripts/f1_lab/pcap_initial.py)와 [추출 CLI](../scripts/extract_vpn_initial_frames.py)는 2GiB 이내 classic PCAP의 지원 형식만 읽는다. [libpcap 원본 명세](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in)에 따라 byte order와 µs/ns 형식을 구분하고, capture 시각은 정수 ns로 보존한다. 이는 근사 캡처 시각이며 로그 이용 가능 시각·호스트 간 시계 일치의 증명이 아니다. 물리 packet ordinal을 유지하고 시각 역행은 기록하며 임의 정렬/시각 보정으로 숨기지 않는다.

현재 지원 대상은 Ethernet/IPv4·비분할 UDP·서버 port 1194로 향하는 bare OpenVPN v2 client reset이다. opcode/key ID·8-byte SID·ACK/첫 message ID·정확한 길이를 확인한다. HMAC/tls-crypt·IPv6·VLAN·TCP·fragment·미지원 형식은 추측해서 채우지 않는다. [OpenVPN 공식 구조](https://build.openvpn.net/doxygen/network_protocol.html)와 [초기 로그의 SID 처리 원본](https://github.com/OpenVPN/openvpn/blob/v2.4.7/src/openvpn/ssl.c)을 참고했다. 이 참고 코드가 실제 대상 서버 버전을 검증했다는 뜻은 아니다.

관측 특징은 TTL·DF·IP header 길이·TOS·IP ID의 zero/nonzero 범주다. 구체적인 IP/포트/SID는 source-local 연결 hash에만 쓰며 학습 특징에 넣지 않는다. 프레임 지문·원래 source SHA·ordinal·capture 시각을 함께 출력한다. 전체 입력 SHA를 EOF와 게시 직전에 다시 확인하기 전에는 최종 출력을 만들지 않는다.

**이 헤더는 위조 가능한 네트워크 관측이며 기기/사람 신원·권한·인증 성공을 증명하지 않는다.** IP/UDP checksum이나 패킷 인증을 검증한 것으로 보고하지 않는다. 현재까지는 실제 전체 PCAP에 이 추출기를 실행하지 않았고, 원래 OpenVPN 행과의 SID/source/시각 연결도 아직 구현하지 않았다. 후기 인증서·ClientHello·연결 성공을 초기 행에 소급하지 않는 조건을 유지한다. 점수/정책/자동 차단 동작도 추가하지 않았다.

## 실제 기능 시험과 남은 검증

Windows 수집 관련 60건·새 PCAP 31건, Linux 전체 관련 묶음 **908건**·Ruff+RUF100 통과다. 새 시험은 수집기 22건·PCAP 31건이며 나머지는 기존 탐지/근거/보호 경계 회귀다. Linux는 network none·UID10001·read-only root·CPU 2/2GiB였고 소유 시험 컨테이너를 제거했다. 실제 외부 다운로드는 로컬 호스트에서 별도 공개 자료 요청으로 실행한다. network none 시험이 실제 대용량 전송 완료를 입증하는 것은 아니다.

수집 시험은 license/version/크기/checksum 변경, 잘못된 origin/status/range/길이/인코딩, 범위 경계, 전체 checksum 실패 때 최종 파일 금지, 변조된 chunk 재개 거부와 실행/디스크 조건을 검사한다. PCAP 시험은 네 가지 byte order/시각 형식, 전체 source pin·모든 물리 ordinal, 오류/잘림/조각/미지원 packet·잘못된 SID/ACK/message ID·출력 덮어쓰기 금지와 실제 신원 미검증을 확인한다.

다음은 원본 checksum 완료 후 (1) 정확한 PCAP member CRC/전체 SHA와 같은 archive의 VPN 원문이 기존 기준선과 동일함을 확인하고, (2) 원래 물리 순서·source/endpoint/SID·이용 가능 시각으로 실제 초기 프레임만 연결하고, (3) training 역할만으로 후보를 적합한 뒤, (4) 정답을 차단한 전체 재생·봉인 후 기존 모든 행에서 새 FP/기존 TP 손실 없이 목표가 개선되는지 채점하는 것이다. 패킷에 구분 근거가 없을 가능성도 남는다. 완료/향상은 실제 결과로만 판단한다.

공유 감사 FN 4·VPN FP 42·별도 Wheeler training FN 9와 원래 6영역의 새 독립 인수는 남아 있다. 실제 LLM 품질 개선/재측정은 하지 않았으며 이번에도 LLM/유료 API·AWS·push·새 CI·병합·장기 soak는 0이다.

[지문·시험·수집 상태 스냅샷 JSON](infrastructure-results/extra-packet-source-v119-20261116.json) · [실제 JUnit](infrastructure-results/extra-packet-source-v119-20261116.xml) · [실행/재현](packet-source-test-guide.md) · [현재 탐지 진행표](goal-performance-progress.md)
