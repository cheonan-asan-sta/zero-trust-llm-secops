# 실제 VPN 패킷 검증과 요청한 Docker 정리 — v122

2026-11-17 · 채희주 담당 · 무료 로컬 · 전체 탐지 목표 active

원본 수집·실제 PCAP 검증·초기 로그 진단 연결을 완료했다. 사용자가 요청한 불필요한 프로젝트 Docker 이미지 10개와 관련 캐시 38개도 정리했다. **새 탐지 후보는 채택하지 않았으며 확정 성능은 v117 그대로**다.

## 실제 자료에서 확인한 결과

[AIT Log Data Set V2.1](https://zenodo.org/records/19483937)의 RussellMitchell full archive 7,132,670,599 bytes를 수집해 게시 MD5와 대조하고 전체 로컬 SHA-256을 고정했다. Landauer et al., DOI 10.5281/zenodo.19483937, CC BY-NC-SA 4.0에 따른 비상업 연구 자료다. 원시 자료를 Git에 추가하지 않았으며 역할은 기존 **training**이다. 새 독립 최종 평가 자료로 바꾸지 않는다.

전체 archive SHA: `2da85d89764afa4ea3aa2b7565d246ccba25681866a516ddd151834089b5ab4c`.
같은 서버의 `openvpn.log` 전체 바이트가 기존 평가 source와 같음을 확인했다. 선택한 PCAP 2개는 ZIP CRC와 전체 SHA를 확인한 뒤 각각 EOF까지 읽었다.

| 항목 | 실제 결과 |
|---|---:|
| PCAP 물리 packet records | 3,210,611 |
| 허용 형식의 initial frames | 81 |
| 원래 VPN 물리 로그 행, 삭제/재라벨 없음 | 5,537 |
| 해당 초기 로그의 고유 ID/endpoint 진단 일치 | 66/66 |
| 해당 진단 창의 미일치·모호한 연결 | 0/0 |
| 원문 시각 파싱 오류·역행 | 0/0 |

나머지 5,471행은 initial 메시지가 아니며 그대로 남겼다. 물리 packet ordinals와 각 입력의 지문도 보존했다. 로그 일치율은 탐지 정확도나 사람/기기 인증 성공률이 아니다. 66건은 모두 로그에 적힌 초 안의 capture이므로 해당 일치만으로 현재 판정 시점의 이용 가능성을 입증하지 않았다. 예측기 승인·시각 이용 가능성 플래그는 계속 false다.

추출된 81개 프레임의 6개 특징은 모두 `initial UDP / TTL 63 / DF true / IHL 20 / TOS 0 / IPID nonzero`로 같았다. 고유 연결 66행의 이미 사용한 training 정답과 v117 판정을 대조하면 정상 65행(TN 63/FP 2), 위협 1행(TP 1)이 **동일 특징 셀**에 있다. 정상 지지 5 이상이어도 공격 1개가 있으므로 기존 any-attack veto가 적용된다. 이 헤더 조합으로 정상 경보를 낮추는 head를 적합하거나 채택하지 않았다. 다른 학습 출처의 실제 패킷 지지도 검증하지 않았으며 단계별 지지를 합치지 않았다.

이 결과는 확인한 6개 헤더 특징의 한계다. 모든 가능한 신호나 모델로도 목표 달성이 불가능하다는 주장은 아니다. raw IP/SID·절대 시각·정답을 배운 예외나 나중 handshake 근거를 현재 행에 넣지 않았다.

이전 stats.log의 마지막 관측 kernel_packets 3,233,007에서 kernel_drops 22,396을 뺀 값은 PCAP 물리 기록 3,210,611과 일치했다. 이는 전체 파일 집계의 교차 확인이며 특정 사건의 손실·현재 이용 가능성·무손실 캡처를 입증하지 않는다. [이전 캡처 품질 조사](extra-vpn-frame-diagnostic.md)의 한계를 유지한다.

## Docker 정리 결과

프로젝트 실행 receipt의 지문과 **정확한 이미지 ID**가 확인된 예전 이미지 10개를, 사용 중인 컨테이너 참조가 없는지 다시 확인한 뒤 삭제했다. 정확한 ID 기록이 부족한 후보 2개는 유지했다. 전체 이미지 수는 115→105다.

이미지 삭제 전후 동일한 cache ID 748개를 대조했다. 이 작업에서 삭제된 이미지 외의 이미지 ID 변화는 없었고, 기존 shared 캐시 중 38개가 private·immutable·reclaimable로 바뀌었다. 해당 38개 ID만 허용한 읽기 전용 조회를 먼저 통과한 뒤 같은 ID 필터로 정리했다. 제거된 cache ID는 허용 목록 안의 38개뿐이며 총 cache records는 748→710, Docker 보고 회수량은 **2.715GB**다.

[Docker의 필터 설명](https://docs.docker.com/reference/cli/docker/buildx/prune/)과 [실제 BuildKit v0.33.1 구현](https://github.com/moby/buildkit/blob/v0.33.1/cache/manager.go)을 확인했다. 이미지 삭제는 `--no-prune`로 상위 이미지 삭제를 제한했고, 캐시는 정확한 ID 정규식과 `type=regular`를 사용했다. `--all`이나 전체 목록 대상 prune은 사용하지 않았다. 캐시 명령의 확인 생략은 이미 요청받은 이 범위에만 적용했으며 사용/공유 참조의 보호를 해제한 것이 아니다. 현재 CLI에서 boolean 문자열 필터의 형식 차이를 발견해, 삭제 전 조회로 정확히 검증한 ID 필터와 엔진 기본 보호를 사용했다.

현재 시험 image `f10c45ff…`와 역할별 최신 baseline 6종, DB·백업/미상 volume 14개, 관련 없는 기존 컨테이너를 보존했다. 정리 후 보존 image를 pull/build 없이 network none으로 실행해 Python 3.12.16·pytest·cryptography·FastAPI import와 정상 종료를 확인했고 그 확인용 컨테이너도 제거했다. Windows VHDX의 축소나 탐색기 여유 공간의 증가를 측정한 값은 아니다.

## 성능·시험·남은 작업

이 실행은 실제 원본 intake·진단과 Docker 정리다. 탐지 코드/모델·원래 1,681,815행·정답·목표를 변경하지 않아 전체 성능 재생은 반복하지 않았다. [v117 확정 성능](extra-apparmor-status-review.md)의 공유 감사 TP 2/FP 0/FN 4·F1 50%, VPN TP 84/FP 42/FN 0·F1 80%를 유지한다. 인증·웹 감사 관측 P/R/F1 100%도 기존 결과다.

기능 코드의 마지막 Linux 964건·Ruff+RUF100 성공 기록은 [v121](extra-vpn-frame-diagnostic.md)이며, 이번 실제 intake·진단 CLI는 모두 종료 0·stderr 0이다. 새 기능 시험 수나 실제 LLM 성능 개선으로 더하지 않는다. 공유 감사에 남은 실행 주체/명령 근거, VPN의 현재 시점에서 검증된 구분 신호, 별도 Wheeler training FN 9, 원래 6영역의 새 독립 인수는 미완료다. 기존 후보와 부족한 근거를 재분석해도 실제 개선 전에는 목표 달성으로 표시하지 않는다. 장기 soak는 유예하고 유료 호출·AWS·push·새 CI·병합은 수행하지 않았다.

[전체 집계·원본/실행 지문·삭제 증거 JSON](infrastructure-results/extra-wire-data-cleanup-v122-20261117.json) · [재현 방법](packet-source-test-guide.md) · [현재 목표 표](goal-performance-progress.md)
