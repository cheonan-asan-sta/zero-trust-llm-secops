# 개인키 교체 인수 회차와 자원 측정 구간 격리

채희주 담당3주차 인프라 실행·측정 후속이며 Codex 도구로 구성·실행·측정했다. [PR47](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/pull/47)의
병합 전14개 성공과 [첫 병합 후 CI42451942010](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/actions/runs/42451942010)의
실패를 구분해 보존한다. 앱·탐지·평가 데이터·운영 인증/인가·인증서 TTL·서비스 timeout은 바꾸지 않는다.

## 확인한 실패

- 개인키 인수는12개 뒤 `rekey_outage_recovery_used_different_key`. 공개 진단은39신원 중 세대4가36개,
  세대5가3개, phase없음·paused=true·reload ack일치를 보였다. 시험용15초 자동 교체와 호스트 관측 사이에
  추가 회차가 시작될 수 있는 구조를 확인했다. 당시 개별 pending/현재 키 비교 값은 공개 진단에 없어
  모든 신원의 원인을 역으로 확정하지 않는다. 같은 pending키 조건을 약화하지 않는다.
- 선정 인수는37개 기능/576요청(153허용/423거부)을 모두 통과했지만 자원 수집 ValueError2건으로 실패했다.
  정상 표본1358행, 소유 자원0. 한 오류는 첫 gateway정지/복구 경계, 다른 오류는 두 번째 shared wave
  관측 중이었다. 잘못된 원시 필드가 저장되지 않아 PIDs/CPU/메모리 중 어느 값인지 단정하지 않는다.
- 나머지11개 code job은 성공했으며 최종 종합 test는 실패했다. 실패 run을 재실행해 덮지 않고 후속 PR로 보완한다.

## 개인키 시험의 한 회차 고정

`start_round`는 pause확인 → 자신의 컨트롤러 정지 → network none 도우미의 controller.lock 독점 →
일회용 state의 **last_key_rotation만** 과거로 이동 → 재시작 순서다. active신원만 이동하며 disabled/inhibited,
pending키·CSR·키 경로·개인키 바이트·인증서 유효기간·토큰·권한·공개 등록은 유지한다.
paused_ack·설정paused·transaction없음·등록 완료와 유한 시각을 확인하지 못하면 거부한다.

교체 주기는 원래 로컬 프로필 기본값600초를 사용하고 다음 교체까지의 여유를 확보한다. 실제 서명/발급·
게시·reload ack·구 키 폐기는 기존 코드를 그대로 실행한다. 매 회차의 key_generation은 기존 `>`에서
**정확히 이전+1**로 강화했다. CA장애 후 보관 pending키 게시·강제 종료 재개·폐기 collector유지와
기존 서명키 분리 조건도 유지한다. 최종 원래 설정으로 복구한 뒤 호스트 재기동을 검사한다.
이것은 정지한 시험 전용 데이터의 스케줄 제어이며 운영 CA상태를 자동 편집하는 기능이 아니다.

## 자원 측정 v2

schema는 `infrastructure-selection-verification-2`다. 종전 schema1을 새 구간 결과로 받아들이지 않는다.
각 반복은14서비스의 정상 수치가 연속3회분 확보될 때까지 준비한 뒤 실제 부하 측정을 시작한다.
오류가 나오면 그 뒤에 다시 정상3회분이 필요하며30초 안에 준비하지 못하면 실패한다.
준비 표본/오류는 `resource_warmup`과 별도 JSONL에 남겨 누락을0으로 바꾸지 않는다.

9개 workload묶음 동안만 본 Sampler를 실행하고 thread/Docker stats요청을 join한 **뒤** gateway를 중지한다.
복구 후 다음 반복은 새 준비 단계와 새 Sampler를 사용한다. `resource_windows`·표본의 window번호와14서비스
포함 여부를 서로 대조한다. 실제 부하 구간의 수집 오류0 조건은 유지한다. 이 수치는 gateway가 꺼진 동안의
CPU/메모리나 전체 장애 복구 자원 사용량이 아니다. 장애시 문서 전달0·새 grant복구는 별도 실제 검사다.

공통 Sampler는 허용된 공개 오류 코드와 값이 없는 필드명만 추가로 남긴다. 실제 원시 필드값·환경·키를
로그에 덤프하지 않는다. 비정상 값을 정상 수치로 바꾸지 않으며 PRIVATE_KEY sentinel 비노출도 검사한다.
이 구간 분리는 수집 도구의 진단·재현성 보완이며 최초 두 ValueError의 필드를 소급해 확정한 증거는 아니다.

## 재현

```powershell
.venv/Scripts/python.exe -m scripts.test_rekey_mtls_runtime --directory runtime/c02/my-rekey-round
.venv/Scripts/python.exe -m scripts.test_infra_selection_runtime --directory runtime/c02/my-resource-windows
.venv/Scripts/python.exe -m scripts.infra_selection --report runtime/c02/my-resource-windows/verification.json
```

새 directory를 사용한다. 기존 sealed release입력/운영 state를 덮어쓰거나 새 기준으로 재봉인하지 않는다.
긴 로컬 검증 중에는 작업 수명 동안만 절전 방지 요청을 사용하고 종료 시 해제한다.

## 결과와 소스 구분

로컬 개인키 인수 **22/22**, 새 측정 프로토콜 인수 **37/37**, Linux 전체 **2577통과/기존 경고2**,
고정 Ruff0.17.3과 관련 집중214개를 확인했다. 새 단위17개(회차10·관측7)를 포함하며 겹친 수를 합산하지 않는다.
부하576요청은153허용/423거부, gateway장애3회는 각각 전달0과 복구 후 새 grant전달1을 확인했다.
측정 구간 자원 표본 **1820행/오류0**, 준비 구간 오류 **0건**을 별도로 보존한다.

개인키22개는 먼저 검증·정리한 뒤 관측 보조 프로그램3개와 해당 시험2개만 변경했다. CA·키 교체·
운영 서버와 개인키 인수 드라이버의 파일 지문이 그대로임을 대조해22개 결과를 재사용했다.
전체 release 지문이 같다고 주장하지 않으며, 새 소스의 실제 측정37개·Linux 전체를 별도로 실행했다.
정확한 clean PR head와 병합 후 CI는 새 소스에서22개·37개를 포함한14개 경로를 다시 실행하고 PR에 기록한다.
개인키 인수 이후 시작한 앞선 Linux 컨테이너는 관측 보완까지 묶어 전체 회귀를 한 번 수행하려고
정확한 자신의 label/이름을 확인해 중단했으며 통과로 집계하지 않는다.

[소스·실제 결과·실패 보존 원자료](infrastructure-results/rekey-resource-isolation-20261108.json)를 따른다.
측정시간과 자원은 단일 공유 호스트/짧은3반복의 관측이며 운영 SLA/RTO/RPO가 아니다.
모든 소유 컨테이너·볼륨·네트워크0, AWS·유료 LLM 호출0이다.


## 남은 범위

C01/C02는 로컬 조건부, C03는 현재 이미지 재검사·앱 영향 독립 검토 전 보류다. 신뢰하는 로컬 결과이며
원격 증명/운영 승인·팀원 독립 재현·3주차 전체 완료가 아니다. 운영 RTO/RPO·지속 부하·물리 HA·실제
IdP/EDR·운영 DB복원과 실시간 최신 회수 원장은 별도다. 11/29 동결·12/6 제출 가능본은 유지한다.
