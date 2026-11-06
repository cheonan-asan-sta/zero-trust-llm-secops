# 인프라 사전 점검·관측 준비 검증·로컬 묶음 실행

11/7 DB 통신 자동 교체 묶음: [독립 전송 root·서버/client 키·중단 재개](database-transport-rotation.md). 채희주가 별도 보관함·서명 계획·고정 객체 정지/게시·실제 DB TLS 검증을 연결한다. 초기 Linux2383/관측75와 마지막 변조 검사46 중단을 보존했다. 예외 분류·실행기 중복 차단·시험 대기를 보완한 최종 소스의 집중229/신규47·Ruff·실제48/48·정리0을 별도 확인했다. 최종 전체 회귀/정확한 head·병합 후 CI는 PR을 따른다. DB/물리 HA·전체 백업 통합·독립 인수는 후속이다.

2026-11-06 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.

기준은 [PR39](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/pull/39)의
`6dd6cf9`다. 이전 [CA/JWK·CA 프로세스 이중화](persistent-authority-rotation.md)를 재사용하고,
이번에는 사전 차단과 검증 신뢰성을 묶는다. 앱·정책·탐지·평가 데이터와 김택희의 저장 계약은 유지한다.

## 이번에 연결한 동작

| 작업 | 이전 | 이번 동작 |
|---|---|---|
| 공유 DB 전송 PKI | 공개 파일 지문과 실제 TLS 연결에서 오류 확인 | 기동 전에 root 서명·유효기간·용도·이름·키 일치·권한을 오프라인 검사 |
| 만료 예고 | 연결 실패 때 확인 | 세 신원의 최소 남은 시간과 24시간 이내 경고를 공개 상태로 반환 |
| 관측 장애 준비 | `ALERTS` 조회 결과가 사라지기를 대기 | 대기 시작 이후의 정상/비활성 rule 평가와 최근 성공 scrape를 함께 요구 |
| 실패 진단 | 현재 rule 상태와 조회된 alert 값 | `timestamp(ALERTS)`도 수집해 표본 시각과 조회 시각을 구분할 근거 추가 |
| 로컬 검사 실행 | 기능마다 수동 명령 반복 | 같은 코드와 Docker 엔진을 고정해 전체 Linux·관측·authority HA를 한 명령으로 실행 |

## DB 전송 인증서 사전 점검

```powershell
.venv/Scripts/python.exe -m scripts.persistent_authority_runtime preflight --directory runtime/c02/my-authority
```

기존 프로필의 시작 승인 검사를 재사용한다. release·이미지/도구·고정 설정·서명된 authority 이력·
소유 볼륨과 DB 초기화 marker를 확인한다. 서비스 기동/발급/키 교체 없이 검사하며 실제 접속의
가용성을 보장하는 health 명령은 아니다. 진행 중인 authority 전환에는 기존 pinned resume 경계를 유지한다.

DB root·서버 `ca-db`·노드별 client `secops_ca`의 인증서와 키를 검사한다. 원래 고정한 root 지문,
자체/발급 서명, P-256/SHA256, BasicConstraints/KeyUsage/EKU, 정확한 CN/DNS SAN, 현재 유효기간,
각 cert/key의 공개키 일치와 세 신원의 키/serial 분리를 확인한다. 개인키는 Linux의 현재 실행 UID
소유·다른 사용자 접근 금지·단일 regular file이어야 한다. symlink·hardlink·과대 파일을 거부한다.

검사는 UID10001·network=none·읽기 전용 rootfs·권한 제거·128MiB/1CPU·15초 제한의 일회성
작업에서 수행한다. 세 전송 TLS 볼륨만 RO 마운트하며 보관함·DB 데이터·Docker socket은 없다.
키 원문은 출력하거나 호스트 파일로 내보내지 않는다. 공개 결과에는 인증서 지문/만료 시각·최소
남은 시간·권한 검사 여부만 포함한다. 실패 원문 대신 고정된 `database_transport_preflight_failed`로 거부한다.

같은 검사를 `up`의 DB/업무 시작 전과 authority 변경 단계의 사전 검사에 연결한다. 문제가 있으면
변경을 시작하지 않는다. 이미 연결된 세션을 강제로 종료하는 기능은 아니다. 만료까지 24시간 이하일 때
`expires_soon`, 유효하면 `ready`를 반환하고 만료/미래 인증서는 거부한다. 24시간은 로컬 점검의 예고
기준이며 인가/탐지 기준 변경이 아니다. **이 기능이 인증서를 갱신하지는 않는다.** DB 전송 root/leaf는
기존 2일 fixture이며 자동 수명 관리와 실제 운영 인증서 정책은 다음 작업이다.

## 관측 준비 경계와 이전 실패

PR39 병합 후 CI42214281406/attempt1은 관측23개 뒤 `monitoring_previous_alert_not_cleared`로
실패했다. 당시 exporter `up=1`·현재 rule inactive/health=ok인데 instance 없는 이전 firing series가
조회됐다. 같은 소스의 선택 재실행은72개 통과했다. 원본 표본 시각이 없어서 lookback을 확정 원인으로
기록하지 않는다. 첫 실패와 재실행 기록은 PR39에 보존한다.

이번 준비 검사는 고정한 rule 하나만 정확히 존재하고, 새 평가 시각이 대기 시작 이후이면서15초 이내이며,
state inactive/health ok/lastError 없음/활성 alert 없음인지 검사한다. 이어서 대상 exporter의15초 이내
성공 scrape를 요구한다. 누락·중복·다른 group·오래된 평가·pending/firing·평가 오류는 준비 완료가 아니다.
기존90초 대기 기준, 실제 장애 주입, 새 episode 시작 시각·instance·fingerprint 결합, 같은 episode의
resolved 판정, 실제 outage 진단·고정 시각 TSDB/AM 보존 검사는 유지한다.

과거 `ALERTS` 표본을 지우거나 경보 정책을 완화하지 않는다. 현재 상태와 이력 조회를 구분하는 근거는
[고정 Prometheus3.15.1 rule API](https://github.com/prometheus/prometheus/blob/v3.15.1/web/api/v1/api.go)와
[instant selector/lookback 설명](https://prometheus.io/docs/prometheus/latest/querying/basics/#instant-vector-selectors)이다.
회귀 테스트는 과거 firing 표본이 남아 있는 대조와 오래된/실제 활성 rule 거부를 포함한다.
실제 과거 CI 실행 환경의 원인을 재현/제거했다는 주장과는 구분한다.

## 한 번의 로컬 묶음 실행

```powershell
.venv/Scripts/python.exe -m scripts.test_infra_preflight_batch
```

새 `runtime/c02/infra-batches/<id>` 아래에 전체 결과와 단계 로그/원보고서를 남긴다.
Linux Docker 전체 Ruff/pytest, 실제 관측75개, 실제 authority/HA38개를 순서대로 한 번씩 실행한다.
로컬에서는 기존 kind와 메모리·공유 다운로드 cache의 경쟁을 줄이기 위해 순차 실행하고,
GitHub CI의 독립 runner 병렬 구성과 기존 앱 복구24/CA30/rekey22/Lambda 검증은 유지한다.

app/scripts/tests·runtime build/lock·CI·Docker 입력 지문과 현재 Git head/Docker Engine ID를 고정한다.
test image가 같은 입력을 포함하는지도 대조한다. 단계 전후 소스/엔진이 달라지면 중단한다.
한 단계가 실패하면 실패를 보존하고 같은 소스의 다른 독립 단계만 계속한다. 자동 재시도는 없다.
부분 검사/다른 소스/cleanup 누락은 성공으로 집계하지 않는다. 전체 회귀 컨테이너에는 network=none을
설정하며 업무 프로필은 기존 내부망과 rule 분석기를 사용한다. AWS 배포·유료 모델 호출은 없다.

정리는 이번 실행의 라벨/프로필 범위만 대상으로 한다. 기존 kind·ZIP·다른 Docker 자원은 건드리지
않는다. 재사용 가능한 비활성 image/build cache는 남을 수 있다. 물리 호스트 전원 상실까지 보장하는
작업 스케줄러는 아니며 중단/timeout의 정리 실패는 성공으로 바꾸지 않는다.

## 검증과 남은 범위

짧은 집중 검사236개 통과·Windows POSIX 권한1개 제외, 고정 Ruff0.17.3 통과.
신규 단위59개이며 POSIX 검사는 Linux Docker에서 실행한다. 최종 묶음 결과는
[공개 원자료](infrastructure-results/infrastructure-preflight-batch-20261106.json)와 해당 PR에 기록한다.
실행 완료 전에는75/38의 예정 건수를 통과 수치로 쓰지 않는다.

DB 전송 PKI 자동 교체·DB/물리 호스트 HA·전체 백업 복원 통합·장기 signed checkpoint·
native 즉시 폐기/기존 TLS 세션 종료·실제 JSONL writer/path 연결·김택희의 독립 인수는 남아 있다.
탐지 품질95% 달성이나3주차 전체 완료로 해석하지 않는다.

## 최종 로컬 결과 (11월 7일)

한 번의 고정 소스 묶음에서 **Linux2340통과·기존 경고2/Ruff 통과, 관측75/75, authority/HA38/38**을 확인했다. 자동 재시도0, 각 보고서·image/source/release 지문 대조와 소유 컨테이너/볼륨/망0을 확인했다. 전체 Linux는 network=none에서 실행했고 POSIX 권한 검사도 포함했다.

일치하는 개인키를 사용한 별도 RAM 대조4건(정상·SAN만 변경·EKU만 변경·KeyUsage만 변경)도 통과했다. 이는59개 신규 pytest와 별도이며 실제 TLS/파일 권한 실험으로 합산하지 않는다. 두 ZIP/기존 kind·앱/동료 저장 계약 코드 보존과 AWS·유료 LLM 호출0을 확인했다. 커밋 전 작업 트리 실행이며 정확한 clean CI 증거는 PR을 따른다.

이전 소스 release lock을 가진 프로필은 자동 승격하지 않는다. 이 명령은 현재 소스와 일치하게 승인한 새 로컬 프로필을 대상으로 하며, 기존 사용자 데이터/키의 자동 이관은 하지 않는다.
