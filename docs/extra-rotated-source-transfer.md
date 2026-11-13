# 회전 로그를 포함한 출처 분리 평가 준비 — v53

2026-11-14 · [v51](extra-command-history-development.md)과 [v52](extra-post-refinement-development.md)를
사전에 고정해 별도 Wilson 출처에 적용할 실행기를 구현했다.
**실제 동결·예측·채점·겹침 감사를 완료했다. [최종 평가 결과](extra-wilson-source-transfer.md)를 참조한다.**
아래 구현 검증 수치는 준비 단계의 기록이며, 실제 평가에서는 동결 후 원시 본문을 열고 예측 봉인 후 정답을 열었다.
[준비 근거 JSON](infrastructure-results/extra-rotated-transfer-ready-v53-20261114.json)은 구현 검증 기록이며
실제 후보 동결·예측·채점 완료 증명으로 사용하지 않는다.

## 사전 고정하는 범위

| 항목 | 계약 |
|---|---|
| 출처 | AIT LDS v2.1, `wilson_no-pcaps.zip`, 게시자 record19483937·MD5 고정 |
| 후보 | v49 민감 파일 읽기 → v51 선행 위험 문맥 → v52 성공 POST 보정 |
| 대상 | 정확한 라벨 미러가 있는 Apache access/error와 OpenVPN |
| 웹 회전 | 비회전 또는 `.log.1`~`.log.9999`; 모호한 번호·압축·백업 접미사 제외 |
| 필수 지지 | access·error·VPN 세 종류가 모두 있어야 원시 본문 읽기 시작 |
| 물리 파일 | 별도 문맥으로 유지; 파일 간 이력 병합·중복 삭제·형제 파일 라벨 차용 없음 |
| 분모 | 선택된 물리 로그 전체 행. 추론 오류도 유지 |
| 상한 | 전체200만 행; access 파일당200만 행/512MiB, error·VPN10만 행/64MiB |
| 기존 모델/임계값 | 파일 SHA 고정, 재학습 없음, 경보0.95·POST 증거0.05·명령 이력60초 |
| 시간 | 게시자 시뮬레이션 기간과 호스트 UTC 확인; 공격 시각을 특징으로 사용하지 않음 |

게시자의 [데이터 설명](https://zenodo.org/records/19483937)에 따라 원본 경로와 같은 위치·이름의
라벨 파일을 연결하고 물리 행 번호를 보존한다. 라벨 파일이 없는 로그를 정상으로 간주하지 않는다.
게시자 메타데이터에는 공격 일정도 보이며 이 열람 사실을 계약에 남겼다. 원문/정답 본문 열람과는 구분한다.

## 실행과 검증 순서

1. **동결:** 완성된 수집 영수증·압축파일 SHA·게시자 식별·사용 조건을 확인한다.
   이미 열람한 출처의 접근 이력이 있으면 새 후보 동결을 거부한다. 코드·프로토콜·모델 지문을 함께 기록한다.
2. **원시 준비:** ZIP 목차로 정확한 쌍과 세 종류의 지지를 확인한 뒤 원문/UTC 메타데이터만 읽는다.
   전처리 출력에는 관측과 참조만 만들며 정답 파일을 만들지 않는다.
3. **예측:** 고정 v49·v51·v52의 각 전체 예측과 최종 v49↔v52 비교 파일을 생성한다.
   단계별 사례 순서·행 수·오류 분모와 SHA를 확인한 뒤 예측 manifest를 기록한다.
4. **실행 환경 분리:** 실제 평가에서는 예측 컨테이너에 압축파일·정답을 마운트하지 않고 network none으로 실행한다.
   예측 컨테이너를 정리한 뒤 별도 채점 프로세스에서 정답을 읽는다. 실제 Wilson 실행에서도 이 순서를 확인했다.
5. **채점:** 예측/원문 manifest·중간 단계 지문을 다시 확인한 뒤 정답을 읽는다.
   전체 및 물리 파일별 수치, 각 단계의 새 TP/FP·기존 TP 손실을 함께 남긴다.
6. **중복 감사:** 고정된 예측을 확인한 뒤 기존 R/S/F와 이미 관측한 Harrison 웹·VPN의
   원시 파일 SHA 및 특징 벡터 일치를 센다. 일치 행을 삭제하거나 정답을 후보에 되돌리지 않는다.
   `audit_transfer_overlap --protocol rotated`는 해당 동결 계약을 처음과 끝에 검증한다.

[rotation_transfer.py](../scripts/f1_lab/rotation_transfer.py)에 고정 계약·선택·최종 예측 결합을,
[run_rotated_transfer.py](../scripts/run_rotated_transfer.py)에 단계별 CLI를 구현했다.
기존 v49 원시 준비 함수에는 검증기/선택기 인자를 선택적으로 추가했으며 기본 동작은 유지했다.
기존 v49 후보·이미 소비한 Harrison 결과를 새 평가로 소급 변경하지 않았다.

```text
python -m scripts.run_rotated_transfer freeze --freeze <freeze.json> --acquisition <acquisition.json> --archive <archive.zip>
python -m scripts.run_rotated_transfer prepare --freeze <freeze.json> --freeze-sha256 <SHA> --archive <archive.zip> --raw-directory <fresh-raw> --prepared-directory <fresh-prepared>
python -m scripts.run_rotated_transfer predict --freeze <freeze.json> --freeze-sha256 <SHA> --raw-directory <raw> --prepared-directory <prepared> --output <fresh-predictions>
python -m scripts.run_rotated_transfer score --freeze <freeze.json> --freeze-sha256 <SHA> --archive <archive.zip> --raw-directory <raw> --prediction-directory <predictions> --prediction-manifest-sha256 <SHA> --output <fresh-score>
```

파일 지문은 변경을 검출하는 수단이다. 다른 사람이 도구 밖에서 원문·라벨을 봤는지 자동 증명하거나
독립 라벨 심사를 대신하지 않는다. 실패한 부분 출력은 보존하고 다른 후보로 같은 자료를 반복 조정해
최종 평가라고 부르지 않는다.

## 현재 구현 검증

- Windows 관련53개 통과. 신규 계약/선택/결합24개와 실제 모델·세 단계 제어 재생1개를 포함한다.
- Linux Docker 관련149개 통과, 실패/skip0, 전체 Ruff+RUF100 통과.
  원래 v49 선택/평가와 v50 회전 선택, 전처리, v51/v52 회귀도 함께 확인했다.
- 5행 합성 제어군에서는 access·error·VPN을 준비하고 실제 모델·문맥·세 단계·채점 함수를 실행했다.
  예측 고정 전 라벨 멤버 읽기0, 추론 오류0을 확인했다. 이 제어군은 새 독립 성능 자료가 아니다.
- 첫 Linux 시도는 5행 테스트가 기본21GiB 디스크 예산을 요구해 2GiB tmpfs에서 거부됐다.
  테스트에 작은 명시적 예산을 지정해 재검증했다. 실제 평가의 디스크·모집단 보호 조건은 낮추지 않았다.
- Linux는 캐시 이미지·network none·비root·읽기 전용 root로 실행했다. 소스922파일 불변과 소유 컨테이너 제거를 확인했다.
  유료 LLM/AWS 호출0. 다운로드는 게시자의 비상업 연구 사용 조건을 따르는 공개 자료 수집이다.
- 중복 감사 연결 보완 후 Windows 관련25개와 Linux 관련149개를 다시 통과했다.
  마지막 Linux 스냅샷은924파일이며 전체 Ruff+RUF100, 소스 불변, 컨테이너 제거를 확인했다.
  합성5행을 자기 자신과 대조하면5행이 겹치고 제거 행0, 정답 본문 읽기0이며
  변조된 예측 manifest 지문은 거부된다. 앞선149개와 합산하지 않는다.

## 원래 목표와의 관계

현재 확인한 개발 개선은 오탐122건·미탐9건 감소, 기존 TP 손실0이다.
Harrison 웹 개발 F1은99.9689%·오탐률4.6013%지만 VPN과 원래 여섯 영역의 독립 인수는 미완료다.

Wilson은 개발 자료와 생성 계열 및 시기가 겹친다. 이 실험은 **출처를 분리한 전이 평가**이며,
시간 순서·주체·기기·세션·공격 계열까지 모두 독립인 최종 기업 성능 평가로 대체하지 않는다.
계약은 `forward_time_split=false`, `goal_qualified=false`, `original_six_domain_goal_replaced=false`다.
결과가 좋아도 이 구분을 유지하고 낮은 VPN 정밀도나 부족한 신호를 전체 행 수로 숨기지 않는다.
