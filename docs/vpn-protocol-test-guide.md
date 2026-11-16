# VPN 개선 테스트 케이스·근거·재현 방법

2026-11-16 · v109 · 채희주 담당 · 무료 로컬 연구 평가

기존 테스트와 방법은 GitHub `aitest`에 있고, 이 최신 개선 묶음은 목표 충족 전 push/새 CI/병합 보류 조건에 따라 로컬 브랜치에 저장한다. **구성 요소 시험 통과와 실제 탐지 성능 평가는 구분한다.** 원래6개 보안 영역의 독립 인수는 이 VPN 시험으로 대체하지 않는다.

## 어떤 테스트이고 왜 필요한가

| 구분 | 테스트 내용 | 필요한 이유 |
|---|---|---|
| 관측 문맥 | 과거/현재 순서, 미래 기록 미사용, 재접속·idle 만료 | 뒤쪽 인증서 정보를 앞선 패킷에 붙여 성능을 부풀리지 않음 |
| 출처 결속 | 원본 SHA·물리 행·시각·순서, 다른 source/peer/port | 다른 로그나 다른 연결의 근거가 섞이는 것을 방지 |
| 명시적 위험 | 인증/TLS/인증서 오류, 과거 오류 뒤 성공·포트 변경 | 성공 응답이나 정상 학습 셀로 실제 실패 근거를 지우지 않음 |
| 모델 경계 | 최소 정상 지지5, 학습 공격1건 veto, 기본 탐지·권한 폐기 보존 | 정상 비율이 높아도 기존 위협 탐지와 현재 정책을 우선함 |
| 파일·모델 무결성 | 고정 모델/의존 모델 SHA, 경로 이동, 변조 거부 | 다른 모델을 같은 실험으로 보고하지 않음 |
| 모집단 | 정상·위협·기존 오류·비VPN행의 수와 순서 유지 | 오류/미상을 제거하거나 새 정상 행을 더해 F1을 높이지 않음 |
| 입력 분리 | 준비/원본 메타데이터 필드 허용 목록, 예측 내 정답 필드 거부 | 평가 정답·정상/위협 집계가 예측 입력으로 들어가지 않음 |
| 이미지 분리 | 이미지에 내장된 프로젝트 문서·테스트·설치 사본 차단 | 새 mount만 제외하고 이미지 안의 이전 자료를 놓치는 것을 방지 |

새 경계 시험은 [판정·학습·원본/모델 결속](../tests/test_vpn_protocol_review.py)과 [평가 입력 분리](../tests/test_vpn_protocol_stage.py)에 있다. 시험 fixture는 경계 동작 검사용이며 아래 탐지 F1에 합산하지 않는다.

## 빠른 구성 요소 시험

저장소 루트에서 개발 의존성이 준비된 Python으로 실행한다. 이 명령은 외부 LLM/AWS를 호출하지 않는다.

```text
python -m pytest tests/test_vpn_protocol_review.py tests/test_vpn_protocol_stage.py tests/test_f1_vpn_context.py tests/test_f1_vpn_risk_retention.py tests/test_f1_vpn_precision_audit.py -q
```

이번 전체 관련 묶음은 기존 감사/인증/기기/평가 회귀까지 포함한579건이다. 전체 실행의 실제 JUnit과 소스 지문은 [최종 결과 문서](extra-vpn-protocol-refinement.md)를 따른다. 빠른 시험만 실행한 결과를579건 전체 재현이나 정밀도·재현율·F1 재현으로 보고하지 않는다.

## 성능 평가 데이터의 근거

게시자의 [AIT LDS v2.1](https://zenodo.org/records/19483937) 원본과 **정확히 같은 호스트·경로의 미러 라벨 파일**을 사용한다. 원래 물리 행 번호의 공격 관련 라벨이며 독립 사람이 심사한 실제 기업 사고 정답과 다르다. 라벨 파일이 없는 로그를 정상으로 만들지 않는다. 게시자 크기/MD5와 로컬 SHA, 원본·라벨 SHA, UTC facts와 원래 행 수를 확인한다. 압축의 명령이나 코드는 실행하지 않는다.

새 VPN 의도 표는 R/S/Shaw/Wheeler 개발 자료로 학습하고 Fox/Harrison을 이번 표 학습에 넣지 않았다. 모두 이미 관측하거나 같은 생성 계열을 소비한 자료이므로 새 독립 최종 평가가 아니다. 학습된 정상/공격 셀 집계는 모델 파라미터로 제공한다. 평가 정답과 평가 집계는 별도로 차단한다.

기존 전체1,681,815행의 전후 비교, 별도 Harrison VPN11,090행, 기존 전이8,908행, 새로 소비한 학습용 VPN24,474행을 각각 보고한다. 새 정상/학습 행을 기존 시험 분모에 합산하지 않는다. 원시 로그·정답과 큰 기준선 예측 파일은 Git에 포함하지 않으므로 **저장소만 clone해서 pytest를 실행한 것과 이 성능 실험을 재현한 것은 다르다.**

## 고정 모델과 실행 입력

[고정 모델 묶음](../infra/f1-lab/frozen-vpn-protocol-v109/bundle.json)은 새 표와 기존 판정 모델의 파일 경로·SHA를 연결한다. 모델 파일은 실제 검증에 사용한 바이트 그대로이며, [NOTICE](../infra/f1-lab/frozen-vpn-protocol-v109/NOTICE.md)의 비상업적 연구 자료 이용 조건을 유지한다. 경로 이동 후 로딩과 변조 거부를 실제 시험했다. 모델 JSON을 재포맷하거나 줄바꿈을 바꾸지 않는다.

전체 전후 실험에는 준비 메타데이터, 원본 폴더, **이미 봉인한 기준선 예측**이 필요하다. 다음은 catalog 형식이다. 경로는 저장소 루트에서 접근 가능한 실제 파일로, SHA는 해당 파일의 실제 값으로 설정한다. 예시 문자열을 그대로 사용하거나 결과 숫자를 맞추려고 모집단·정답을 고치지 않는다.

```json
{
  "schema": "vpn-protocol-replay-catalog-1",
  "scope": "observed_development",
  "goal_qualified": false,
  "scenarios": [{
    "name": "russellmitchell",
    "preparation": "data/russellmitchell/preparation.json",
    "preparation_sha256": "<해당 준비 파일 SHA-256>",
    "raw": "data/russellmitchell/raw",
    "baseline": "data/baseline/russellmitchell-predictions.jsonl",
    "baseline_sha256": "<봉인된 기준선 예측 SHA-256>",
    "population": 295243
  }]
}
```

[학습 CLI](../scripts/train_vpn_protocol.py)는 별도의 `vpn-protocol-training-plan-1` 계획에서 `role=training`을 명시한 자료만 받고 정답 순서/사례 ID/지문을 확인한다. 평가 역할을 학습에 넣으면 실패한다. 고정 모델을 재현하는 평가에는 재학습이 필요하지 않다.

## 평가 정답을 제외한 로컬 Docker 실행

[패키지 생성기](../scripts/stage_vpn_protocol_replay.py)는 메타데이터의 라벨 경로/집계를 제거하고, 필요한 VPN 원문·기준선 예측·고정 모델·Python 코드만 새 폴더에 복사한다. 코드 archive에는 테스트/문서가 없다. 기준선에 별도 정답 필드가 있거나 행 수·지문이 다르면 실패한다. 원본과 projection 지문을 함께 저장한다.

PowerShell 예시다. 실행 폴더는 새 이름을 사용한다.

```powershell
$vpnCatalogSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/replay-catalog.json').Hash.ToLowerInvariant()
python -m scripts.stage_vpn_protocol_replay --catalog runtime/f1/replay-catalog.json --sha256 $vpnCatalogSha --output runtime/f1/vpn-replay-01
$vpnStageSha = (Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/f1/vpn-replay-01/stage.json').Hash.ToLowerInvariant()
python -m scripts.run_local_vpn_protocol_batch --package runtime/f1/vpn-replay-01 --stage-sha256 $vpnStageSha --image sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4
```

[실행기](../scripts/run_local_vpn_protocol_batch.py)는 이미 로컬에 있는 이미지 ID만 사용하며 자동 pull/build를 하지 않는다. 위 digest는 이번 검증에 사용한 캐시 이미지다. 다른 환경에는 동일한 테스트 의존성과 지원하는 Python3.12 이미지가 준비돼 있어야 한다. 저장소의 [테스트 이미지 정의](../Dockerfile.test)를 참고할 수 있으며, 다른 이미지/의존성을 사용한 결과는 그 지문을 별도로 기록한다. CPU2·메모리2GiB·network none·UID10001·capability 제거·읽기 전용 root로 실행한다.

기본 이미지의 `/workspace`, 설치된 프로젝트 `app` 사본과 해당 배포 metadata를 빈 읽기 전용 tmpfs로 가린다. 시작 시 그 경로가 비었는지, 실제 app 코드가 `/work/app`에서 오는지 확인하고 `results/image-scope.json`을 남긴다. 알려진 프로젝트 사본이 남으면 성공 보고하지 않는다. 자기 소유 ID/label/image가 일치하는 컨테이너만 제거한다.

## 채점과 결과 판정

`execution.json`의 완료·입력/소스 불변·이미지 차단·소유 컨테이너 제거와 `prediction-seal.json`의 예측 SHA를 먼저 확인한다. 그 뒤 호스트에서 정답을 열고 [기존 고정 채점 함수](../scripts/f1_lab/transfer_evaluation.py)의 `score(prediction, truth, prediction_sha256, truth_sha256)`로 평가한다. 원본의 모든 사례 ID·순서·모집단이 일치해야 한다. 추론 오류와 미상 사례를 정상으로 바꾸거나 제거하지 않는다.

새FP·기존TP손실·종류별 P/R/F1·FPR/FNR을 이전 결과와 비교한다. 같은 입력에 정답을 보고 예외를 넣는 대신 부족한 관측과 실패 후보를 남긴다. 유효성 검증 실패나 목표 미달을 통과로 고쳐 쓰지 않는다. 일반적인 fixture 통과율을 탐지 F1에 합산하지 않는다.

기본 이미지가 이전 자료를 포함했던 첫 실행과, 해당 경로를 차단한 재실행을 구분해 보존한다. 이전의 “새 mount에 문서/테스트 없음” 확인만으로 이미지 전체까지 차단됐다고 해석한 부분은 [최종 결과의 환경 정정](extra-vpn-protocol-refinement.md)에 명시한다.
