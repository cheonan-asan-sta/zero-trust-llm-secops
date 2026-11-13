# Wardbeck 보정 출처의 고정 후보 검증 준비 — v63

2026-11-14. [v62 스캐너 읽기 요청 후보](extra-scanner-read-review.md)를 별도 Wardbeck 출처에
적용하는 동결·원시 준비·예측·채점 경로를 준비했다. **이 문서 시점의 실제 출처 평가는 아직 미완료다.**
아래6행 제어 시험과170개 Linux 테스트는 실제 Wardbeck 성능 수치가 아니다.

## 원래 자료 역할 보존

[처음의 개발 자료 계약](../infra/f1-lab/native-data-protocol.json)은 Wardbeck을 보정용으로 지정했다.
원시 본문을 아직 사용하지 않았더라도 최종 holdout으로 재분류하지 않는다.
이번 검증은 **보정 출처에 사전에 고정한 후보를 적용하는 출처 전이 확인**이다.
생성 계열·기간·주체/공격 계열 독립성·실제 기업 일반화는 별도로 입증해야 한다.
원래 여섯 영역의 목표·사용한 Harrison/Wilson의 용도/결과를 대체하지 않는다.

## 사전 고정 계약

- [게시자](https://zenodo.org/records/19483937) record19483937/v2_1의 `wardbeck_no-pcaps.zip`,
  818,462,147bytes, MD5 `14eeacd83571a83615c2cce1f6a6eacf`와 CC-BY-NC-SA-4.0 비상업 연구 조건을 확인한다.
- 게시자의 일정 메타데이터는 열람했다. 절대 시각·공격 일정·호스트/계정/IP 값은 분류 특징으로 쓰지 않는다.
- 정확한 대응 라벨 파일이 있는 Apache access/error의 비회전/숫자 회전 로그와 OpenVPN을 선택한다.
  세 종류가 모두 없으면 본문 준비를 거부한다. 행/크기 상한·UTC 계약·물리 파일 경계는 v53과 같다.
- 기존 v49→v51→v52 뒤에 고정 v62 후보를 적용하며, 주 비교는 **v52→v62**다.
  모든 단계의 예측·오류·사례 순서·지문을 보존하고 재학습하지 않는다.
- 예측 환경에는 원시 관측·코드·고정 모델만 제공한다. 압축 원본/정답을 넣지 않고 network none Docker를 사용한다.
  예측 컨테이너를 제거한 뒤 정답을 읽고 물리 파일별 지표·새 TP/FP·TP 손실을 채점한다.
- 후보/임계값·자료 역할·코드/모델/사례 결속 변조를 거부한다. 보정 출처를 final로 바꿔 재해시해도 거부한다.
- 출처 겹침 감사는 행을 삭제하지 않는다. 전체 결과가 높아도 VPN 등 작은 집단의 낮은 성능을 숨기지 않는다.

## 구현과 로컬 검증

`scanner_transfer.py`에 고정 계약을 두고 기존 v53의 순수 동결/검증·선택·단계 실행을 재사용했다.
기존 Wilson 기본 경로는 그대로 유지하고 별도 CLI를 사용한다.
개발 재현의 후보 소스 SHA는 다른 Git 줄바꿈에서도 같도록 기존 source_pins의 LF 정규화를 적용했다.

```text
python -m scripts.run_scanner_transfer freeze --freeze <freeze.json> --acquisition <acquisition.json> --archive <archive.zip>
python -m scripts.run_scanner_transfer prepare --freeze <freeze.json> --freeze-sha256 <SHA> --archive <archive.zip> --raw-directory <새_raw> --prepared-directory <새_prepared>
python -m scripts.run_scanner_transfer predict --freeze <freeze.json> --freeze-sha256 <SHA> --raw-directory <raw> --prepared-directory <prepared> --output <새_predictions>
python -m scripts.run_scanner_transfer score --freeze <freeze.json> --freeze-sha256 <SHA> --archive <archive.zip> --raw-directory <raw> --prediction-directory <predictions> --prediction-manifest-sha256 <SHA> --output <새_score>
```

- Windows 관련48개, network none Linux 관련170개와 전체 Ruff+RUF100 통과.
- 실제 모델·파서·네 단계·정답 채점으로6행 합성 제어를 실행했다. v62 새 TP1·새 FP/TP 손실0, 봉인 전 라벨 멤버 읽기0.
- 기존 v53 회귀·후보/자료 역할 변조·순서 결속·라벨 격리·기존 점수 재현을 함께 검사했다.
- Linux 소스956파일 불변·소유 컨테이너 제거, 유료 API/AWS 호출0.
- [준비 실행 근거](infrastructure-results/extra-scanner-transfer-ready-v63-20261114.json)를 실제 평가 완료 증거로 대신하지 않는다.
