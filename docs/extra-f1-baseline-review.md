# extra: F1 개선 전 기준선과 오류 검토

2026-11-12 · `extra`는 계획 커밋 `9c67889`에서 만든 로컬 작업 브랜치다.
[개선 계획 F0/F1](f1-improvement-plan.md)의 기준선 고정·기계적 오류 추적·사람 검토 준비를 수행한다.
F3 탐지 규칙/임계값 개선과 새 독립 평가는 아직 시작하지 않았다.
현재 규칙·OCSF 매핑·원본 데이터/라벨과 운영 접근 정책은 바꾸지 않는다.

## 도구가 실제로 하는 일

`scripts.prepare_f1_review`는 네트워크/유료 API/Docker 없이 다음 작업을 수행한다.

1. 모델·Sigma 엔진/규칙·OCSF 매핑·평가기·벤치마크 생성기·원본 데이터/라벨·도구 소스를
   명시한 파일 목록으로 복사한다. 소스의 CRLF는 LF로 정규화하고 각 파일의 SHA-256을 기록한다.
   생성기 지문이 데이터 계약과 맞는지도 확인한다. 환경 Python/Pydantic/PyYAML 버전도 기록한다.
2. 복사한 규칙/데이터를 사용해 기존 개발360·holdout360을 실제 재평가한다. 실행 중 입력 소스가
   바뀌면 게시하지 않는다. 원본 데이터와 기존 결과는 덮어쓰지 않는다.
3. FP/FN과 **기대 규칙/실제 규칙 불일치**를 모두 추적한다. 다른 규칙이 경보를 내서 전체 TP여도
   기대 규칙이 놓친 사실을 숨기지 않는다. 원래 관측과 OCSF 입력, selector/분기/필드의 실제·기대 값,
   매칭 결과를 실제 엔진 함수로 계산하고 전체 규칙 결과와 대조한다.
4. 오류 계열별 빈 검토지를 만든다. 원인·라벨 타당성·근거 사례·수정 가설·반례는 사람이 작성한다.
   자동 매칭 추적은 근본 원인 확정이나 라벨 승인으로 처리하지 않는다.
5. 후보 파일을 해시 manifest와 함께 원자적으로 새 디렉터리에 게시한다. 외부 anchor로 검증하고
   원자료·소스·결과 변조, 추가 파일, 경로 범위/심볼릭 링크, 중복/다른 계열 검토를 거부한다.

소스 사본은 재현 근거다. 검증 도구가 사본의 임의 Python 코드를 실행하지 않는다.
검출기 자체는 현재 프로세스가 가져온 저장소 코드이며 생성/검토 중 해당 소스를 변경하지 않는다.
`source_commit`만으로 깨끗한 커밋 원본을 시험했다고 판단하지 않고 `source_dirty`와 파일 지문을 함께 확인한다.

## 실행

```powershell
.venv\Scripts\python.exe -m scripts.prepare_f1_review create --directory runtime/f1/extra-baseline-20261112 --author chaeheeju
.venv\Scripts\python.exe -m scripts.prepare_f1_review verify --directory runtime/f1/extra-baseline-20261112 --expected-sha256 <생성시_출력한_freeze_sha256>
.venv\Scripts\python.exe -m scripts.prepare_f1_review assess --directory runtime/f1/extra-baseline-20261112 --expected-sha256 <같은_외부_anchor>
```

반복 실행은 새 디렉터리를 사용한다. `freeze.json`의 지문은 그 디렉터리 밖에 보관한다.
원본 raw 결과는 `development.json`, `holdout.json`, 상세 입력/규칙 추적은 `evidence.jsonl`,
검토할 계열/사례 목록은 `review-index.json`, 사람이 수정할 파일은 `reviews.jsonl`이다.
review-index와 원자료는 동결되고 검토지만 수정 가능하다. 검토 후 검토지 자체의 지문도 출력한다.

## 직접 검토할 부분

김택희 등 다른 검토자는 `reviews.jsonl`의 각 계열에 다음을 작성한다.

- `reviewer_subject`: 실제 검토자. 구현자와 같은 이름은 거부하지만 신원 보증은 자기 신고 수준이다.
- `cause`: input_mapping / missing_observation / temporal_context / scope_exception /
  rule_condition / label_dispute / other 중 근거에 맞는 값.
- `label_assessment`: supported / disputed / insufficient. 기존 정답을 결과에 맞게 수정하지 않는다.
- `evidence_case_ids`: 같은 계열의 실제 검토 근거 사례.
- `rationale`, `proposed_change`, `counterexample`: 각각 10자 이상으로 원인 근거·가설·정상/위협 반례.
  현 정보로 원인을 확정하지 못하면 정보 부족·추가 확인 항목을 그대로 쓴다.

미작성 상태의 assess는 exit2와 pending 건수를 반환한다. 모두 작성해도 팀 합의 준비만 표시하고
`independent_review_verified:false`, `label_approval:pending`을 유지한다.
검토표에 이름을 넣는 것만으로 팀원 독립 인수가 증명되거나 새 탐지 규칙이 자동 적용되지 않는다.
개별 필드가 false여도 OR/not 조건에서는 전체 규칙이 참일 수 있다. 필드의 실패 표시만으로
근본 원인이나 조정 방향을 확정하지 않고 전체 condition과 정상/위협 반례를 함께 읽는다.

## 해석 경계

기존 holdout은 이미 본 합성 오류 분석 자료다. 이 실행을 새 blind 평가나 새로운 기업 데이터 확보로
표현하지 않는다. 기존 F1 56.25%를 올렸다고 기록하지 않는다. 공개 인증48세션의 M7 검토지와도 별개다.
지금 만든 검토 자료로 F1 단계의 실제 원인을 확인한 뒤 필요한 신호·정규화·규칙 후보를 설계한다.
정상 업무 예외의 서명/권한·테넌트/범위·유효기간 검증 없이 승인 bool만 믿는 변경은 하지 않는다.

## 11/12 실제 실행

- 기준선의 개발360·holdout360을 실제 재평가했고 기존 혼동행렬과 일치했다.
  holdout의 F1 56.25%, P64.29%/R50%/FPR27.78%이며 품질 목표 gate는 false다.
- 기계적 근거220건·22계열의 검토지를 생성했다. 기존 FP/FN200건 외에 전체 TP20건의
  규칙별 불일치도 포함한다. 이 중 다른 규칙이 경보를 낸 기대 규칙 미탐을 확인할 수 있다.
- 실제 assess는 reviewed0/pending22, 종료코드2다. 새 자료 생성·외부 anchor 검증은 종료코드0이며
  품질 목표 달성이나 사람 검토 통과를 뜻하지 않는다.
- 새 도구21개와 기존 탐지/벤치마크/파이프라인을 묶은 **74 passed**, 실패/오류/skip0,
  기존 의존성 경고3, 15.55초였다. 전체 Ruff·diff check도 통과했다.
- AWS·유료 모델 호출·Docker 자원 생성0. GitHub push/PR/병합은 하지 않았다.

실제 동결 디렉터리는 `runtime/f1/extra-baseline-20261112`이며 외부 anchor는
`801992ad587f3cc77bb857bfda0b3bfd0d857cc87e6aa1d2f479bfc10f8dfb7a`다.
소스/원자료 지문·실제 시험 범위·검토 상태는 [공개 결과](infrastructure-results/extra-f1-baseline-20261112.json)에 연결한다.
기록된 source_commit은 부모 `9c67889`이고 미커밋 도구 소스를 포함한 실제 실행을 파일별 지문으로 구분한다.
독립 원인 검토와 새 평가셋/신호 계약을 확정한 뒤 F3 후보 개선으로 넘어간다.
