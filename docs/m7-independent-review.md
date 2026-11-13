# M7 독립 라벨 검토 절차

2026-11-12 · 기존 48세션 공개 합성 인증 파일럿의 검토 준비다. 새 평가셋이나 검토 완료가 아니다.
`scripts.review_m7`은 frozen candidate의 외부 SHA-256을 확인하고 후보 사본·빈 검토지를 만든다.
관측값·출처·원본 줄 위치·게시자 라벨은 `candidate`에 있으며 검토지에는 정답을 넣지 않는다.
파일럿과 라벨이 공개돼 있으므로 이 절차를 완전한 blind 평가라고 부르지 않는다.

1. 김택희 등 구현자와 다른 사람이 `candidate/development.jsonl`, `evaluation.jsonl`의 세션 관측을 읽는다.
2. `reviews.jsonl` 각 행에 자신의 `reviewer_subject`, `reviewer_label`(normal/threat/unknown),
   같은 세션의 `evidence_ids`, 10자 이상의 `rationale`을 직접 쓴다. 관측만으로 라벨을 판단할 수 없다면
   unknown과 부족한 근거를 기록한다. 게시자 라벨을 무조건 정답으로 복사하지 않는다.
3. `candidate/labels.jsonl`의 게시자 정답·범주·원본 줄/시각과 대조한다. 라벨 기준·피처 제거로 사라진
   공격 근거·불일치·범위 밖 anomaly 제외 이유를 확인하고 원본이 필요하면 출처 계약의 고정 원본을 사용한다.
4. 아래 assess를 실행한다. 누락·같은 구현자·다른 세션 근거·중복·잘못된 anchor는 거부한다.
   검토 전 exit2/48 pending은 정상적인 미완료 결과다. 모두 작성해도 **팀 합의 준비**만 표시한다.
5. 채희주와 검토자가 불일치 해결·라벨 승인·최종 동결 anchor·실제 검토자/시각을 별도 기록한다.
   자동 도구가 사람의 신원이나 독립성을 증명하지 않으며 `independent_review_verified`는 항상 false다.

```powershell
.venv\Scripts\python.exe -m scripts.review_m7 create --frozen <동결후보폴더> --expected-sha256 <freeze.json의_외부_anchor> --directory <새_검토폴더> --author chaeheeju
.venv\Scripts\python.exe -m scripts.review_m7 assess --directory <검토폴더> --expected-sha256 <생성시_출력된_contract_sha256>
```

이 변경으로 기존 데이터·라벨·탐지 규칙을 수정하지 않는다. 검토지의 사람이 적은 이름은 자기 신고다.
48세션은 공통 모델 평가에 충분한 최종 표본 크기나 운영 비율을 보장하지 않는다.

## 이번에 준비한 검토지

`runtime/week4-followup-20261112/m7-review`에 실제 빈 검토지를 생성했다.
contract 외부 SHA-256은 `60a0ee42361fd2c5cfb62eab9d895c519585384476162e67e63aa7b4bb8fc6a2`다.
실제 assess 결과는 reviewed0/pending48, disagreements0, exit2다.
disagreements0은 아직 검토를 하지 않았다는 상태이며 ‘48건 모두 동의’가 아니다.
최종 공개 결과와 공유 묶음에는 이 검토지 사본을 포함한다.
