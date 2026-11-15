# 로컬 승인 원장 백업·복원 인수

2026-11-12 후속 · [남은 작업 R2](week4-remaining-and-handoff.md).
기존 `app_state_recovery`의 정지 상태·전체 JSONL 저장 계약을 선택형으로 확장한다.
온라인 스케줄러·물리 재해 복구·운영 HA·팀원 독립 인수를 추가한 것은 아니다.

## 동작과 경계

- `--full-state --response-state`로 초기화한 저장 계약은 `response-workflow.sqlite3`를 필수 파일로 고정한다.
  기존 앱 DB와 분리하고, 외부 DB·다른 스키마·trigger·누락·손상을 거부한다.
  SQLite backup API로 WAL의 커밋까지 복사하며 동일한 논리 행 지문을 확인한다.
- checkpoint 이후 원장이 바뀌면 backup을 거부한다. 기존 암호화·서명·독립 최신 anchor·세대·유효기간
  검증을 재사용한다. 모든 원본 writer를 멈춘 정비 경계에서만 사용한다.
- 복원 전 원장·앱 SQLite·3개 JSONL·공개 신호 등록부를 같은 checkpoint와 대조한다.
  모든 과거 세션을 회수하고, **PENDING/APPROVED 계획을 REJECTED로 마감**한다.
  기존 이력은 그대로 두고 `infra-recovery`의 무효화 이력·새 버전을 추가한다.
  이전 승인으로 실행할 수 없다. 새 판단·새 요청 키·새 독립 승인이 필요하다.
- 이미 REJECTED/SIMULATED인 원래 행은 보존한다. SIMULATED의 정확한 재시도는 원래
  외부 호출0·세션 변경0의 영수증만 반환한다. 실제 계정 비활성화·기기 격리를 실행하지 않는다.
- 복원된 최종 행의 지문을 서명 release에 결합한다. 입장 검증은 기존 행의 삭제·덮어쓰기·승인 부활을
  거부한다. 그 뒤 생성된 새 계획은 기존 terminal 행을 바꾸지 않는 한 허용한다.
  앱 기동 gate는 원장 설정 경로도 복원된 데이터 경로와 일치해야 한다.
- 원장 작성/입장 게시 도중 프로세스가 종료되면 이전 release는 유효하지 않다.
  같은 암호화 백업에서 격리 복원을 다시 수행해야 한다. 원본 live DB를 덮어쓰지 않는다.

정지된 앱의 승인 원장을 계약의 정해진 파일명으로 같은 `data` 디렉터리에 배치한다.
기존 control을 덮어 초기화하지 말고 새 실험 디렉터리를 사용한다.

```powershell
.venv\Scripts\python.exe -m scripts.app_state_recovery init --directory runtime/week3/response-lab --full-state --response-state
.venv\Scripts\python.exe -m scripts.app_state_recovery checkpoint --directory runtime/week3/response-lab
.venv\Scripts\python.exe -m scripts.app_state_recovery backup --directory runtime/week3/response-lab
```

명령 전 `data/app.sqlite3`, `storage.json`, 3개 JSONL, 필요한 sources.json,
승인 원장이 준비돼 있어야 한다. 예시 명령이 기존 workload를 자동 정지하지는 않는다.
기존 원장 없는 계약은 그대로 유지하며, 기존 계약에 파일만 넣어 조용히 범위를 바꿀 수 없다.

## 검증

구현·문서 작업을 모은 후 새 원장 복원 시험과 기존 앱 정비/전체 저장/승인 시험을 함께 실행한다.
범위는 실제 SQLite·기존 서비스·프로세스 강제 종료를 사용하는 로컬 시험이다.
CA·DB 전송의 이전 Docker 인수25개와 별개의 앱 저장 계약이다.
이번 시험에서 전체 CA/관리 호스트 장애 행렬을 다시 수행했다고 표시하지 않는다.
지속 mTLS 전환 실행기는 이번 새 원장 모드로 재인수하지 않았다. 원장을 실제로 사용한 배포에서는
해당 실행기의 복사·설정·모드 연결과 종단 검증을 후속으로 해야 한다. 누락을 자동 허용하지 않는다.

최종 실행 결과는 문서 하단의 실제 기록과 공개 JSON을 따른다. 독립 검토는 계속 pending이다.

## 11/12 실행 결과

Windows/Python3.12 로컬 묶음 **181 passed, 0 failed/errors/skipped, 기존 경고2, 234.43초**, 종료코드0이다.
승인 원장 복원17개·M7 검토지9개·연결 해제 회귀1개가 새 시험이다.
기존 앱 정비/전체 JSONL 복원·승인·M7 무결성 시험과 함께 실행했으며 이전 묶음 수치와 합산하지 않는다.
전체 프로젝트2,749개나 Docker/mTLS 전체 행렬을 이번에 다시 실행한 결과는 아니다.

```powershell
.venv\Scripts\python.exe -m pytest tests/test_response_storage_recovery.py tests/test_response_workflow.py tests/test_app_state_recovery.py tests/test_app_storage_recovery.py tests/test_m7_review.py tests/test_m7_freeze.py tests/test_m7_auth_dataset.py -q --junitxml=runtime/week4-followup-20261112/final-focused.xml
```

초기 묶음은161 passed/3 failed/16 errors였다. 원장 SQLite 연결 미해제에 의한 Windows 파일 잠금,
확장된 digest 인자와 맞지 않던 기존 시험 대체 함수, 실행 중 수정이 섞인 코드 지문 불일치를 확인했다.
실패 XML을 보존하고 연결 해제·시험 대체 함수의 인자 계약을 수정한 뒤 전체181개를 새 회차로 재실행했다.
중간 새 기능26개 통과도 별도 기록하며 최종181개와 중복 합산하지 않는다.

전체 Ruff와 diff check도 통과했다. 새 Docker 컨테이너·볼륨·망을 만들지 않았고 AWS/유료 모델 호출0이다.
실제 M7 검토지 생성 후 assess는48 pending/exit2로 미완료를 표시했다.
공개 근거는 [후속 결과 JSON](infrastructure-results/week4-followup-20261112.json)에 있다.
