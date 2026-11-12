# 다른 AI 작업자를 위한 프로젝트 인수인계서

## 현재 상태: 새 독립 평가 자료 수집과 탐지 후보 개선 재개

2026-11-12 사용자 재개 지시로 P/R/F1 각각95% 이상·FPR5% 이하의 **새 독립 평가**를 목표로 진행한다.
이 목표에는 이전09:00 종료 시각을 적용하지 않는다. 원본 `app/`·규칙·기존 라벨은 보존한다.
기존 관찰 holdout의 초안 F1 80%·FPR33.33%는 목표 미달이며 새 독립 성능이 아니다.
새 자료가 없다는 사용자 답변에 따라 공개 자료와 무료 로컬 수집을 사용한다.
독립 사람 검토자를 확보한 것으로 기록하지 않으며 검토자 신원·승인을 만들어 넣지 않는다.

같은 Docker 엔진에 재연결하여 이전 두 소유 컨테이너의 exited255·OOMfalse를 직접 확인했다.
최종 status가 없어 장시간 시험은 **미완료**다. 공개 증거만 회수한 뒤 정확한 두 컨테이너와
소유 파생 이미지만 제거했고 남은 소유 컨테이너0을 확인했다. 다른 서비스/데몬은 변경하지 않았다.
[v15 실제 정리 근거](docs/infrastructure-results/extra-interrupted-cleanup-v15-20261112.json)가
v14의 정리 미확인을 갱신한다. 이전 Windows418·전체 Linux3153 통과는 그 소스의 기록으로 보존한다.

AIT 공개 원시 로그/경보의 고정 버전·라이선스·크기·체크섬을 확인하고 수집기를 구현했다.
[수집·평가 계약](docs/extra-native-evaluation.md)과 `infra/f1-lab/native-data-protocol.json`을 따른다.
개발 시나리오만 본문을 읽고 최종 예약 시나리오의 본문/라벨은 후보 동결 전 읽지 않는다.
새 독립 성능 수치는 아직 없다. 결측 IdP/EDR/업무 승인 정보를 정상으로 채우지 않는다.
개발 경보45,544행 변환·파싱/관측 오류0, 현재 관련 집중 시험 Windows204·Linux204개 통과다.
원시 ZIP522,084,364바이트 전체 MD5/SHA 검증 완료. 실제 최상위 gather/labels 경로·dataset.yaml을 지원했다.
개발 원시8쌍295,243행(공격61,862/정상233,381)을 색인했다. 후속 시간 전수 감사에서 실패/범위 밖0,
특징 오류0·웹 시간 역순3곳을 확인했다. [원시 후보 개발 진단](docs/extra-native-candidate.md)을 따른다.
경보의 정확한 정답 연결은11,019건(공격10,918/정상101), 미확정34,525건으로 알려진 부분에 공격 편향이 크다.
이 부분만 성능 분모로 삼지 않는다. 전체295,243 원시 행으로 새 통계 후보를 개발 재대입했다.
임계값0.5의 F1 98.66%는 독립 성능이 아니며 파일별 평균 재현율30.28%·웹 FPR53.89%·감사/VPN/CPU R0으로 미채택이다.
기존 holdout shadow F1 80%와 자료/범위가 다르므로 원본 대비 개선 폭으로 쓰지 않는다.
후속 v20에서 실제 CPU/감사 명령·HTTP 과거 창을 추가했고 기존 파일·정답·실패한 후보는 보존했다.
추가 관측 NB는 웹 FP506으로 악화했다. 결정트리 후보는 개발 재대입 F1 99.09%·웹 FP0/835·인트라넷 감사 TP8/9지만
파일별 평균 재현율44.55%·VPN/CPU/공유감사 R0으로 최종 후보 미채택이다. 단독 특징의 기여도 실험은 아니다.
다음은 관측 종류별 학습 불균형/판단 근거 부족과 다른 개발 시나리오에서의 일반화 검토다.
AIT만으로 여섯 영역 전체를 입증할 수 없으므로 [추가 맥락 출처 검토](docs/extra-contextual-source-review.md)를 함께 진행한다.
GRAAI 사전 계약 뒤 고정7z25,241,476바이트·단일 CSV838,136,631바이트 전체 해시를 검증했다.
최초128개 개발 기록만 구조를 봤고102개 명시 JSON 라벨·26개 비JSON/미해석 메시지가 있었다.
`runtime/f1/contextual-schema-probe-20261112`의 나머지 기록은 격리 상태이며 독립 최종 평가로 인증하지 않았다.
후속 사전 감사 계약 뒤347,768건을 기계적으로 연결/라벨 메타데이터 검사했다. 사례별 후속 본문 출력/모델 학습0,
명시 정상141,153·공격140,637·라벨 미확정65,978이다. 안정 브라우저/반복 요청 가정까지 적용한 probe 연결280,859행,
미연결이지만 링크가 있는985행을 새 독립 최종으로 인증하지 않았다. 선언된 명시 신뢰 필드 이름 목록에 일치한 경로0이다.
지문은 기기 건강 상태가 아니고 DB 연결 정보는 자원 소유자의 역할 정책이 아니다. 없는 라벨/신뢰 주장을 정상으로 채우지 않는다.
santos 수집 세션69533과 준비/전이 세션36198은 완료exit0이다. 재시작하지 않는다.
고정 v20 모델을 재학습 없이295,976행에 적용해 P99.73/R97.56/F1 98.63/FPR0.0499%였다.
그러나 웹 FPR6.95%·파일별 평균 재현율41.92%·VPN/CPU R0이며 개발 시나리오 간 진단일 뿐 최종 인수가 아니다.
[전이·새 맥락 자료 기록](docs/extra-native-transfer.md)을 따른다. 최종 예약 harrison/wilson 본문·행별 정답은 읽지 않는다.
[v22 메타데이터·관측별 후보](docs/extra-metadata-and-heads.md)에서 종류별 학습과 순서 이진 분할을 추가했다.
순서 이진 후보는 CPU R49/49·S44/44/FP각1로 개선했지만 S VPN FP1152/5594·웹 FP116/1668로 미채택이다.
Santos는 이미 관찰한 개발 자료이며 v22 재적용을 새 독립 평가로 부르지 않는다. 이전 범주형 후보 실패도 남겼다.
[v23 단일 이진·CloudTrail 감사](docs/extra-flat-tree-and-cloud.md)에서 단일 순서 이진 모델은 S 개발 자료
P99.73/R97.91/F1 98.81/FPR0.0511%였다. CPU44/44·FP1로 개선했지만 VPN0/28·인증2/12·웹FPR6.71%로 미채택이다.
S는 이미 관찰한 자료다. `785862dedbb8d2627204e99b08400639d7b80f88a43e250707bd7b21130cc89f` 모델을
재학습 없이 전이했으며 최종 예약 AIT 자료는 읽지 않았다.
고정 ArielCyber CloudTrail 학습 ZIP2개를 사전 계약 후 수집/검증하고20,711행(정상20,170·공격541)의 관측/정답을 분리했다.
관측 오류/라벨 미확정0이지만 실제 계정 활성·기기 건강·자원 소유 정책·업무 승인은 없다.
`mfaAuthenticated=false`는 MFA 미사용이며 실패가 아니다. 정상 AssumedRole에도 존재한다.
라이선스 파일/API 명시가 없어 읽기 전용 구조 연구만 진행하고 제품 채택·재배포는 미선정이다.
CloudTrail 모델 학습0·테스트 ZIP 다운로드0이다. 다음은 원래 여섯 영역의 데이터/권한 맥락과 새 자료의 주체·시나리오 경계를 보완하는 것이다.
[v24 정보/라벨 검토](docs/extra-cloud-information-and-labels.md)에서 현재 CloudTrail 특징으로 같은 학습 자료에
도달 가능한 이상적 최대F1은93.7622%·최소 오분류64였다. 정답을 쓰는 진단이며 모델 성능이 아니다.
S3의 요청된 ACL/암호화만 추가한 별도 프로필도 상한 개선0·정답 지문 동일이다. 원본 관측을 덮어쓰지 않았다.
학습 파일 공통principal7개/관련7190행·발급역할4개/5487행으로 무작위 행 분리의 독립성을 추정하지 않는다.
ZTA-RAD 전문가 CSV 첫128개·노트북 코드2개만 조사했다. 전문가 CSV 생성 경로에 집계 위험 규칙이 있어
독립 공격 사건 정답으로 채택하지 않았다. 기기 계열103/128·HTTP77/128 결측은 전체 비율이 아니다.
이후 CSV 행 사례 분석/노트북 실행0·SMOTE/LLM 라벨 자료 미수집이다.
다음은 미래/정답을 쓰지 않는 과거 이력·검증 가능한 주체/권한 맥락을 보완하는 것이다. 여섯 영역의 최종 평가 부족은 남는다.
[v18 실제 자료 근거](docs/infrastructure-results/extra-native-actual-pairs-v18-20261112.json)를 따른다.
[v19 원시 후보 근거](docs/infrastructure-results/extra-native-raw-candidate-v19-20261112.json)는 개발 재대입과 미채택 사유다.
[v20 맥락/트리 근거](docs/infrastructure-results/extra-native-context-tree-v20-20261112.json)도 독립 성능이나 원본 대비 개선 폭이 아니다.
[v21 고정 전이·맥락 수집](docs/infrastructure-results/extra-native-transfer-v21-20261112.json)의 모델 상태 전후 일치와 잔여 문제를 보존한다.
[v22 감사/후보 근거](docs/infrastructure-results/extra-metadata-heads-v22-20261112.json)는 여전히 goal_qualified=false다.
[v23 단일 이진/학습 감사 근거](docs/infrastructure-results/extra-flat-cloud-v23-20261112.json)도 goal_qualified=false다.
[v24 정보 부족/라벨 근거](docs/infrastructure-results/extra-cloud-information-v24-20261112.json)도 goal_qualified=false다.
로컬 구현·검증·문서만 수행하며 GitHub 업로드/병합·AWS·유료 API를 실행하지 않는다.

아래의 **진행 중** 표기는 관측 중단 이전의 당시 기록이다.

진행 중 목표(11/12 02:26 KST): 사용자가 목표 달성 또는 오늘9시까지 지속 작업을 지시했다.
오전/오후 확인 전 종료 기준은 11/12 09:00 KST다. [extra 지속 실험](docs/extra-f1-experiments.md)을 이어간다.
**진행 중 장시간 시험:** `runtime/f1/extra-soak-20261112-03/run.json`의 소유 컨테이너/파생 이미지를 확인한다.
종료 예정08:50 KST이며 helper 세션70567이 공개 stdout 증거를 수집한 뒤 소유 자원을 정리한다.
`extra_start_frozen_soak_03.py`를 사용했고 다른 기존 컨테이너/데몬은 중지하지 않는다.
중간 checkpoint는 완료가 아니다. 종료 상태·공개 파일 SHA·private runtime0·컨테이너/이미지 제거를 확인해야 한다.
**추가 진행 중:** 사용자 프로필 `runtime/f1/extra-subject-soak-20261112-02`는 전체 Linux pytest 뒤
08:45 KST까지 실행한다. helper 세션55094, `extra_start_frozen_subject_soak_02.py`, 고정460파일이다.
최초01은 통제 증거 문서2파일이 빠져3152통과/1실패·soak 시작0이며 소유 컨테이너/파생 이미지0으로 정리했다.
앱 수정 없이 증거 문서를 source snapshot에 추가해02를 실행한다. 실패 회차는 보존한다.
읽기 전용 Docker 자원 관측02 세션88019는 두 소유 컨테이너만60초 간격으로 측정하며08:51까지다.
기존 관측 세션33253은01실패/기존 v9 관측 이력으로 별도 보존하며 회차 수를 합치지 않는다.
두 시험은 서로 다른 소스/profile이다. 각 완료/해시/정리를 별도로 확인한다. 현재 Windows 최종418개 통과다.
02 재실행 **전체 Linux3153개 통과·실패/오류/skip0** 뒤05:46 KST 첫20고유 이벤트/원장20행으로 soak를 시작했다.
`start-checkpoint`는 공개 파일/전체 XML과 source460 지문이며 완료가 아니다.
[v13 시작 근거](docs/infrastructure-results/extra-subject-soak-start-v13-20261112.json)를 따른다.
최종에는 `extra_validate_public_soaks.py`로 공개 증거의 일정/원장/해시/실행 간격과 각 정리를 대조한다.
기존 app/규칙/라벨은 보존하고 shadow v1은 관찰 holdout F1 80%·FPR33.33%로 **목표 미달**이다.
서명 없는 승인 정보를 제외한 개발 투영에는 충돌30그룹이 있다. 서명 업무 맥락·초안/원본 비교를
실험했고 v8 최종 Windows307·Linux307개가 각각 통과했다. 시계 high-water·비교기별 오류 분모,
관측 출처 snapshot pin과 판단 근거 부족 표시를 보완했다.
서명된 누적 작업 맥락을 넣은
별도 제어군96세션은 TP54/FP0/FN0/TN42였으나 모의 조직 승인·작성된 시나리오다.
[v3 근거](docs/infrastructure-results/extra-window-v3-20261112.json)와 실험 기록을 따른다.
[v4 근거](docs/infrastructure-results/extra-inference-v4-20261112.json)는 최초 시계 회귀 실패와 수정 후 결과를 구분한다.
[v5 근거](docs/infrastructure-results/extra-source-v5-20261112.json)는 원본56.25%·초안80% 재현과
holdout 판단 근거 부족30건을 기록하며 분모에서 빼지 않는다.
[v6 개발 한정 보정](docs/infrastructure-results/extra-calibration-v6-20261112.json)은7후보·31연결성분의
그룹 교차 검증에서 F1 83.78%/FPR33.33%로 미달이다. 선택된 auth-5를 채택하지 않고 기본3/8/500을 유지한다.
[v7 자원 정책](docs/infrastructure-results/extra-resource-v7-20261112.json)은 공개 정책 pin·행위/복수 역할·
등록 민감도·이전 거부/at-risk 이력 보존을 검증한다. 실제 기업 정책/IdP 인수나 운영 연결은 아니다.
[v8 원본 점검](docs/infrastructure-results/extra-streamed-v8-20261112.json)은 공개 원본91.6MB/130,767행을
점검해 M7 4파일을 Windows/Linux에서 바이트 동일하게 재현했다. 선언 투영69충돌·파일럿11해당세션은
F1 실측이 아닌 관측 모호성이다. [데이터 적합성](docs/f1-data-readiness.md)을 참고하며 사람 검토를 대체하지 않는다.
[v9 시작 근거](docs/infrastructure-results/extra-soak-start-v9-20261112.json)는 tenant 내 기기/비활성 이력을
새 세션에서도 유지하는 경계와 Linux323개·실제 시계 시험 시작을 기록한다. 세션 간 인증/유출 누적은 아직 후속이다.
사람 독립 검토·새 평가·운영 통합/최종 채택은 완료가 아니며 목표도 미달 상태를 유지한다.

[v10 입력 검토](docs/f1-data-intake.md)는 외부 anchor·관측/정답 분리·필수 보안값 명시·분할/시간/반대 라벨
점검과 빈 사람 검토지를 준비한다. 최종6형식 예시 후 Windows348·Linux348개 각각 통과·소유 컨테이너0이다.
의도적 부적합96세션 분할은 중복/시간 역전/동일 순서 반대 라벨을 검출했고96 pending이다.
실제 출처/독립 검토/목표 달성은 false이며 새 검출기 성능을 측정하지 않았다.
[v10 공개 결과](docs/infrastructure-results/extra-intake-v10-20261112.json)를 따른다. 장시간 시험은 고정 v9 소스만 포함한다.

[v11 사용자 활동](docs/f1-subject-activity.md)은 tenant/analyst/user 범위에서 여러 세션·기기의
실제 실패 로그인/다운로드 증분/fanout을 모으는 **별도 선택형**이다. 모든 기기/자원/행위/총량 승인과
기존 verifier 혼합 거부·일회 집계/시계/네 지점 worker 종료를 확인했다.
최종 Windows387·Linux387개 각각 통과·Linux382파일 전후 동일·소유 컨테이너0이다.
[v11 공개 결과](docs/infrastructure-results/extra-subject-v11-20261112.json)를 따른다. 독립 F1 평가·운영 통합은 아니다.
v9 고정 장시간 시험은 v11 사용자 프로필의 장시간 시험으로 대체하지 않는다.

[v12 전체 원본 분할](docs/infrastructure-results/extra-source-splits-v12-20261112.json)은 전체/이진 모집단의
계열+주체+클라이언트 연결 성분이 각각1개이며, 클라이언트 제외 후에도 정상 전체가 한 성분임을 확인했다.
전체 모집단/선언 그룹 조건의 제약이며 모든 부분집합의 불가능성이나 분류 성능이 아니다.
Windows 집중45·Linux403개 통과·전체 원본 분석 동일·소스384파일 전후 동일·소유 컨테이너0이다.
새 분할 선정/파일럿 변경/검출기 실행0, 사람 검토와 목표는 여전히 미완료다.

11/12 `extra`: 사용자 요청으로 `9c67889`에서 브랜치를 만들고 [F0/F1 기준선·오류 검토 도구](docs/extra-f1-baseline-review.md)를 구현한다.
기존 탐지 규칙·임계값·라벨은 유지하며 새로운 품질 달성이나 사람의 원인 검토 완료로 기록하지 않는다.

11/12 추가 사용자 요청: 남은 작업 뒤 F1 목표를 위한 [후속 계획 F0~F6](docs/f1-improvement-plan.md)을 수립했다.
계획 수립이며 탐지 규칙·임계값·라벨 변경 지시는 아니다. 기존 holdout은 이미 관찰했으므로
개선 후보의 최종 평가는 별도 새 분할로 한다. R10 최종 동결에 그 결과를 연결한다.

11/12 후속: [정확한 잔여 작업](docs/week4-remaining-and-handoff.md)을 먼저 확인한다.
선택형 전체 저장 계약의 승인 원장 복원과 M7 검토지 도구를 추가하며,
M8은 네트워크 범위 판단이다. 사람의 독립 검토·최종 동결 승인으로 자동 전환하지 않는다.
후속 Windows 묶음181개 통과·Ruff/diff check 통과. 새 Docker/AWS/유료 호출0, M7 실제 검토48 pending.
초기 실패·중간26개와 최종181개를 별도로 보존하며 이전 Linux2,749개와 합산하지 않는다.

## 2026-11-11~12 구현·검증 근거

[4주차 잔여 구현·로컬 검증](docs/week4-local-batch.md)을 우선 확인한다.
기준 PR52 `c83b857`, 작업 `feature/chaeheeju-week4-local-batch`다. M5 2인 승인 모의 대응,
M7 동결 후보, 로컬 일괄 실행을 추가했다. 유료 모델·AWS 호출0, 탐지 규칙/임계값 변경0이다.
Linux2,749·관측75·선정37·앱복원13 통과와 최초 CA51개 뒤 실패/정리0을 구분한다.
초기 집중180개 이후 최종 집중57개·Ruff와 DB/백업 변경 경계25개 통과·정리0/0/0을 확인했다.
CA 3회차·DB 실행기 종료4회는 직전17개 부분 실행의 성공 근거와 구분한다.
정상 유지보수 중 소비·폐기 원장은 추가될 수 있으며 모든 기존 행을 보존해야 한다.
그 뒤 DB 교체·재시작의 비교는 준비 후 전체 원장의 정확한 동일성을 요구한다.
공급망 최초60분 제한과 이어 실행한 결과도 분리해 기록한다. 정확한 최종 결과는 연결 문서와
공개 요약을 따른다. 기존 `docs.zip`, `docs/week03.zip`은 사용자 파일이므로 건드리지 않는다.
팀원 독립 인수·라벨 검토·새 모델 비교·최종 동결 승인과 탐지 목표 달성은 완료로 표시하지 않는다.

11/7 후속 묶음: [DB 교체 관리 잠금·실제 프로세스 종료 복구](docs/database-transport-process-recovery.md). 채희주가 시작/종료/purge와 교체기의 공통 잠금, 읽기 전용 상태 조회, 네 종료 지점의 같은 후보·고정 객체 재개를 구성·실행·측정한다. 초기 Linux2413/관측75와 CA27 중단·정리0을 보존했다. 비밀값 없는 실패 진단만 추가한 최종 소스의 집중211/신규31·실제 프로세스 종료4회를 포함한 인수54/54·정리0을 별도로 확인했다. 초기 실패 원인 해결로 확대하지 않으며 최종 전체 회귀·정확한 head/병합 후 CI는 PR을 따른다. DB/물리 HA·백업 통합·장기 checkpoint·독립 인수는 후속이다.

11/7 DB 통신 자동 교체 묶음: [독립 전송 root·서버/client 키·중단 재개](docs/database-transport-rotation.md). 채희주가 별도 보관함·서명 계획·고정 객체 정지/게시·실제 DB TLS 검증을 연결한다. 초기 Linux2383/관측75와 마지막 변조 검사46 중단을 보존했다. 예외 분류·실행기 중복 차단·시험 대기를 보완한 최종 소스의 집중229/신규47·Ruff·실제48/48·정리0을 별도 확인했다. 최종 전체 회귀/정확한 head·병합 후 CI는 PR을 따른다. DB/물리 HA·전체 백업 통합·독립 인수는 후속이다.

11/6 착수·11/7 검증 묶음: [DB 전송 PKI 사전 점검·관측 준비·로컬 일괄 검증](docs/infrastructure-preflight-batch.md). 채희주가 만료/신원/키 권한 선검사와 현재 rule 평가 경계·소스/엔진 고정 실행을 구성한다. 집중236/신규59·고정 Ruff·로컬 Docker2340·관측75/75·authority38/38·소유 자원0을 확인했다. 정확한 clean head/병합 후 CI는 PR 기록을 따른다. DB 전송 인증서 자동 교체·DB/물리 HA·팀원 독립 인수는 후속이다.

11/6 기능 묶음: [CA/JWK 교체·CA 프로세스 이중화·병렬 CI](docs/persistent-authority-rotation.md). 채희주가 인프라18서비스·공유 mTLS DB와 서명된 교체/복구 검증을 연결한다. 로컬 집중190/신규91·고정 Ruff·Docker2281·통합35/35·소유 자원0이며 정확한 head/병합 후 CI는 PR을 따른다. DB·물리 호스트 HA와 팀원 독립 인수는 후속이다.

기준선은 PR38 병합50842b4·병합 후 CI42197450065 성공이다. 이번 묶음은 별도 개인 브랜치에서 진행하고 전체 검사 범위를 유지한 병렬 CI로 검증한다. 앱/탐지·평가 데이터·동료 저장 계약 코드는 유지한다.

11/6 최신 후속은 [CA 최초 발급 준비 경계](docs/ca-bootstrap-readiness.md)다.
PR37 병합 전 CI 성공 뒤 병합99bf0ca의 CI42185498165/attempt1은 CA0검사 기동 timeout으로 실패했다.
소유 자원은0이며 아래 이전 성공 기록과 구분한다. 고정 CA의 기동 전 iat 거부를 로컬 대조했고,
TLS health/UTC Date 뒤 grant를 생성하는 순서와 현재 iat·소비한 jti의 replay 검사를 보강한다.
집중69/신규18·고정 Ruff 통과. 전체 Linux·실제 CA30·후속 PR head/병합 후 결과는
[새 원자료](docs/infrastructure-results/ca-bootstrap-readiness-20261106.json)와 후속 PR을 따른다.
CA/JWK·HA 통합·실제 JSONL 경로·native 즉시 폐기·독립 인수는 미완료다. AWS·유료 LLM 호출 없음.

위 수정 소스의 최종 로컬은 Linux2190/기존 경고2·실제 CA30/30/소유 자원0이다.
test image 소스211개 대조 완료. 정확한 PR head/병합 후 결과는 후속 PR에서 별도 확인한다.

11/6 최신 통합 기준: PR36 전체 저장 계약 코드를 보존했다. 통합 집중319·Linux2172/경고2,
실제 전체 상태 복구24/24·컨테이너/볼륨0 통과. 정확한 head의 관측72/CA29/rekey22와
앱 전체 복구24·병합 후 CI는 PR37 최종 기록을 확인한다. 독립 인수는 미완료다.

## 2026년 11월 6일 지속 실행 leaf rekey 및 관측 실패 진단

- 후속: PR37 첫 head985cd4c의 CI42168186247/attempt1은 CA `Runtime.up`에서0검사 timeout·정리0이다.
  원인 미확정이며 새 rekey는 skipped다. 같은 head의 Ubuntu 재현은 초기39/서버11 통과 뒤19검사에서
  이미 만료된 collector 양성 대조로 중단·정리0. 이를 CI 초기 실패 재현/전체 CA29로 기록하지 않는다.
  후속은 원문을 제외한 controller 실패 종류와 RO/8초 초기 snapshot을 CA/rekey 인수 main에서 수집한다.
  집중205/신규22·최종 Linux2109/경고2 통과. 정확한 새 head의 전체 회귀·인수·병합 결과는 PR37 후속 기록을 확인한다.
- 초기 구현: 집중104/신규37, Linux2087·경고2, Windows2083/skip4·경고3, 실제 rekey22/관측72/CA29 통과·소유 자원0.
  [공개 원자료](docs/infrastructure-results/persistent-key-rotation-20261106.json)의 로컬 커밋 전 입력과 PR의 정확한 head CI를 구분한다.

- [새 선택형 프로필](docs/persistent-key-rotation.md): 기존 교체기를 업무/관측16서비스·9내부망·31볼륨에 연결한다.
  신원39개·서버11개, 별도 고정 JWK11개, 기본9/관측14/동일 키 갱신 프로필을 구분한다.
- 원래 설정에서 journal이 허용한 동일 역할/볼륨의 완전한 cert/key 치환만 재시작 때 허용한다.
  정상 교체 후 재봉인하지 않는다. CA 키/JWK 자동 교체·HA 연결은 이 작업의 범위가 아니다.
- 이전 CA reload group의 실제 `*-tls` 경로 누락을 보완한다. 이전 실제 TLS 관측을 올바른 ack
  경로 검사 증거로 소급하지 않는다. 기존 CA29 인수도 현재 소스로 회귀한다.
- 관측 실패 때 최대20초/고정 호출 timeout·수량/label 제한으로 공개 상태만 수집한다.
  원문 요청/오류/로그/환경/키는 기록하지 않는다. 원래 실패와 기존 경보 판정/90초 기준을 유지한다.
  PR35 첫 시도 경보 지연 원인은 미확정이며 진단 추가를 원인 해결로 표시하지 않는다.
- 앱/탐지·정책·평가 기준은 유지한다. 독립 재현·전체 JSONL 계약의 실제 경로 인수·운영 채택과 남은 CA/HA 통합은 후속이다.

## 2026년 11월 6일 앱 전체 저장 정비 계약

- [전체 저장 계약](docs/app-storage-recovery.md): 기존 SQLite 정비 복원에 audit/cases/outbox
  JSONL을 선택형 `init --full-state`로 연결한다. 관리 anchor에 모드를 고정하며 누락을 빈 로그로
  바꾸거나 기존 SQLite 전용 관리 영역을 자동 승격하지 않는다.
- 정확한 바이트·hash chain·모델·사건 버전/테넌트와 CloudEvent를 대조한다. 합법적인 case/outbox
  commit 간극은 집계해 보존하고 기존 reconciler가 같은 ID로 누락분만 채운다.
- 모든 기존 세션을 회수하고 JSONL·Inbox의 변경 없음을 확인한 뒤 서명된 기동 승인을 발행한다.
  전체 모드는 앱/복원 검사 코드 identity와 JSONL prefix, 실제 세 로그의 설정 경로를 검사한다.
- 중간 종료 뒤 옛 승인 사본은 거부하며 새 격리 사본으로 재시도한다. 기존 단위 51개를 유지하고
  추가 63개·집중 114개, 최종 Mac 전체 2111/기존 skip2를 확인했다. 실제 Docker 전체 복원 24개와
  소유 컨테이너/볼륨 0도 확인했다. Linux 집중114/Ruff도 통과했다. 추가 Linux 전체는 맥 공간
  보호를 위해 중단했으며 성공으로 세지 않는다. 전체 Linux/최종 PR 상태는 별도 확인한다.
- 정지된 기록자 경계의 로컬 정비다. 온라인 백업·외부 exactly-once·전체 관리 저장소 rollback
  방어·운영 RTO/RPO·팀원 독립 인수의 완료로 확대하지 않는다. 기존 인프라 인계의 실제 실행자는 유지한다.

## 2026년 11월 6일 CA leaf 지속 실행 통합 인수

- [CA leaf 인수](docs/ca-runtime-acceptance.md): `scripts.authority_mtls_runtime` 선택형16서비스/9내부망.
  기존9·관측14서비스는 유지하고 별도 CA/제어기·39개 신원/11서버의 발급·갱신을 연결한다.
- root/최초 bootstrap 서명키는 드라이버 RAM, 암호화 issuer와 DB는 CA 전용 볼륨이다.
  제어기는 중앙 신뢰 관리 영역이며 업무 DB/API 키·수집 서명키·CA 서명키/Docker socket은 없다.
  관측 TLS 볼륨에 함께 있는 scrape/notify 토큰은 읽을 수 있으므로 이 한계는 숨기지 않는다.
- 기존 CSR 결합 grant·pin 겹침/교체·NGINX/Go ack/실제 TLS 관측·구 pin 제거를 재사용한다.
  사용한 grant 삭제, 초기화 중단의 무승인 재등록 거부, 고정 관리 설정/공개 CA 입력 불일치 선거부를 추가한다.
- CA 최초 생성 승인 파일을 exec 전에 한 번 소비하고 이후 Badger metadata/marker를 요구한다.
  호스트 up과 CA entrypoint가 각각 검사해 DB 전체 유실을 빈 DB 자동 생성으로 숨기지 않는다.
  기존 DB를 보존 이동한 실패 주입·직접 CA 컨테이너 시작 차단·같은 DB 복원/폐기 보존을 별도 검증한다.
  이 기동 보호를 임의 DB rollback·부분 손상·전원 손실의 백업/복원 승인으로 확대하지 않는다.
- 실제 CA/제어기 재시작·DB 폐기 보존·유효 업무/관측 경로·disabled/pin 회수 보존·정상 재개를 검증한다.
  CA serial 폐기와 즉시 업무 peer pin 회수를 구분한다. 만료 자동 재등록 금지는 unit 회귀 범위다.
- 최종 집중237/신규29·Linux 전체2050/기존 경고2·실제 CA29가 통과했고 소유 컨테이너/볼륨/망은0이다.
  [원자료](docs/infrastructure-results/ca-runtime-acceptance-20261106.json)에 실패9/7·중간26·최종29와
  입력156/image payload·이전 Linux2043의 소스 차이를 구분했다. 정확한 head/병합 후 CI는 PR에 남긴다.
- CA/JWK·개인키 교체 및 CA HA/공유 DB 호스트 복구의 이 프로필 통합, 전체 JSONL 저장 계약·
  새 Go 도구 이미지 공급망 검토·운영 채택·김택희 독립 대조는 남긴다. 탐지/정책·기준선은 유지한다.

## 2026년 11월 6일 C01 관측 지속 실행 통합

- [선택형 관측 프로필](docs/persistent-monitoring.md): `scripts.monitored_mtls_runtime`을 사용한다.
  기본 `continuous_mtls_runtime` 9서비스는 유지하며 관측 프로필은 14서비스·8개 내부망이다.
- reader는 별도 viewer 신원/API 키, exporter는 보안 DB/응답·수집 키 없이 mTLS로 조회한다.
  reader 자체는 기존 앱의 초기화/트랜잭션 구조상 공유 DB RW 마운트가 필요함을 명시한다.
- Prometheus/Alertmanager는 기존 공식 asset digest를 재사용하고 전용 저장소를 쓴다. app ID·
  기반 RootFS prefix·도구 ID/바이너리4·관측 lock/rules/설정 지문을 확인한다. 재시작 불일치는 거부한다.
- `FROM sha256:<local-ID>`는 BuildKit이 외부 repo/tag로 해석해 준비2회가 실패했다. 기반 로컬
  태그의 ID와 결과의 전체 기반 레이어 prefix 대조로 보완했으며 계정 인증이 필요한 문제가 아니다.
- 기존 mTLS48에 실제 새 경보 episode·same fingerprint/startsAt resolved·고정 시각 TSDB·
  AM silence 보존·관측 설정 drift·접수 후 폐기 키 재검증/failed 경보를 추가했다. CI도 --monitoring을 사용한다.
- 최종 로컬 관측71·기본9 호환4·집중129·Linux 전체2021이 통과했다. 실제 시험 소유 자원은 모두 정리했다.
  [원자료](docs/infrastructure-results/persistent-monitoring-20261106.json)에 입력151개와 실패/중간 시도도 남긴다.
- PR33 병합 전 CI 전체 통과 뒤 같은 tree의 병합 후 CI42088599100은 호스트 Ruff가 0.17.3→0.17.4로
  바뀌어 기존 SIM102에서 중단됐다. 호스트 CI도 기존 Docker build/test wheel lock을 해시 검증 설치하고
  프로젝트를 오프라인/no-deps/no-build-isolation 설치·pip check하도록 후속 수정한다. lock·검사 규칙·앱 판정은 유지한다.
- 시험 수신기는 RAM/최대1000개이며 운영 알림 이력 저장소가 아니다. AM native TLS는 허용 SAN에
  관리 API를 신뢰하며 경로별 세분화 RBAC/운영 host attestation은 미구현이다.
- 앱/정책·탐지 기준은 바꾸지 않는다. CA 자동화 통합 인수·전체 JSONL 저장 계약·C01~C03 최종
  조건부 선정·운영 부하/인증·김택희 독립 검토는 미완료다. 전체 3주차 완료로 확대하지 않는다.

## 2026년 11월 6일 3주차 실행 환경 고정

- [release lock/재현/범위](docs/runtime-release-lock.md): `scripts.runtime_release`와 기존 지속 실행기의
  최초 입력 고정·재시작 대조를 확인한다. 앱/정책·탐지 코드는 변경하지 않았다.
- app 전체·scripts Python·runtime build/lock·NGINX 설정·실행 구조가 release 입력이다. 파일 목록의
  추가/삭제도 변경이다. 문서/bytecode는 제외하고 CRLF/LF는 정규화한다.
- 앱 tag가 다른 ID로 바뀌거나 고정 이미지/플랫폼·설치된 공개 프록시 설정이 다르면 시작을 거부한다.
  실제 Compose는 앱/NGINX의 로컬 image ID와 pull_policy=never로 생성한다.
- release 없는 과거 descriptor는 자동 재봉인/승인하지 않는다. 조회/범위 검증된 종료·정리는 허용한다.
  소스 변경은 새 환경 인수 검증 대상이며 기존 데이터의 자동 이관/초기화로 해결하지 않는다.
- release는 신뢰 호스트의 공개 지문이다. 서명/외부 승인/악성 root 방어/바이트 재현 빌드가 아니다.
  시작 전 gate이며 불일치를 발견해 이미 실행 중인 앱을 자동 강제 종료하지 않는다.
- 키·동적 registry는 기존 검증을 따르며 정상 재개에서 새로 발급하지 않는다. C01 통합/CA 연결·
  전체 JSONL 저장 계약·C01~C03 최종 판정과 김택희 독립 대조는 미완료다.
- 로컬 최종 통합48/48·정리0, 입력145·집중91 통과. 공개 `runtime-release-lock-20261106.json`에
  초기 실패21개와 최종 성공을 구분했다. 검증기 상태 snapshot 경쟁 경로를 재현/보완했으며
  앱/정책/TTL은 바꾸지 않았다. 초기 전체 회귀 수치를 보완 후 최종 전체 회귀로 바꾸어 기록하지 않는다.

## 2026년 11월 5일 3주차 I4 앱 정비 복구

- [새 관리 경로/남은 주차 표](docs/app-state-recovery.md), 공개 `app-state-recovery-checkpoint-20261105.json`을 먼저 읽는다.
- 후속 보강: snapshot 전에 다음 세대 차단 pin을 저장하고, anchor와 public 세대 불일치는 백업/복원을 거부한다.
  초기 PR #30의 병합 후 CI는 후속 검증으로 대체하려고 취소했다. 취소를 통과로 기록하지 않는다.
- `scripts.app_state_recovery`는 앱 SQLite journal/inbox와 registry를 백업한다. CA 복구나 구→신 런타임
  호환 시험과 별개다. 기존 앱/정책/탐지 기준은 수정하지 않았고 기존 회수 함수를 재사용한다.
- **모든 쓰기 프로세스를 정지·봉쇄한 정비 경계만 지원**한다. 저수준 CLI는 외부 기록자를 발견하지 않는다.
  checkpoint·anchor·관리 키는 백업 밖에서 보호한다. 전체 제어 저장소 rollback/운영 HA 보장은 없다.
- 복원 전 모든 테넌트/세션 회수, inbox·압축 이력 보존, 현재 public pin/서명·journal prefix 검증을 거쳐 기동한다.
  일반 앱에 관리 키/백업 볼륨을 연결하지 않는다. 사건/감사/outbox JSONL 전체 복구는 후속이다.
- Docker 원본 DB 파괴·복구·실제 API 키 HTTP 403과 TTL 고정 대조·변조/구 백업 거부 18개 검사를 통과했다.
  source 지문·원자료·자원 정리를 남기고 CI에서 현재 이미지로 동일 검사를 실행한다.
- 채희주 구성/도구 실행·측정이며 김택희 상태 의미/독립 검토는 미완료다. 통합 버전 lock·C01~C03
  최종 판정·전체 저장 계약은 남아 있다. 3주차 전체 완료, 탐지 품질 개선, 운영 RPO 0으로 표현하지 않는다.

## 2026년 11월 5일 C03 우선 런타임 패치

- 로컬 최종: Linux1,892 / Windows1,888+4skip, 실제 mTLS41·정리0. 빌드 cache 제외 후 집중106·앱/Lambda23씩 통과.
  로컬 mTLS와 최종 포장은 소스/SQLite 바이너리가 같고 이미지 ID는 다르다. 최종 PR/병합 후 CI가 새 포장의 mTLS를 재검증한다.

- [패치 근거/재현](docs/supply-chain-priority-patches.md): 세 Dockerfile에 digest 기반 Python3.12.16,
  검증한 SQLite3.54.1·pip26.3·외부 wheel hash lock과 HTTP 문법 로컬 backport를 연결했다.
- 3.12 PR160772는 확인 당시 open이다. 원본/patch/결과 지문 불일치는 빌드 중단한다.
  Debian SQLite는 로컬 Deb3.54.1-0secops1이며 공식 DSA가 아니다. Lambda의 활성 /var/lang/lib와 OS RPM을 구분한다.
- 실제 앱/Lambda23개씩, 같은 현재 앱의 구→신 런타임 DB/백업18개를 로컬 검증했다.
  전체 회귀·mTLS·새 이미지 양 검사기/동일 DB 반복의 최종 수치는 공개 JSON과 PR 기록을 따른다.
- 과거 C03 200항목 JSON은 그대로 보존한다. 스캐너 잔여·zipfile 기록 차이·disputed·앱 독립 검토는
  [새 검사 결과](docs/infrastructure-results/c03-patched-scan-20261105.json)에 연결하고 일괄 억제하지 않는다.
- 앱/정책/탐지 코드·평가 기준은 변경하지 않았다. 실행/측정은 채희주, 앱 의미/입력 경계 독립 대조는 김택희다.
  AWS·유료 모델/OS 신뢰 변경 없이 로컬 시험하며 ZIP·기존 kind를 보존한다.

## 2026년 11월 5일 C03 인프라 영향 조건 검토

- 기준 `2e52165`/PR #27, 이름 브랜치 `feature/chaeheeju-c03-impact-review`.
- [영향 검토/실행/담당](docs/supply-chain-impact-review.md), [200항목 대장](docs/supply-chain-impact-register.md),
  공개 `c03-impact-inputs`/`c03-impact-review` JSON을 읽는다. 이전 비교 JSON의 미검토 상태는 당시 기록으로 보존했다.
- 과거 b4660ad 이미지5a64의 Python3.12.15/pip25.0.1·패키지131을 실제 확인했다. 제한된 실물 probe3회는
  바이트 동일하다. P1은 조치/검증 순서17항목(TLS/HTTP/tar3+SQLite14)이며 실제 악용17건이 아니다.
- pip PEP706 fallback/self-check 전제2개를 관측 구성에서만 완화. Debian185의 source mapping/현재 vendor open과
  source-match metadata5·부팅 전제 부재1을 구분한다. libsystemd/libgcc 등 공유 라이브러리는 자동 제외하지 않는다.
- 현재 소스2e52165의 직접 AST 참조와 과거 이미지 참조를 구분한다. 앱의 입력 도달성/김택희 독립 검토,
  새 고정 이미지 재검사·C03 최종 선정은 후속이다. 의존성/탐지/앱 정책과 과거 C03/C04 근거를 수정하지 않는다.
- `scripts.assess_supply_chain`은 pinned 공개 입력의 오프라인 보고서만 만든다. security_gate_passed/production_approved는
  false이며 새 테스트38·C03 집중107 통과. 인프라 검토를 취약점 해결이나 운영 승인으로 바꾸지 않는다.

## 2026년 11월 5일 C03 발견 차이 재분석

- `feature/chaeheeju-c03-findings-review`, 기준 `aitest` PR #26 `01aebf9`.
- [실행·조건·결과](docs/supply-chain-findings-review.md), `scripts.review_supply_chain`,
  [공개 원자료](docs/infrastructure-results/c03-findings-review-20261105.json)를 읽는다.
- 11/3 고정 이미지/DB의 원본 27개를 오프라인 재분석한다. 같은 ID180·직접 alias6·단독14,
  심각도 차이78; 200항목 모두 미검토. 최신 이미지 새 스캔/실제 영향/독립 검토/선정 완료가 아니다.
- 요약 외부 신뢰 SHA-256 필수, 원본 해시/이미지/도구/반복/설치 목록/대조군 재검증 후 새 보고서만 쓴다.
  `--require-reviewed`의 실제 종료2는 미검토 항목 보류이며 테스트 실패나 보안 통과로 바꾸어 기록하지 않는다.
- 앱/정책/탐지/의존성·기존 C03/C04 근거는 변경하지 않는다. 실행·측정은 채희주,
  김택희의 독립 재현·앱 영향 검토와 최신 배포 후보 재검사는 후속이다.

## 2026년 11월 5일 후속 CA·DB·leaf 서비스 복구

- 최종 `c02-665896d5f3f5`: 실제 dockerd 재시작3·서비스10·기존 실행기15/관리 제거2, 옛 JWK132거부.
  신규 단위65, Windows1749+2skip/Linux1751·Ruff 통과. 구현 기준 `c8cdf65`.
  양 실험 이미지114개·전체206/단위 이미지205 대조, 11개 소유 범위 잔여0/기존 Docker·ZIP 보존.
  [공개 원자료](docs/infrastructure-results/c04-service-daemon-windows-20261105.json)에 초기/검토 중단 제외와 지문을 기록했다.

- 실제 서비스 캠페인은 `c8cdf65`/PR #24 앱으로 통과했다. 이후 동료 PR #25 `15366df`를 `7e014b5`로
  보존 결합했다. 이 변경의 앱/상시 mTLS 입력 4개와 당시 실험 지문을 구분하고 최신 전체 회귀를 별도로 기록한다.
  C04 복구 코드는 그대로이며 `15366df` 대비 이번 작업의 앱 변경은 없다. 최신 앱으로 CA 재시작을 다시
  실행했다고 기록하지 않는다. CI의 최신 상시 mTLS 검증도 별도 범위다.

- 기준 PR #23 `9088245`, 이름 브랜치 `feature/chaeheeju-service-daemon-recovery`.
  [서비스 manifest·단계·실행·한계](docs/service-daemon-recovery.md)를 읽는다.
- 동료 PR #24 `e9ae427`의 inbox 보관 이관을 `3d5acb2`로 보존 결합했다. README 양 안내를 유지했고,
  실제 서비스 실험과 최종 회귀는 이 결합 코드로 실행한다. 동료 앱 변경을 이번 작업 기여로 기록하지 않는다.
- `scripts.service_daemon_recovery`의 `seal/recover`: 같은 부모/내부 Engine·고정 서비스/볼륨·현재 관리/실행 역할을
  검사하고 최신 인증 checkpoint·DB 역할/동기 복제 확인 뒤 접속을 연다. 모든 대상은 사전 고정 ID 또는 명시 extras다.
- 기존 authority lease 아래 전용 공개 journal과 동일 actor로 재개한다. pending/busy/사본 충돌·생존 미완료 작업·
  paused·부분 온라인 새 장애·미완료 actor 유실은 거부한다. 자동 kill/lease 삭제/DB 승격·복원·키 재생성은 없다.
- `opening` 이후 새 토큰 소비·폐기를 과거 snapshot으로 되돌리지 않는다. 다음 전체 정지에는 새 service cycle을
  사용하고 역할 epoch와 ID는 유지한다. Docker Desktop 대신 별도 격리 부모의 실제 CA/DB/leaf를 시험한다.
- AWS/유료 LLM/실계정/OS 신뢰 설정·탐지 기준 변경 없이 진행한다. 기존 ZIP/컨테이너를 보존한다.
  물리 HA·운영 SLA·팀원 독립 검토/전체 주간 완료는 별도이며 인프라 실행/측정은 채희주 담당이다.

## 2026년 11월 4일 후속 부모 Docker 데몬 재시작 복구

- 기준 `aitest` PR #20 `3a45b58`, 브랜치 `feature/chaeheeju-parent-daemon-recovery`.
  [구성·seal·복구·검증·한계](docs/parent-docker-recovery.md)를 읽는다.
- `scripts.executor_daemon_recovery`의 정상 상태 `seal-daemon`과 명시적 `recover-daemon`을 추가했다.
  Docker Engine ID/이미지를 먼저 대조하고 양 기록/owner/고정 ID를 검증한다. 모호한 사본·살아 있는
  미완료 actor/worker는 거부하며 Docker Desktop이나 운영 데몬을 재시작하는 명령은 제공하지 않는다.
- 기존 actor의 workers/published/retired 재개는 양 owner와 고정 worker 사양/전환 표식을 먼저 검증해
  멈춘 worker를 시작한다. 완료 복구는 복제/owner/epoch 변경 없이 같은 영수증을 반환한다.
- 실제 검증은 별도 privileged DinD의 자식 dockerd 프로세스를 재시작한다. 같은 supervisor와 데이터 볼륨,
  바뀐 daemon PID/유지된 Engine ID를 대조한다. 완료 후 보존 marker는 합성이며 이전 실제 CA 캠페인을
  새 데몬 검증으로 relabel하지 않는다. 물리 HA·전원 장애·독립 팀원 검토는 별도다.
- 최종 `daemon-final2` project `c02-66f1bc36252c`: 실제 child dockerd 재시작12·검사16 통과.
  같은 actor/op/예약 worker/epoch 유지, 완료 후 합성 profile 보존·부분 시작 재시도·실제 paused 선거부·
  live-restored actor/worker 거부·명시적 정지 후 재개. 최종 epoch3/A활성/양세대2다.
- 신규 단위27, Windows1381+2skip/Linux1383·Ruff 통과. 양 실험 이미지의 앱/스크립트94개 대조,
  결합136입력/단위이미지135개(미포함.gitattributes1)와 Git raw/LF 지문 대조, 6소유범위잔여0을 확인했다.
  구현 기준 `b9c50ad`, [공개 원자료](docs/infrastructure-results/c04-parent-daemon-windows-20261104.json)에
  준비/진단 실패3회·이전버전통과1회 제외 근거와 기존 Docker/ZIP 보존을 기록했다. 앱 변경은 없다.
- 동료 PR #21 `e240c59`를 `e46ec18`로 보존 결합했다. 최신 회귀 Windows1465+2skip/Linux1467·Ruff 통과,
  입력140/단위이미지139·Git raw/LF 대조, 총7소유범위잔여0·기존 Docker/ZIP 보존을 확인했다.
- 실제 데몬 캠페인의 94개 원본 지문은 유지한다. 수집기 앱/스크립트4개는 동료 변경으로 달라졌고 90개는
  동일하다. 핵심 데몬 코드8개도 동일하다. 새 결과는 `integration_validation`의140맵을 쓰며 검증기는 이를
  우선한다. 앱 변경은 e240c59 대비 없고 동료 기여를 이번 작업으로 바꾸어 기록하지 않는다.
  최신 수집기로 실제 데몬/CA 캠페인을 다시 실행했다고 확대하지 않는다.

## 2026년 11월 4일 후속 전환 실행기 컨테이너 유실 복구

- 기준 `aitest` `5d957aa`(PR #18), 작업 브랜치 `feature/chaeheeju-actor-container-recovery`.
  [명시적 복구·재현·한계](docs/actor-container-recovery.md)를 먼저 읽는다.
- `recover-takeover`만 유실한 미완료 actor의 대체를 허용한다. 모든 이전 ID의 Docker 전체 부재,
  양 공개 기록/owner/이미지/예약 객체/원본 지문을 생성 전과 생존 flock 안에서 다시 확인한다.
- `executor-transition-2`의 `actor.predecessors`(최대16)와 checkpoint-bound 복구 표식으로 식별자만 이전한다.
  같은 작업 ID/epoch/계획을 이어가며 완료 시 actor를 다시 만들거나 보안 상태를 되복제하지 않는다.
- `resume-takeover`는 같은 고정 컨테이너 재개다. 일반 사본 불일치/불확실한 식별자 이전은 조사 대상으로
  거부한다. Docker 관리자 신뢰·생존 볼륨/이미지·같은 물리 PC 조건, 팀원 독립 검토 미완료를 유지한다.
- 새 단위/실제 삭제 실험과 기존 CA/DB/관리 상태 회귀 결과는 위 문서·공개 JSON에 기록한다.
  AWS/유료 LLM 호출·탐지 기준 변경·개인 ZIP/기존 Docker 변경 없이 로컬에서 실행한다.
- 동료 상시 mTLS PR #19 `72afde1`을 `9716a08`로 보존 결합했다. Windows 경로 기대값 3곳만
  `Path` 표현으로 호환 수정했고 앱 변경은 없다. 최종 회귀 Windows1354+2skip/Linux1356·Ruff 통과다.
  앞선 결합 실패(경로2·기존 HTTP1)와 변경 없는 HTTP 단독 재통과는 별도로 기록한다.
- 최종 `actor-loss-final1` project `c02-9a91d2c2613e`: 유실26+실행기15+관리제거2=43 통과.
  actor 실제 삭제16/미완료 대체14·관리 종료2·새 콘솔26, 같은 작업/epoch/예약 ID·Root1·이전JWK132거부·
  완료 뒤 새 토큰 소비 보존. 옛 실행 볼륨4/관리18 제거, 최종 실행/관리 epoch3·A활성·양세대2다.
- [공개 원자료](docs/infrastructure-results/c04-actor-container-loss-windows-20261104.json)에 113입력/양이미지93씩·
  외부20, 결합126입력/단위이미지125, 사전/실패/최종 구분과 3소유범위 잔여0·기존 Docker/ZIP 보존을 남겼다.
  tested source는 `97bc043`이며 이후 문서/결과 저장과 Git raw/LF 지문 검증을 구분한다.
  C04 graph 실험을 동료 9서비스 상시 프로필의 자동 갱신 통합 완료로 확대하지 않는다.

## 2026년 11월 4일 후속 호스트 전환 실행기 중단 복구

- PR #15는 `aitest` `ee8067b`에 병합됐고 병합 후 CI도 통과했다. 후속 브랜치는
  `feature/chaeheeju-executor-transition-recovery`. [구성·재개·경계](docs/executor-transition-recovery.md)를 읽는다.
- `scripts.executor_transition`의 고정 PID-1 actor와 생존 볼륨 flock으로 전환을 직렬화한다. 같은 컨테이너
  ID/전체 사양을 확인해 정지한 actor만 명시적으로 다시 시작한다. 실행 중/ID 변경/유실한 미완료 actor는 거부한다.
- 공개 op journal의 peer-first fsync, 양 marker 완료 전 일반 작업 거부, OPID 볼륨/실행기 채택, 같은 부분
  복제 재개와 old/new owner 대조를 사용한다. `complete`는 copy/fence/owner 재설치를 반복하지 않는다.
- actor도 socket을 가진 신뢰 관리자다. physical HA/quorum/자동 선출·불확실한 업무 POST 재전송으로 확대하지
  않는다. OS 신뢰/AWS/유료 LLM/탐지 기준을 바꾸지 않고 기존 컨테이너/ZIP은 보존한다. 실제 결과는 위 문서를 따른다.
- `operator-final1` project `c02-62de02a2e5c6`: operator30+실행기15+관리제거2=47, 별도 사전8+14 통과.
  같은 actor 실제 exit73 16회·관리 프로세스2회·새 콘솔20회, Root1·이전 JWK132거부·완료 뒤 새 토큰 소비 보존.
  실행/관리 epoch3 A활성·양세대2·옛 실행볼륨4/관리18 삭제. 111입력/양이미지91씩·외부20과 정리 증거를 보존했다.
- 신규 단위66, 캠페인 회귀 Windows1152+2skip/Linux1154·Ruff 통과. 초기에 더 좁은 사전2회는 최종 합계에서
  제외했다. 동료의 수집기 PR #16 `a908270`이 별도로 병합돼 결합 후 회귀 결과를 추가하며 해당 기여는 보존한다.
- 동료 변경을 `1f29373`으로 합쳤고 README 충돌은 양쪽 섹션을 보존했다. 결합 전체 회귀 Windows1223+2skip/
  Linux1225·Ruff 통과. 캠페인112개 원본/Git 지문 유지, 추가 수집기5개 포함117개 입력/단위이미지116개 대조.
  미포함1개는 `.gitattributes`. 앱 변경은 `a908270` 대비 없고 CA 캠페인은 이전 기준/이미지 결과로 구분한다.
  총6개 시험 프로젝트 잔여0, 기존 Docker/ZIP 보존. 팀원의 구현을 이번 작업 기여로 바꾸어 기록하지 않는다.
- PR #17 `6765abd`도 `ff8a7ee`로 보존 통합했다. 최종 Windows1275+2skip/Linux1277·Ruff 통과, 의도적 naive
  날짜를 동등하게 구성하는 테스트 호환 수정 후 Windows세션/watchdog52도 통과. noqa불필요 경고로 중단한
  Linux 준비는 pytest 통과로 세지 않는다. 최신120입력/단위이미지119대조(미포함.gitattributes1), 총8범위잔여0.
- 동료가 바꾼 앱 2개 파일(trusted_signals/zero_trust)의 예전 CA 지문은 역사적으로 보존한다. 나머지 110개와
  우리 PKI/actor 코드는 동일하다. 최신 앱으로 CA 캠페인을 재실행했다고 확대하지 않고
  latest_integration_validation의 결합 회귀/새 지문과 구분한다. app 변경은 6765abd 대비 없다. 향후 검증은 최신 120맵을 쓴다.

## 2026년 11월 4일 후속 관리 실행 호스트·기록 이중화

- PR #14 병합 `aitest` `8569385`에서 `feature/chaeheeju-executor-host-redundancy`로 진행한다.
  [구성·신뢰 경계·전환·재현](docs/executor-host-high-availability.md)을 먼저 읽는다.
- `scripts.executor_cluster`의 두 유지보수 실행기는 별도 rootfs와 journal/owner 볼륨을 갖는다.
  `ExecutorManagement`가 기존 관리 backend에 peer-first 전환 기록/프로필과 실행 epoch 검사를 더한다.
  실행 host epoch와 관리 cell epoch를 구분한다. 양 owner 불일치·대기·기록 불일치는 거부한다.
- operator lock 아래 고정 실행기 ID/전체 사양 확인·두 실행기 제거·옛 임시 작업 정리·서비스 ExecIDs 0
  확인 후 새 세대 저장소를 생존 사본으로 채운다. 공개 anchor와 명시한 생존 볼륨이 복구 입력이다.
  Windows JSON은 필요하지 않다. 임시 작업은 시작 전/관리 파일 변경 전에 양 owner를 확인한다.
- 실행기는 부모 Docker socket을 가진 신뢰 관리자다. UID/RO rootfs/cap-drop이 socket의 관리자 권한을
  줄이지 않는다. 온라인 CA/leaf에 socket/vault를 추가하지 않고 Root/백업 키는 network-none 작업만 읽는다.
- 같은 부모 Docker/물리 PC, 두 노드 수동 전환이며 quorum·물리 HA·자동 선출이 아니다. operator 전환
  자체 중단/부분 실패는 lock·봉쇄 상태에서 수동 조사한다. `opening` 이후 보안 상태를 초기화하지 않는다.
- `.env.local`을 읽지 않고 기존 `docs.zip`, `docs/week03.zip`, `pod-forensics-20261025-control-plane`을
  보존한다. AWS·유료 LLM 호출 없이 시험 프로젝트 자원만 정리한다. 역할/전체 주간 완료는 별도다.
- 최종 `executor-final2`, project `c02-e6790d753406`: 새 CA 1회·실행기15+관리 저장소 제거2, 별도 사전8,
  실제 본 종료2/사전1, Root/issuer/JWK epoch1·옛 JWK132거부. 관리/실행 epoch3, 양 세대2, 옛 실행 볼륨4/
  관리 볼륨18 삭제. 준비된 동일 키 후보와 접속 재개 후 새 JWT 소비가 양 호스트 손실/재개 후 보존됐다.
- 신규 단위68, Windows1087+1skip/Linux1088·Ruff 통과. 입력109개·양 이미지 안89개씩/외부20개·새 단위
  지문을 공개 결과에 남겼다. 최종/예비/단위7개 범위 잔여0, 기존 컨테이너/ZIP 보존. BuildKit 빌드 참조
  실패·unlabelled host drain 보완을 위한 준비 중단·이전 좁은 사전 실험은 최종 합계에서 제외했다.

## 2026년 11월 4일 후속 관리 전환 중단 복구

- PR #13 병합 `aitest` `1531625`에서 `feature/chaeheeju-control-transition-recovery`로 진행한다.
  [전환 단계·재개·검증·한계](docs/control-transition-recovery.md)를 먼저 확인한다.
- `scripts.control_transition`은 기존 호스트 lease 아래 공개 `management-transition.json`을 원본으로 쓴다.
  `scripts.control_plane_ha resume`은 같은 전환을 이어간다. 미완료 기록은 일반 host control 작업을 막는다.
- `idle`/`prepared` 후보 검증·busy 거부는 유지한다. 작업 전 의도/사양을 기록하고 부분 사본 일치와
  Docker 표식·이미지·ID·명령·환경·권한·마운트·네트워크를 확인한다. ID 기록 후 바뀐 객체는 대체하지 않는다.
- `opening` 이후에는 copy/initialize/reconcile/writer-stop을 반복하지 않는다. 접속을 이미 열었다면
  최신 pending/토큰 소비를 남긴 채 완료 기록만 확정한다. 업무 POST의 일반 재전송 기능이 아니다.
- `scripts.test_control_transition`은 별도 호스트 프로세스의 실제 강제 종료와 다음 프로세스의 lease 획득을
  검사한다. 새 실행기 import 누락으로 중단한 준비는 최종 통과 합계에 넣지 않는다. 실제 결과는 위 문서를 따른다.
- 로컬 journal/신뢰된 실행기·동일 부모 Docker가 남아야 한다. 전원/디스크/호스트 전체 손실·quorum·자동
  선출·임의 authority 중간 단계·구 이미지 인플레이스 이전·팀원 독립 검토·전체 주간 완료로 확대하지 않는다.
- 최종 새 클러스터 1회·35개(기존 관리20+추가15), 실제 process death9회, 신규 단위58개,
  Windows1019+1skip/Linux1020·Ruff 통과. 동일 생성 컨테이너 ID 채택과 접속 재개 후 새 JWT 소비 보존을 확인했다.
  5개 프로젝트/단위 이미지 태그 잔여0, 기존 Docker/ZIP 보존. 예비 import·60초 상한·정지한 발행기에서의
  CSR 준비·CA 재기동 전 JWT의 올바른401 거부를 최종 합계에서 제외한다. CSR은 정지 전 준비하고 JWT는
  접속 재개 후 network-none/RO vault 작업에서 만든다. 운영 전환 코드는 예비 실행기 수정 중 변경하지 않았다.

## 2026년 11월 4일 후속 관리 영역 이중화

- `aitest` `635638a`에서 `feature/chaeheeju-control-plane-ha`로 진행한다.
  [관리 구성·전환·재현·한계](docs/control-plane-high-availability.md)를 먼저 읽는다.
- `scripts.control_plane_ha.Management`가 management 프로필의 backend다. 기존 프로필은 기존 동작이다.
  cell별 9개 볼륨, 대기 우선 동기 파일 쓰기/삭제, 두 RO 역할 기록·관리 epoch, 단일 활성 leaf와 RO
  대기를 사용한다. 조정기 Linux 사본이 원본이며 Windows JSON은 복구 가능한 캐시다.
- 승격은 host lease, 완료된 관리/leaf 작업, `idle`/`prepared`, CA/vault/계획 일치와 PG system ID를
  요구한다. 기존 프로세스/관문과 CA writer를 정지한 뒤 새 세대 볼륨으로 이전한다. busy 삭제·과거
  프로필 재사용·불확실한 POST 재전송으로 복구하지 않는다. 전환 도중 실패의 자동 복구는 후속이다.
- `scripts.test_control_plane_ha`는 실제 준비된 root 계획 중 a→b, 완료 뒤 b→새 a와 옛 볼륨 삭제를
  검증한다. root/backup 키는 network-none 작업만 읽고 온라인 제어기에 socket/vault를 주지 않는다.
- 두 cell은 같은 부모 Docker/PC다. CA 서비스 호스트 두 DinD와 구분한다. 신뢰된 호스트 실행기/
  파일 lease, workload 인증서 볼륨과 앱 SQLite는 공통/별도 경계다. 물리 HA·quorum·운영 SLA·독립
  팀원 검토·전체 주간 계획 완료로 확대하지 않는다. 실제 결과는 위 문서와 공개 증거를 따른다.
- 최종 새 클러스터 1회·20개, 신규 단위 45개, Windows 961+1 skip/Linux 962와 Ruff 통과.
  역할/CA 설정 파일 유실 후 같은 키 계획 재개, cell 전환 2회·이전 볼륨 18개 삭제·미만료 소비/폐기
  거부·캐시 삭제 후 백업 인증을 검증했다. 4개 프로젝트/전체 회귀 이미지 태그 잔여 0, 기존 Docker/ZIP 보존.
  TLS health의 봉쇄 관문 의존과 quiesce의 Windows 캐시 의존 예비 실패를 최종 합계에서 제외한다.

## 2026년 11월 4일 CA DB·서비스 호스트 복구

- `aitest` `b6e35be`에서 `feature/chaeheeju-db-host-recovery`로 진행한다.
  [구현·복원 절차·검증·한계](docs/ca-db-host-recovery.md)를 먼저 확인한다.
- `scripts.test_ca_host_recovery`는 별도 Docker 데몬/저장소의 CA+DB 두 노드와 remote_apply 복제를
  구성한다. `scripts.ca_host_recovery`는 고정 소유 객체의 정지를 증명한 뒤에만 승격하며, 재가입은 새 저장소에
  reseed한다. 자동 네트워크 분할 선출이 아니고 실제 PC/관리 영역은 단일 장애점이다.
- 독립 관문 journal은 전달 전 intent를 기록한다. 암호화 백업의 authority/DB incarnation 및 최신 보안
  checkpoint와의 일치를 검사하고, 이전 dump 복원 후 토큰 소비·폐기를 재적용한 뒤 접속을 연다.
  관리 영역까지의 재해 복구·전역 antirollback·앱 SQLite 복구로 확대하지 않는다.
- 키 교체의 기존 모든 노드 증명 장벽은 `service_hosts` 프로필에서 새 backend를 사용한다. 기본 프로필과
  앱/탐지/개선 전 평가 기준선은 보존한다. 실행 결과·실패·정리는 위 문서와 공개 증거를 따른다.
- DinD 호스트만 신뢰된 privileged 시험 서버다. 일반 CA/leaf에 부모 Docker socket·root/JWK 보관함을
  연결하지 않는다. 백업/오류 후 leaf pause 유지와 수동 복구 조건을 문서에서 확인한다.
- 최종 새 클러스터 1회·33개 검사, Windows/Linux 각 917개(신규 47개), Ruff 통과. daemon 5개를
  관측하고 seal 후 cold restore 329.891초, 유효 토큰/폐기 인증서 거부와 새 nonce 양 CA 발급을 확인했다.
  [공개 근거](docs/infrastructure-results/c04-ca-db-recovery-windows-20261104.json)에 예비 실패도 구분한다.
  내부 CA/DB는 `unless-stopped`, 봉쇄 대상 외부 host는 검증된 `no` 정책이다. 전용 container/volume/
  network/image tag 0, 기존 Docker/ZIP 보존. Docker Desktop/물리 PC/관리 영역 전체 HA는 미완료다.

## 2026년 11월 3일 후속 CA 프로세스 고가용성

- PR #10 병합 `aitest` `0c32273`에서 `feature/chaeheeju-ca-high-availability`로 진행한다.
  [구현·재현·한계](docs/ca-high-availability.md)와 [계약](infra/mtls/ca-ha-contract.json)을 확인한다.
- CA 두 프로세스는 같은 온라인 issuer 설정을 읽기 전용으로 사용하고 단일 PostgreSQL의 발급/토큰/폐기
  상태를 공유한다. DB 전용 내부망·독립 transport PKI·노드별 mTLS·verify-full·최소 권한 역할을 적용한다.
  앱 SQLite나 기존 Badger 운영 DB를 마이그레이션하지 않는다. DB/호스트 이중화는 별도다.
- `ca-endpoints.json`이 있는 관리 프로필만 연결 장애 시 승인 CA로 전환한다. TLS 인증 오류·전송한 POST·
  401/403은 다른 노드로 재시도하지 않는다. 같은 일회용 토큰의 동시 소비에는 SERIALIZABLE 충돌 거부를
  사용한다. 전체 CA/ACME/admin API의 분산 트랜잭션 보장이나 성공 exactly-once로 확대하지 않는다.
- 키 교체는 단일 조정기·leaf pause/ack를 유지하고 모든 pinned CA의 새 issuer TLS·개별 새 JWK 발급·각
  구 JWK의 개별 거부를 확인한다. 순차 재시작이어도 발급 유지보수 중단이 가능하다. 무중단 SLA는 아니다.
- 실제 검사 수·실패·이미지/소스 지문·정리는 위 검증 문서를 따른다. 팀원 독립 검토·운영 배포·HSM·DB
  transport PKI 자동 수명 관리는 후속이다. 아래 HA 미완료 표기는 이전 프로필의 당시 범위로 보존한다.

- 최종 HA 90초 canary/여유 60초 프로필로 새 CA/DB 2회 × 222 = 444개, Windows/Linux 각각 전체
  870건과 Ruff 통과. 새 단위 사례 52개, 회당 48개 활성 신원/14개 TLS 서버/3 authority epoch,
  양 CA의 구 JWK 새 요청 총 792개 거부를 확인했다. 중단 배포 48개/46개 각각 동일 후보를 복구했다.
  [공개 증거](docs/infrastructure-results/c04-ca-ha-windows-20261103.json)에 초기 bootstrap 파일 assertion,
  전체 batch 가정 assertion, 30초 canary의 실제 만료 실패를 최종 합계와 분리했다. 소진 파일 삭제를
  배포 성공과 분리하고 전체 키 보존/실제 중단 후보 재사용/전체 이행을 따로 검증한다. 30초 HA SLA
  통과로 표현하지 않는다. 5개 프로젝트 자원/전용 태그와 단위 이미지 4개의 잔여 0, 기존 Docker/ZIP 보존.

## 2026년 11월 3일 후속 CA·발급 JWK 키 자동 교체

- PR #9 병합 `aitest` `4d74f06`에서 `feature/chaeheeju-authority-key-rotation`으로 진행한다.
  [구현·운영 경계](docs/authority-key-rotation.md)와 [계약](infra/mtls/authority-rotation-contract.json)을 확인한다.
- 신뢰된 호스트 조정기와 `network=none` custodian을 분리한다. 새 프로필은 루트/중간/전체 JWK를 인증
  암호화한 Linux bundle에 보관한다. 이전 RAM 전용 루트 프로필은 그대로다. 보관함 암호도 같은 볼륨에
  있으므로 HSM/물리적 air gap/독립 secret manager 보호가 아니다. 온라인 CA·leaf에는 보관함/socket을 주지 않는다.
- 이전 루트 서명 계획·단일 writer·leaf pause/ack·겹침 신뢰→CA/JWK 등록 교체→모든 활성 leaf의 새 issuer/
  epoch·TLS 확인→구 신뢰 제거→구 JWK 모두 거부→구 비밀 파일 제거 순서다. 별도 committing 단계로 재개한다.
- CA/JWK별 타이머를 독립 검증한다. 부트스트랩 52개와 서버 JWK 14개를 모두 교체하되 이름·용도·정책을
  보존한다. issuer-only 교체는 훔친 구 중간 CA 체인의 active 폐기가 아니다. 정상 교체/사고 복구도 구분한다.
- 앱·탐지·정책·개선 전 품질은 변경하지 않는다. 팀원 독립 검토·운영 배포/HA·저장소 anti-rollback·물리 소거는 후속이다.
- 최종 새 CA/상태 2회 × 197 = 394개 통합 assertion, Windows/Linux 각각 전체 818건과 Ruff를 통과했다.
  회당 48개 신원/14개 TLS 서버, root+issuer+JWK→issuer+JWK→JWK 3 epoch과 각 66개 구 JWK 요청 거부를 확인했다.
  별도 3개 신원 루트1→루트2 반복의 구 root TLS 거부/현재 root 200은 보조 검사 3건으로 합계에서 분리한다.
  [공개 증거](docs/infrastructure-results/c04-authority-rotation-windows-20261103.json)에 소스/이미지 지문·실패·정리를 보존했다.
  초기 policy 함수/상속 dict 이름 충돌과 smoke Host 설정을 고친 후 전체 반복을 검증했다. 5개 프로젝트/단위 이미지
  잔여 0이며 기존 Docker 작업·사용자 ZIP은 보존했다. 아래 CA/JWK 미구현 표기는 이전 프로필의 당시 범위다.

## 2026년 11월 3일 후속 C04 서비스 개인키 자동 교체

- PR #8 병합 `aitest` `e8e7867`에서 `feature/chaeheeju-private-key-rotation`으로 진행한다.
  [구현·재현·한계](docs/private-key-rotation.md)와 [계약](infra/mtls/private-key-rotation-contract.json)을 확인한다.
- 명시적 `key_rotation` 모드만 leaf 키를 교체한다. 기본 동일 키 갱신은 유지한다. 관리 mTLS 키도 교체하지만
  CA 루트/issuer와 별도 등록 JWK 서명키는 제외하며, JWK 키는 관리 mTLS 키와 독립적으로 생성한다.
- immutable 세대별 파일→겹침 pin→profile/config 원자 전환→reload ack/실제 TLS→구 pin 제거→구 client
  serial 자체 폐기→유예 후 구 파일 unlink 순서다. journal에 private PEM을 저장하지 않는다.
- 단일 publisher/운영자 pause/ack 규칙과 만료·retired·disabled 거부를 유지한다. unlink는 물리 소거나
  메모리/백업 키 제거가 아니다. HSM/HA/운영 배포/독립 재현과 별도로 기록한다. 아래 C04 결과는 이전 기준선이다.
- 최종 2회 × 174 = 348개 통합 assertion, Windows/Linux 각각 전체 766건과 Ruff를 통과했다.
  회당 48개 신원·14개 서버, 3회 이상 새 키 전환·실제 activated 단계 중단 복구·CA 장애 후 복구를 확인했다.
  등록 JWK 교차 발급 401은 별도 검사 1건이다. [공개 증거](docs/infrastructure-results/c04-key-rotation-windows-20261103.json)를 따른다.
  초기 null 세대 비교 TypeError·3개 신원 빠른 시험은 최종 합계에서 제외했다. 3개 프로젝트/단위 이미지 잔여 0,
  기존 Docker 작업과 사용자 ZIP은 보존했다. 앱·탐지·정책 소스는 변경하지 않았다.

## 2026년 11월 3일 후속 C04 인증서 수명 자동화

- PR #7 병합 `aitest` `1775491`에서 `feature/chaeheeju-certificate-automation`로 진행합니다.
  [범위/재현/한계](docs/certificate-automation.md), [선정 기록](docs/technology-decisions/C04-certificate-lifecycle.md),
  [계약](infra/mtls/certificate-lifecycle-contract.json)을 확인합니다.
- step-ca 0.30.2/CLI 0.31.0을 고정 출처/SHA-256으로 확인합니다. 루트 개인키는 드라이버 RAM에만,
  온라인 중간 CA는 암호화 키·부팅 암호·DB를 전용 Linux 볼륨에 둡니다. 제어기는 CA 키/Socket이 없습니다.
- clientAuth는 mTLS로 갱신합니다. serverAuth 전용 `/renew`는 실제 버전에서 거부되어 서버별
  `renew-<서버>`에 연결된 제어면 전용 JWK 서명키로 제한된 재발급을 사용합니다. 일반 CA client 인증서에
  관리 권한을 주는 범용 X5C provisioner는 설치하지 않습니다. 서버 EKU를 넓히거나 업무 역할을 주지 않습니다.
- 단일 publisher/journal, 새 pin 겹침→인증서 교체→reload ack/실제 TLS 관측→구 pin 제거를 연결합니다.
  운영자 정책 변경은 pause/ack를 지켜야 하며 분산 writer·anti-rollback을 구현한 것은 아닙니다.
- 최초 grant는 CSR에 묶어 사용 후 지우고, 만료한 관리 신원의 자동 재등록을 하지 않습니다.
  CA 폐기와 즉시 peer pin 제거, 서버 leaf 폐기와 별도 발급 권한 폐기를 구분합니다.
- 실제 반복 결과는 위 문서/공개 증거를 따릅니다. 앱 탐지/정책/개선 전 품질은 보존하고,
  Codex 도구 실행을 팀원 수동 실행·독립 검토로 소급하지 않습니다. 운영 CA/HA/HSM/독립 재현은 후속입니다.
- 최종: 2회 × 153 = 306개 통합 검사, Windows/Linux 전체 각각 739건과 Ruff 통과.
  회당 50개 활성 신원의 발급/타이머 갱신과 서버 14개의 새 TLS 지문을 확인했습니다.
  [공개 증거](docs/infrastructure-results/c04-certificates-windows-20261103.json)에 초기/중단 시도를 분리했습니다.
  시험 8개 프로젝트 자원/전용 이미지 잔여는 0이며 시작 때 실행 중인 다른 Docker 작업은 보존했습니다.

## 2026년 11월 3일 후속 선택 경로 전체 mTLS

- PR #6 병합 `aitest` `f7fc48d`에서 `feature/chaeheeju-mtls-all-hops`로 진행합니다.
  [전체 경로/한계](docs/all-hops-mtls.md)와 [계약](infra/mtls/all-hops-contract.json)을 확인합니다.
- NGINX front/auth/resource, bridge/gateway/native core/consume, 실제 수집기 입력과 선택한
  Prometheus/exporter/Alertmanager/receiver, 관리 조회에 mTLS를 적용합니다. worker는 network=none입니다.
- `python -m scripts.test_all_hops_mtls --repeats 3`은 기존 I2 30·새 경로 43·C02 42개를 반복합니다.
  파일 IPC·호스트 Docker exec 파이프·공개 artifact 다운로드와 서비스 네트워크를 구분합니다.
- native core는 앱 소스를 바꾸지 않고 실제 TLS peer를 Uvicorn h11 guard에 연결합니다.
  peer/header 위조·평문·pin 취소·grant 소비 상태와 실제 firing/resolved의 동일 episode를 확인합니다.
- Python endpoint의 leaf pin, NGINX/Go의 CA/이름/SAN 검증을 구분합니다. 운영 CA/CRL/OCSP/HA/
  정책 anti-rollback·진행 중 업무 취소·독립 재현은 미완료입니다. 과거 HTTP 비교 기록은 보존합니다.
- 실제 실행·측정은 Codex 도구 보조이며 팀원 수동 실행/독립 검토로 소급하지 않습니다. 탐지 기준선은 유지합니다.
- 최종 검증: Windows/Linux Docker 각각 전체 687건과 Ruff 통과. mTLS 그래프 3회 345개 +
  실제 수집기 `_post`/지속 관찰 연결 후 최종 1회 115개, 합계 460개 반복 검사를 통과했습니다.
  앞선 3회와 최종 수집기 구현 1회는 [공개 증거](docs/infrastructure-results/all-hops-mtls-windows-20261103.json)의
  입력 지문/이미지로 구분합니다. 시험 자원·전용 이미지 정리 후 Docker Desktop은 종료했습니다.

## 2026년 11월 3일 후속 I2 서비스 mTLS

- PR #5 병합 `aitest` `87f24f6`에서 `feature/chaeheeju-i2-mtls`로 진행합니다.
  [I2 경계/검증/한계](docs/i2-service-mtls.md), [계약](infra/mtls/contract.json)을 확인합니다.
- C02의 기본 HTTP 실행은 유지하고 별도 실행기가 PEP bridge→인가 gateway에 mTLS를 연결합니다.
  chain/시간/EKU/서버 이름/leaf pin과 서비스별 경로를 검사하며 기존 앱 API 키/역할도 유지합니다.
- `python -m scripts.test_mtls_infrastructure --repeats 3`은 Linux 전용 임시 키 볼륨과 내부망만 씁니다.
  개인키는 호스트 파일이나 OS trust store에 쓰지 않습니다. runtime 경로는 기존 C02 실행기 아래입니다.
- client/server 인증서 교체·pin 폐기·잘못된 설정과 기존 C02의 위험 신호→회수→다음 문서 거부를 검증합니다.
  실제 결과는 I2 문서/공개 원자료를 따릅니다. 앱 탐지·정책·개선 전 평가 기준선은 바꾸지 않습니다.
- gateway 뒤와 다른 hop은 HTTP입니다. 운영 배포/IdP/CA 자동화/CRL·OCSP/HA/독립 검토는 후속입니다.
  C04 step-ca는 자동 발급 요구가 확인될 때 비교하며 이번 도입/비교 완료로 기록하지 않습니다.

I2 추가 결과: 3회 × 72개 = 216개 통합 검사, Windows/Linux Docker 전체 655건을 통과했습니다.
[I2 공개 증거](docs/infrastructure-results/i2-mtls-windows-20261103.json)에 TLSv1.3 관측과 초기 시도를
분리했습니다. 폐기 정책의 과거 버전 복원을 막는 anti-rollback은 미구현이며 다른 hop·운영 배포는 후속입니다.

## 2026년 11월 3일 후속 C02 HTTP 집행

- PR #4 병합 `aitest` `9f61f35`에서 `feature/chaeheeju-c02-pep`로 진행합니다.
- [C02 기록](docs/technology-decisions/C02-http-pep.md)과 [계약](infra/pep/contract.json),
  [고정 이미지](infra/pep/tools.lock.json)를 확인합니다. 기존 앱/정책/탐지 소스는 바꾸지 않습니다.
- `python -m scripts.compare_pep --repeats 3`은 두 프록시를 같은 core API와 별도 자원 서버에 연결합니다.
  core grant를 소비한 뒤 3초짜리 일회용 handoff로 문서를 전달하며, 장애에 재허용/환불하지 않습니다.
- 위험 신호 내구 접수·기존 networkless worker 처리·관련 세션 제한·다음 HTTP 거부를 연결합니다.
  직접 접근·헤더 위조·동시 소비·테넌트/운영자·회수·만료·키 폐기·장애/재시작도 대조합니다.
- 인가 시점은 core SQLite 트랜잭션입니다. 이미 허용된 in-flight 요청을 회수로 취소하거나 업무와
  원자적으로 커밋하는 구현은 아닙니다. 운영 TLS/IdP/HA/고부하·영속 업무 감사·독립 재현은 후속입니다.
- 최종 반복·검증·초기 실패와 한계는 C02 문서/원자료를 따릅니다. 아래 기록은 당시 상태로 보존합니다.
- 최종 각 3회·42개씩 총 252개 검사와 Windows/Linux Docker 전체 630건을 통과했습니다.
  [공개 실측](docs/infrastructure-results/c02-windows-20261103.json)에 준비 실패를 분리했고, 소스 지문도 재검사했습니다.
  로컬 통합 NGINX를 잠정 제안하되 관측 지연은 Envoy가 낮았음을 보존합니다. 운영 채택·독립 검토는 후속입니다.

## 2026년 11월 3일 후속 C01 관측·경보

- PR #3까지 병합한 `aitest` `719f069`에서 `feature/chaeheeju-c01-observability`로 작업합니다.
- [C01 기록](docs/technology-decisions/C01-observability.md), [계약](infra/observability/contract.json),
  [공통 경보](infra/observability/alerts.yaml), [고정 도구](infra/observability/tools.lock.json)를 확인합니다.
- 새 exporter는 기존 viewer inbox API의 aggregate만 GET하며 DB/정책에 쓰지 않습니다.
  수집 실패에는 오래된 큐 수치를 제공하지 않고 별도 failure gauge를 냅니다.
- `python -m scripts.compare_observability --repeats 3`은 내부망에서 두 구성을 실제 시험하며
  서명 개인키는 메모리, 임시 토큰은 전용 Linux 볼륨에만 둡니다. 호스트 공개 포트·Docker socket 마운트가 없습니다.
- 초기 연결·query lookback 설정 실패도 보존합니다. 성공 반복과 독립 재현·운영 채택을 구분합니다.
  실제 IdP/EDR·운영 TLS/인가·HA·고부하/장기 보존·알림 무손실 검증은 미완료입니다.
- 기존 앱 소스·탐지 기준선은 유지하며 AWS/유료 모델을 호출하지 않습니다. 아래 기록은 당시 상태로 보존합니다.
- 최종 후보당 3회·18개씩 총 108개 기록 검사를 통과했습니다. 신규 보안/정합성 회귀 25건을 포함한 전체
  Windows/Linux Docker 591건이 각각 통과했습니다. [실측 요약](docs/infrastructure-results/c01-windows-20261103.json)에
  같은 대상·fingerprint·startsAt·구간 인덱스로 검증한 알림, 자원·초기 실패와 한계를 남깁니다.
  후속 로컬 통합 기준선은 Prometheus+Alertmanager를 잠정 제안하며 운영 채택은 보류합니다.

## 2026년 11월 3일 후속 C03·M6 계약

- PR #2는 `aitest`의 `b4660ad`에 병합했습니다. 현재 후속 작업은
  `feature/chaeheeju-c03-supply-chain`에서 진행하며 별도 PR로 기록합니다.
- [C03 로컬 비교](docs/technology-decisions/C03-supply-chain.md): 공식 고정 바이너리의 서명/지문 검증,
  같은 이미지 tar에서 Syft+Grype와 Trivy의 오프라인 반복·설치 metadata 대조·작은 advisory 대조군입니다.
  실제 결과와 보관 위치·한계를 확인하고 스캐너 채택·독립 재현 완료로 오해하지 않습니다.
- [M6/C10 평가 계약](docs/m6-evaluation-contract.md)과 [JSON](infra/model-evaluation-contract.json)은
  후보·질문·안전·비용 조건 초안입니다. 유료 호출·키 등록·새 공급자 실행기·제품 연결은 하지 않았습니다.
  생성형 설명과 Jev/Laya 분류를 분리하고 AI 단독 권한 허용/복구를 금지합니다.
- 이번 변경은 탐지 규칙·임계값·정규화·정책 및 개선 전 품질 결과를 바꾸지 않습니다.
  AWS/실계정 변경 없이 로컬에서 시험합니다. 아래 과거 기록은 당시 상태로 보존합니다.
- C03 도구의 변조/경로·체크섬·패키지 버전·집계 검증 21건을 추가해 전체 566건을
  Windows와 Linux Docker에서 통과했습니다. 각각 기존 경고 3개/2개이며 탐지 품질 목표 통과를 뜻하지 않습니다.

## 2026년 11월 3일 희주 담당 인프라 작업

- 원격 `aitest`의 PR #1 병합 커밋 `82285c6`를 받아 `feature/chaeheeju-m3-infra-validation`에서 작업합니다.
- 사용자 요청에 따라 희주 작업은 `feature/chaeheeju-<작업명>` 브랜치와 `aitest` 대상 PR로 남깁니다.
  직접 통합 브랜치에 푸시하지 않고 [작업 절차](docs/contribution-workflow.md)를 따릅니다.
- 기존 M3 구현을 재사용하며 탐지 규칙·임계값·개선 전 평가 자료는 변경하지 않습니다.
- 시험 개인키는 메모리에서만 사용하고 공개 등록 JSON만 마운트합니다. Windows에서 POSIX 모드 비트를
  그대로 요구하던 시험을 플랫폼 계약에 맞췄습니다. worker는 공유 SQLite만 필요해 네트워크를 제거했습니다.
- `python -m scripts.measure_signal_infrastructure --repeats 3`으로 격리 반복·자원·지연을 기록합니다.
  시연 부하·소표본 결과이며 서비스 SLA·실제 IdP/EDR·mTLS·독립 PEP·RTO/RPO 완료로 사용하지 않습니다.
- 실행·표본·실제 결과·한계는 [인프라 측정 기록](docs/m3-infrastructure-measurement.md)을 우선합니다.
  아래 11월 2일과 11월 1일 기록은 당시 기준선으로 보존합니다.

## 2026년 11월 2일 로컬 개발 업데이트

- 작업 브랜치: `feature/m3-durable-signals`, 시작 커밋: `71cbfc0`. M3 구현·검증 결과이며
  아래 11월 1일 기준선 기록을 보존합니다. 버전 번호는 아직 `0.17.0`입니다.
- M3/I1: `zt-observation-1` identity/device 관찰, 종류·주체·키 권한 분리,
  SQLite 내구 접수, 별도 `scripts.signal_worker`, 관련 세션 제한·회수와 영수증·지표를 추가했습니다.
- 정책 fanout과 관찰 표식을 한 journal 트랜잭션으로 반영합니다. 완료 기록 유실은
  재전달 또는 마지막 시도의 읽기 전용 대조로 복구하며 정책 효과를 중복 적용하지 않습니다.
- 관찰 전용 source는 기존 full-session 서명 경로를 사용할 수 없고, 같은 테넌트에서
  다른 source가 같은 공개키를 공유하면 등록 전체를 실패 폐쇄합니다. 기존 키 등록을 옮길 때 주의합니다.
- 정상 관찰·동기 재평가·새 세션으로 위험 제한을 자동 해제하지 않습니다.
  검토된 해제·복구 프로토콜, 실제 IdP/EDR, GuardDuty, 독립 업무 PEP는 후속 작업입니다.
- 새 API와 worker도 local/test 전용입니다. 기존 Sigma 규칙·임계값·개선 전 평가 원자료는 유지했습니다.
- 계약·시험 위치·M6/M7 준비 사항은 [M3 명세](docs/m3-durable-signals.md)를 따릅니다.
  [검증 결과](docs/m3-validation-results.md): Python 3.12·3.14 각각 전체 518건 통과,
  Ruff·Compose 구성 검사 통과. 이후 Colima의 Linux Docker에서 앱·worker 통합 검사
  11개와 전체 524건을 검증했습니다. 실제 컨테이너 재시작·회수 후 HTTP 403과
  무관 세션 HTTP 200, 공유 SQLite·UID 10001을 확인했습니다.
  [Docker 검증 기록](docs/m3-docker-validation.md)의 환경·재현 명령·원자료를 확인합니다.

이 문서는 다른 AI 또는 개발자가 `zero-trust-llm-secops` 저장소를 처음 열었을 때 현재 상태를 오해하지 않고 안전하게 작업을 이어가기 위한 기준 문서다.

갱신일: 2026년 11월 1일. 프로젝트의 핵심은 **제로트러스트 오퍼레이션**이다. 아래 기능·평가 기준 커밋은 `68519f5`이며 실제 최신 HEAD는 `git log -1`로 확인한다. 현재는 개선 전 탐지 기준선을 보존하는 단계이므로 점수가 낮더라도 규칙·임계값·정규화·정책 집행을 임의로 개선하지 않는다.

## 1. 한눈에 보는 프로젝트

| 항목 | 내용 |
|---|---|
| 프로젝트명 | LLM 기반 지능형 제로 트러스트 보안 오퍼레이션 및 자동화 프레임워크 구축 |
| 팀명 | 천안아산역 |
| 팀원 | 채희주, 김택희 |
| 저장소 | `https://github.com/cheonan-asan-sta/zero-trust-llm-secops` |
| 패키지 버전 | `0.17.0` |
| 언어·프레임워크 | Python 3.11 이상, FastAPI, Pydantic, pytest |
| 기본 분석 모드 | API 비용이 들지 않는 `rule` 모드 |
| 현재 작업 브랜치 | 로컬 `aitest` |
| 기능·평가 기준 커밋 | `68519f5 Record pre-improvement detection benchmark with 720 labeled cases` |
| 핵심 안전 경계 | 실제 계정 차단, 권한 변경, 세션 격리, 외부 SIEM·ITSM 전송을 수행하지 않음 |

이 프로젝트는 합성 이벤트와 출처가 고정된 공개 보안 로그를 받아 다음 작업을 수행하는 시연용 SecOps 애플리케이션이다.

1. 공통 `SecurityEvent` 형식으로 입력을 검증한다.
2. OCSF 1.9.0 형식으로 정규화하고 원본·변환 해시를 남긴다.
3. Sigma 2.1 규칙으로 탐지한다.
4. 규칙 기반, OpenAI 또는 하이브리드 분석기로 위험도와 근거를 구조화한다.
5. 정책 허용 범위와 사람 검토 필요 여부를 확인한다.
6. 여러 이벤트를 엔터티 그래프와 시간창으로 상관분석한다.
7. 사고 케이스와 변경 이력을 저장한다.
8. 외부 연동용 CloudEvents를 아웃박스에 보존하지만 실제 목적지 전송은 기본적으로 수행하지 않는다.
9. local/test 전용 제로트러스트 경로에서 서명·범위·신선도와 사용자·기기·자원·행위를 검증한다.
10. 세션별 단기·단일 사용 허용을 발급하고 위험 변화·키 폐기 시 회수하여 다음 모의 자원 접근을 거부한다.

실제 IdP·MFA·EDR 증명, 상시 신호 수신/관련 세션 자동 재평가, 독립 업무 서비스 PEP는 아직 미완료다. 서명은 등록 수집기의 출처·무결성을 확인하며 그 주장의 진실성을 보장하지 않는다. 새 경로는 production에서 비활성화된다.

## 2. 학사 일정과 실제 코드 진척 구분

이 저장소는 계획보다 빠르게 구현되었다. 발표자료나 주차별 보고서를 작성할 때 실제 코드의 모든 기능을 해당 주차 성과로 쓰면 안 된다.

- 중간 영상의 1~6주차 범위: 제로 트러스트 학습, 위협 시나리오, 이벤트 모델, 합성 로그, Structured Outputs, 로컬 Docker 검증까지다.
- 현재 코드 범위: 계획서의 3~14주차 개발 항목과 이후 기업 적용 고도화 기능까지 구현되어 있다.
- 15~16주차 최종 보고서와 발표는 아직 별도 작성 대상이다.
- 주차별 근거는 반드시 [`docs/README.md`](docs/README.md)와 각 `docs/weekXX/README.md`를 기준으로 사용한다.

## 3. 현재 Git 상태

문서 작성 시점의 상태는 다음과 같다.

```text
branch: aitest
feature/evaluation baseline: 68519f5
remote: origin -> https://github.com/cheonan-asan-sta/zero-trust-llm-secops.git

aitest: 현재 v0.17.0 구현과 개선 전 탐지 평가
실제 원격 상태: git ls-remote --heads origin으로 확인
```

주의사항:

- 2026년 11월 1일 사용자가 현재 코드를 GitHub에 올리도록 요청했다. 대상은 기존 작업 브랜치 `aitest`이며 `main` 병합·강제 푸시는 포함하지 않는다. 실제 게시 상태는 원격 브랜치와 로컬 HEAD 일치 여부로 확인한다.
- `docs.zip`, `docs/week03.zip`은 추적되지 않은 사용자 파일이다. 요청 없이 삭제, 이동, 커밋하지 않는다.
- 기존 브랜치를 강제로 재설정하거나 사용자 변경사항을 되돌리지 않는다.
- 사용자가 지정한 브랜치와 기존 승인을 따른다. 인증정보·실행 데이터·사용자 압축본은 업로드하지 않는다.

## 4. 전체 처리 구조

### 보안 이벤트 분석 경로

```text
SecurityEvent
  -> 입력 모델 검증
  -> 규칙 기반 / OpenAI / 하이브리드 분석
  -> SecurityAssessment
  -> 정책 안전장치와 대응 미리보기
  -> AnalysisResult
  -> JSONL 또는 DynamoDB 감사 기록
  -> 분석가 검토 상태 갱신
```

### 탐지·사고 관리 경로

```text
SecurityEvent
  -> OCSF 1.9.0 정규화
  -> Sigma 2.1 규칙 탐지
  -> 5분·30분·24시간 상관분석
  -> OCSF Incident Finding
  -> 테넌트별 Incident Case
  -> CloudEvents 1.0 Integration Outbox
  -> 전달 상태 기록과 재시도 관리
```

두 경로 모두 실제 보안 시스템을 변경하지 않는다. 대응은 `simulation` 미리보기이며 외부 전달도 로컬 상태 머신에 머문다.

### 제로트러스트 운영 경로

```text
서명 수집기 -> 출처/범위/신선도 검증 -> 규칙+Sigma 및 자원 정책
  -> 세션 판단/버전/단일 사용 허용 -> 모의 PEP -> 모의 자원 200 또는 403
  -> 위험 재평가/키 폐기 -> 이전 허용 회수 -> 다음 접근 거부
```

v0.16은 세션·자원 정책·허용 소비/회수, v0.17은 Ed25519 서명·120초 재인증 챌린지·키 회전/폐기를 추가했다. `/analysis`의 선택적 LLM과 케이스 경로가 완성된 하나의 자동 집행 체인으로 통합된 것은 아니다. LLM은 필수 검증이나 최종 허용·회수를 대체하지 않는다.

## 5. 폴더 구조와 역할

```text
zero-trust-llm-secops/
├─ app/                     FastAPI 애플리케이션
│  ├─ analyzers/            규칙·OpenAI·하이브리드 분석기
│  ├─ data/                 통제대장, Sigma 규칙, 공개 재생 표본
│  │  ├─ replay/            출처·라이선스·해시가 고정된 공개 로그
│  │  └─ sigma/             로컬 Sigma YAML 규칙
│  ├─ services/             정책, 감사, 탐지, 상관분석, 케이스 등 도메인 서비스
│  └─ static/               한국어 관제 대시보드
├─ tests/                   단위·API·통합·회귀 테스트
├─ docs/                    주차별 산출물과 기업 적용 문서
├─ infra/                   AWS CloudFormation 정의
├─ scripts/                 Docker 시험과 AWS 배포 스크립트
├─ .github/workflows/       CI 정의
├─ runtime/                 실행 중 생성되는 로컬 JSONL 데이터
├─ compose.yaml             비용 없는 로컬 실행 구성
├─ Dockerfile               애플리케이션 이미지
├─ Dockerfile.test          검사·테스트 전용 이미지
├─ Dockerfile.lambda        AWS Lambda 컨테이너 이미지
├─ pyproject.toml           패키지·의존성·pytest·ruff 설정
├─ .env.example             비밀값 없는 환경변수 예시
└─ README.md                사용자용 전체 기능·실행·API 설명
```

### `app/`

애플리케이션의 모든 실행 코드가 있다.

| 파일·폴더 | 역할 |
|---|---|
| `main.py` | FastAPI 앱 생성, 의존성 연결, 모든 HTTP 엔드포인트 정의 |
| `models.py` | 이벤트, OCSF, 탐지, 분석, 케이스, 아웃박스, 평가 모델과 교차 필드 검증 |
| `config.py` | `.env.local`과 환경변수 로딩, 운영 환경의 안전하지 않은 설정 거부 |
| `security.py` | 비활성·API 키·OIDC 인증, 역할 기반 권한, 테넌트 주체 생성 |
| `middleware.py` | 요청 ID, 본문 크기 제한, 보안 헤더, Prometheus 요청 지표 |
| `scenarios.py` | 정상 3건과 위협 5건, 시나리오 조건, 합성 이벤트 생성 |
| `prompting.py` | Few-shot 선택, LLM 입력 생성, 자유 텍스트를 데이터로 다루는 프롬프트 경계 |
| `analyzers/` | 분석기 인터페이스와 세 가지 분석 모드 |
| `services/` | 도메인별 처리 로직과 저장소 구현 |
| `data/` | 버전 관리되는 규칙·통제·공개 데이터 |
| `static/` | 대시보드 HTML, CSS, JavaScript, 파비콘 |

### `app/analyzers/`

| 파일 | 역할 |
|---|---|
| `base.py` | 분석기가 따라야 하는 `Analyzer` 프로토콜 |
| `rule_based.py` | API 키 없이 결정적으로 동작하는 기본 위험 분석기 |
| `openai_analyzer.py` | OpenAI Structured Outputs로 `SecurityAssessment`를 생성하는 선택 기능 |
| `hybrid.py` | 규칙 결과가 애매할 때만 LLM을 호출하고 실패 시 안전하게 규칙 결과로 복구 |

분석기를 변경할 때는 `ground_truth`가 LLM 입력으로 전달되지 않는지, 낮은 신뢰도와 고위험 결과가 사람 검토로 전환되는지 확인한다.

### `app/services/`

| 파일 | 역할 |
|---|---|
| `policy.py` | 위험 점수·등급 일관성, 허용 대응 목록, 정책 예외, 대응 미리보기 |
| `scenario_evaluator.py` | 구조화된 조건으로 이벤트와 시나리오의 일치도 계산 |
| `evaluation.py` | 반복 평가, 정확도, JSON 유효율, 지연시간과 오류 진단 |
| `audit.py` | JSONL·DynamoDB 감사 저장, 테넌트 격리, SHA-256 해시 체인 |
| `assurance.py` | 기계판독 통제대장 검증과 구현 증적 조회 |
| `ocsf.py` | `SecurityEvent`를 OCSF 1.9.0 Authentication·API Activity로 변환 |
| `sigma.py` | 승인·버전·시험 메타데이터가 있는 Sigma 2.1 로컬 탐지 엔진 |
| `public_replay.py` | 고정된 Splunk·Microsoft Sentinel 표본을 네트워크 없이 재생 |
| `detection_quality.py` | 규칙별 혼동행렬, Precision, Recall, F1, 오탐률과 품질 게이트 |
| `correlation.py` | 엔터티 그래프와 다중 시간창으로 Incident Finding 생성 및 중복 제거 |
| `incident_quality.py` | 사건 단위 Precision·Recall·F1, 오상관률과 구조 품질 게이트 |
| `cases.py` | 사고 케이스 생성·저장·상태 전이·버전 충돌 방지·증거 지문 |
| `integration_outbox.py` | 케이스 버전을 CloudEvents로 투영하고 대기·재시도·완료·실패 상태 관리 |
| `zero_trust.py` | 세션 정책 판단, 허용 발급·소비·회수, SQLite 상태와 저널 |
| `trusted_signals.py` | Ed25519 서명·범위·신선도·키 수명주기 검증 |
| `detection_benchmark.py` | 합성 개발/평가 분리, 혼동행렬·계열 부트스트랩·품질 게이트 |

### `app/data/`

| 위치 | 역할 |
|---|---|
| `control-register.json` | 18개 기업·공공 보안 통제와 코드·시험 증거를 연결한 대장 |
| `sigma/*.yml` | 계정 침해, 미관리 기기, 권한 상승, 내부 확산, 데이터 유출 규칙 |
| `replay/manifest.json` | 공개 표본의 출처, 커밋, 라이선스, SHA-256, 기대 결과 |
| `replay/*.json*`, `*.xml` | 오프라인 재생용 공격·정상 이벤트 표본 |
| `replay/NOTICE.md` | 공개 데이터 출처와 라이선스 안내 |
| `benchmark/` | 합성 720건·72계열, 분할·라벨 근거·생성기/자료 지문 |
| `zero-trust-policies.json` | 서버 소유 자원·행위·역할·허용/신호 유효기간 정책 |

데이터 파일을 수정하면 관련 해시, manifest, 품질 목표, 테스트도 함께 갱신해야 한다.

### `app/static/`

| 파일 | 역할 |
|---|---|
| `index.html` | 관제 대시보드 구조 |
| `styles.css` | 천안아산역을 연상시키는 남색·파랑·노랑 화면 스타일 |
| `app.js` | API 호출, 시나리오 선택, 분석·탐지·케이스 결과 표시 |
| `favicon.svg` | 프로젝트 아이콘 |

프론트엔드는 별도 빌드 도구 없이 FastAPI가 정적 파일로 제공한다.

### `tests/`

최신 Windows 로컬 기준 421건 통과다. 매개변수별 시험 조건을 포함한 건수이며 코드 커버리지나 탐지 품질 합격을 뜻하지 않는다.

| 영역 | 주요 파일 |
|---|---|
| 모델·시나리오·프롬프트 | `test_models.py`, `test_scenarios.py`, `test_prompting.py` |
| 분석기·정책 | `test_openai_analyzer.py`, `test_hybrid_analyzer.py`, `test_policy.py` |
| API·인증·설정 | `test_api.py`, `test_security.py`, `test_enterprise_config.py` |
| 감사·보증 | `test_audit.py`, `test_assurance.py` |
| OCSF·Sigma·공개 재생 | `test_detection_pipeline.py`, `test_correlation_replay.py` |
| 탐지·사건 품질 | `test_detection_quality.py`, `test_incident_quality.py` |
| 엔터티 상관분석 | `test_entity_graph_correlation.py` |
| 사고 케이스 | `test_incident_cases.py` |
| 연동 아웃박스 | `test_integration_outbox.py` |
| Docker·배포 설정 | `test_docker_setup.py` |
| 반복 평가 | `test_evaluation.py` |
| 제로트러스트·서명 | `test_zero_trust_operations.py`, `test_trusted_signals.py` |
| 추가 회귀 204건 | `zero_trust/test_session_regressions.py`, `test_signal_regressions.py`, `test_api_regressions.py`, `test_identity_regressions.py` |
| 확대 평가기 40건 | `test_detection_benchmark.py` |

새 기능은 정상 경로뿐 아니라 인증 실패, 테넌트 분리, 잘못된 상태 전이, 위변조, LLM 실패 같은 실패 경로도 테스트한다.

### `docs/`

| 위치 | 역할 |
|---|---|
| `README.md` | 계획 주차와 실제 구현 근거를 연결하는 색인 |
| `week03/` | 위협 모델, 이벤트 스키마, 요구사항, 아키텍처 |
| `week04/` | 탐지 조건, 정책 예외, 평가 설계 |
| `week05/` | 비용 없는 Docker 검증 |
| `week06/` | 합성 이벤트, Few-shot, 구조화 출력 |
| `week07/`~`week14/` | 분석기, 정책, API, UI, 성능·오류 진단 산출물 |
| `enterprise-readiness.md` | 현재 통제 상태와 실제 기업 운영 전 필수 게이트 |
| `deep-research-enterprise-secops.md` | 실무 사례·논문 기반 고도화 우선순위 |
| `reference-catalog-enterprise-public-sector.md` | 기업·공공·금융·표준 참고자료 목록 |
| `zero-trust-operations.md` | 제로트러스트 원칙·코드·시험·실환경 한계 |
| `mentoring-priority-roadmap.md` | 멘토링 M1~M8·인프라 I1~I8·남은 주간 일정 |
| `team-responsibilities.md`, `roles/`, `역할분담_주간계획_한눈에보기.md` | 공동 경계·개인 계획·주간 역할 표 |
| `model-candidate-review.md` | Jev·Laya 등을 포함한 작업별 AI 비교 후보 |
| `technology-selection-plan.md`, `technology-decisions/` | 도구 C01~C10 비교 계획·선정 대장·빈 양식 |
| `benchmark-results/` | 개선 전 개발/평가 예측·오류·지표 JSON 원자료 |

보고서나 발표자료의 성과 문구는 코드만 보고 추정하지 말고 해당 주차 문서를 근거로 작성한다.

### `infra/`

| 파일 | 역할 |
|---|---|
| `ecr.yaml` | ECR 저장소와 이미지 스캔 설정 |
| `lambda.yaml` | Lambda 컨테이너, IAM 인증 함수 URL, 실행 역할, DynamoDB 저장 구성 |

이 폴더는 실제 AWS 리소스를 만들 수 있다. 사용자 요청 없이 배포하거나 삭제하지 않는다.

### `scripts/`

| 파일 | 역할 |
|---|---|
| `test-docker.ps1` | Docker 안에서 Ruff, pytest, API 스모크 테스트 실행 |
| `deploy-aws.ps1` | AWS 계정 `172585182454` 확인 후 이미지 빌드·ECR 업로드·CloudFormation 배포 |
| `local_signal_collector.py` | 별도 임시 키를 쓰는 루프백 서명 수집기 시연 |
| `build_detection_benchmark.py`, `evaluate_detection_benchmark.py` | 합성 평가 자료 생성·검증·개선 전 성능 보고 |

배포 스크립트는 비용과 외부 상태 변경을 일으킬 수 있으므로 명시적인 배포 요청이 있을 때만 실행한다.

### `runtime/`

실행 중 생성되는 다음 로컬 상태를 담는다.

- `audit.jsonl`: 분석 결과와 검토 이력
- `cases.jsonl`: 사고 케이스와 상태 변경 이력
- `integration-outbox.jsonl`: 외부 연동 대기·재시도·완료 상태

파일들은 해시 체인으로 연결된다. 테스트 목적이 아니면 직접 편집하지 않는다. 저장소에 없을 수도 있으며 실행 시 생성된다.

## 6. 실행 방법

### 기존 가상환경 사용

현재 로컬에는 `.venv`가 있다.

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

접속 주소:

- 대시보드: `http://127.0.0.1:8000/`
- API 문서: `http://127.0.0.1:8000/docs`
- 상태 확인: `http://127.0.0.1:8000/health`

### 새 환경 구성

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

### Docker 실행

```powershell
docker compose up --build
docker compose down
```

로컬 Docker는 `rule` 모드, 인증 비활성, 읽기 전용 파일시스템, 비루트 사용자로 실행된다. 감사·케이스·아웃박스 볼륨까지 삭제하려는 경우에만 사용자의 의도를 확인한 뒤 `docker compose down --volumes`를 실행한다.

## 7. 환경변수와 비밀정보

- `.env.example`은 비밀값 없는 설정 예시다.
- `.env.local`은 로컬 전용이며 Git에 포함하면 안 된다.
- 다른 AI는 `.env.local`의 값을 출력, 로그, 문서 또는 커밋에 복사하지 않는다.
- 기본 개발은 `ANALYZER_MODE=rule`로 충분하다.
- OpenAI 또는 하이브리드 모드가 필요할 때만 기존 `.env.local`을 재사용한다.
- AWS 배포에서는 API 키 평문 대신 Secrets Manager ARN을 사용한다.

주요 분석 모드:

```dotenv
ANALYZER_MODE=rule
ANALYZER_MODE=openai
ANALYZER_MODE=hybrid
```

운영 환경에서 `AUTH_MODE=disabled`는 설정 검증 단계에서 거부된다.

## 8. 테스트 기준선

2026년 11월 1일 기존 `.venv`의 Windows 로컬 기준:

```text
pytest: 421 passed, 3 dependency deprecation warnings
ruff:   All checks passed
JavaScript syntax: passed
```

검증 명령:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
```

Docker 포함 종단 검증:

```powershell
.\scripts\test-docker.ps1
```

경고 3건은 현재 Starlette TestClient, AnyIO 별칭, Mangum 이벤트 루프 관련 의존성 폐기 예정 경고다. 테스트 실패는 아니지만 의존성을 갱신할 때 회귀 여부를 확인한다.

최근 컨테이너 시험은 Docker 엔진이 꺼져 있어 실행하지 않았다. 10월 27일 로컬·Docker 177건 통과는 이전 기록이며 Docker 421건을 확인한 것으로 쓰지 않는다.

### 개선 전 탐지 평가

- 기존 공개 원본 12건은 고정 회귀 표본으로 보존한다. 새 합성 자료는 720건(정상360·위협360), 72계열, 고유 신호 패턴631개다.
- 개발·평가 각360건이며 계열·세션·사용자·기기·동일 신호 패턴의 분할 간 중복은 0이다. 라벨은 작성자 부여 상태로 독립 팀 검토가 남아 있다.
- holdout: TP90·FP50·FN90·TN130, 정밀도64.29%·재현율50.00%·F1 56.25%·오탐률27.78%.
- 목표 P/R/F1≥95%, 오탐률≤5%에 미달한다. `gate_passed=false`이며 결과를 좋게 만들기 위한 탐지 수정은 하지 않는다.
- 이는 Sigma 이벤트 경보 품질이며 LLM 또는 PEP 전체 성능이 아니다. 합성 자료를 기업 모집단 성능이나 외부 블라인드 평가로 표현하지 않는다.
- API: `GET /evaluation/detection-benchmark?split=holdout`(viewer), CLI: `python -m scripts.evaluate_detection_benchmark --require-targets`. 목표 미달 시 종료 코드1은 정상적인 품질 게이트 실패다.

전체 방법·불확실성·규칙별 결과는 `docs/week04/detection-and-evaluation.md`와 `docs/benchmark-results/`를 따른다.

### 역할과 일정

채희주는 설계·AI와 인프라 구성/실행/장애 주입/자원·지연·복구 측정/원자료/선정 근거를 주담당한다. 김택희는 백엔드·데이터·앱 지표·기능/상태 시험과 M6 모델 평가 실행기·집계를 담당한다. 공동 통합·상대 재현을 수행하며 예정 배정을 과거 실적으로 소급하지 않는다.

미완료 멘토링 M3 지속 검증→M4 GuardDuty 공식 형식 로컬 입력→M5 안전한 독립 집행을 우선한다. 11/29 기능 동결, 12/6 제출 가능본, 12/7~13 잠정 최종 제출이며 공식 일정은 미확정이다. 대시보드는 자체 개발하고 모델·도구 후보는 비교 계획이지 도입 결과가 아니다.

## 9. 작업 종류별 시작 위치

| 요청 | 먼저 볼 위치 | 함께 확인할 테스트 |
|---|---|---|
| API 추가·수정 | `app/main.py`, `app/models.py` | `tests/test_api.py` |
| 이벤트 모델 변경 | `app/models.py`, `app/scenarios.py` | `test_models.py`, `test_scenarios.py` |
| LLM 프롬프트·출력 | `app/prompting.py`, `app/analyzers/openai_analyzer.py` | `test_prompting.py`, `test_openai_analyzer.py` |
| 위험 분석 로직 | `app/analyzers/`, `app/services/policy.py` | `test_policy.py`, `test_hybrid_analyzer.py` |
| 인증·권한 | `app/security.py`, `app/config.py` | `test_security.py`, `test_enterprise_config.py` |
| 감사 저장 | `app/services/audit.py` | `test_audit.py` |
| OCSF 정규화 | `app/services/ocsf.py` | `test_detection_pipeline.py` |
| Sigma 규칙 | `app/services/sigma.py`, `app/data/sigma/` | `test_detection_pipeline.py` |
| 공개 로그 재생 | `app/services/public_replay.py`, `app/data/replay/` | `test_correlation_replay.py` |
| 사건 상관분석 | `app/services/correlation.py` | `test_entity_graph_correlation.py` |
| 품질 지표 | `detection_quality.py`, `incident_quality.py` | 같은 이름의 테스트 파일 |
| 사고 케이스 | `app/services/cases.py` | `test_incident_cases.py` |
| 외부 연동 상태 | `app/services/integration_outbox.py` | `test_integration_outbox.py` |
| 대시보드 | `app/static/` | API 회귀 테스트와 브라우저 확인 |
| AWS 배포 | `infra/`, `scripts/deploy-aws.ps1` | `test_docker_setup.py`와 계정 확인 |
| 주차 보고서 | `docs/README.md`, `docs/weekXX/` | 코드 커밋과 실제 산출물 대조 |

## 10. 안전·설계 불변 조건

다음 조건은 기능을 추가해도 유지한다.

1. `ground_truth`는 평가 전용이며 분석기와 LLM 입력에서 제외한다.
2. 이벤트의 자유 텍스트는 지시가 아니라 분석 대상 데이터로 취급한다.
3. 고위험, 낮은 신뢰도, 규칙과 LLM이 불일치하는 결과는 사람 검토로 전환한다.
4. 추천 대응은 허용된 열거형 안에서만 선택한다.
5. 고위험 대응은 모의 미리보기·승인 범위다. 제로트러스트 경로의 허용·회수·집행은 local/test 모의 자원에 한정한다.
6. 테넌트가 다른 분석 결과, 케이스, 아웃박스 이벤트에 접근할 수 없어야 한다.
7. 감사·케이스·아웃박스 해시 체인이 손상되면 실패 폐쇄한다.
8. 공개 데이터와 탐지 규칙의 출처, 라이선스, 버전, 해시를 보존한다.
9. `production` 환경은 인증 없이 시작할 수 없다.
10. 실제 AWS 변경, 외부 전송, 유료 API 호출은 사용자의 명시적 요청 범위에서만 수행한다.

## 11. 현재 한계와 다음 우선순위

현재 코드는 기업 도입을 위한 기술 기준선이지 운영 승인이나 보안 인증을 받은 제품이 아니다.

주요 미완료 항목:

- 실제 기업 IdP와 OIDC 역할 매핑 검증
- API Gateway 또는 사내 게이트웨이의 속도 제한·WAF·TLS 정책
- 조직의 개인정보·보존·데이터 지역성 정책 승인
- 더 넓고 독립적으로 라벨된 공격·정상 데이터셋 평가
- 운영 부하, 장애 복구, RTO·RPO, 경보·당직 훈련
- SAST, SCA, SBOM, 이미지 서명, DAST, 외부 침투시험
- 프롬프트 공격과 모델 변경에 대한 승인·롤백 절차
- 실제 SIEM·ITSM 커넥터, 목적지 인증, 재전송·충돌 처리
- 15~16주차 최종 보고서와 발표자료

현재 실행 순서는 [`docs/mentoring-priority-roadmap.md`](docs/mentoring-priority-roadmap.md), 운영 한계는 [`docs/enterprise-readiness.md`](docs/enterprise-readiness.md)를 기준으로 한다. GitHub 업로드 요청은 AWS 배포·새 도구 설치·유료 모델 호출·탐지 개선을 뜻하지 않는다.

## 12. 다른 AI의 권장 작업 절차

1. 이 문서와 `README.md`, 관련 `docs/weekXX/README.md`를 먼저 읽는다.
2. `git status --short --branch`로 사용자 파일과 현재 브랜치를 확인한다.
3. 요청과 관련된 모듈·테스트만 우선 읽는다.
4. 구현 전에 안전 불변 조건과 실제 외부 상태 변경 여부를 확인한다.
5. 코드를 수정하면 같은 영역의 실패 경로 테스트를 추가한다.
6. Ruff와 전체 pytest를 실행한다.
7. 기능 진척과 학사 주차를 구분해 문서를 갱신한다.
8. 실제 키, 개인정보, 기업 로그, AWS 자격증명을 출력하거나 커밋하지 않는다.
9. 배포, 푸시, 실제 외부 연동은 사용자가 요청한 경우에만 수행한다.

## 13. 다른 AI에게 전달할 시작 프롬프트 예시

```text
이 저장소는 아주대학교 파란학기 천안아산역 팀의 zero-trust-llm-secops 프로젝트다.
먼저 AI_HANDOFF.md와 README.md를 읽고, git status와 현재 브랜치를 확인해라.
현재 실제 코드는 v0.17.0까지 구현되어 있지만 학사 주차별 성과는 docs/README.md와
docs/weekXX 문서에 맞춰 구분해야 한다.

실제 계정 차단, 권한 변경, 세션 격리, 외부 SIEM·ITSM 전송은 구현 범위가 아니다.
.env.local의 비밀값을 출력하거나 커밋하지 말고, ground_truth를 분석기 입력에 넣지 마라.
사용자 파일과 기존 변경사항을 보존하고, 작업 후 Ruff와 전체 pytest를 실행해라.
개선 전 탐지 결과를 보존하고 탐지 규칙·임계값을 임의로 개선하지 마라.

이번 요청: [여기에 수행할 작업을 적기]
```

## 14. 가장 먼저 읽을 문서

1. [`README.md`](README.md): 실행 방법, 전체 기능, API 목록
2. [`docs/README.md`](docs/README.md): 계획 주차와 실제 구현 연결
3. [`docs/enterprise-readiness.md`](docs/enterprise-readiness.md): 현재 보안 기준선과 남은 운영 검증
4. [`docs/deep-research-enterprise-secops.md`](docs/deep-research-enterprise-secops.md): 다음 고도화 근거
5. 작업 대상과 관련된 `docs/weekXX/README.md`와 테스트 파일
6. [`docs/zero-trust-operations.md`](docs/zero-trust-operations.md): 핵심 운영 경로와 한계
7. [`docs/mentoring-priority-roadmap.md`](docs/mentoring-priority-roadmap.md): 현재 피드백 우선순위와 비용 경계
