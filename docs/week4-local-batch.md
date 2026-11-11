# 4주차까지 잔여 구현·로컬 일괄 검증

2026-11-11 착수. 기준 PR52 `c83b857`, 작업 `feature/chaeheeju-week4-local-batch`.
변경 경계 Docker 검증 종료: **2026-11-12 00:59:56 KST**, 종료코드0, 소유 자원0/0/0.
주차는 개발 로드맵 분류다. 이 작업은 11/23~11/29의 독립 통합 평가·동결 준비까지 대조한다.
과거 3주차 시험의 성공을 이번 실행 성공이나 팀원의 독립 검토로 바꾸지 않는다.

[공개 검증 요약과 원자료 지문](infrastructure-results/week4-local-20261111.json)을 함께 확인한다.

## 이번 구현

- M5: 고위험 모의 대응을 저장된 분석 ID에 결합하고 API로 그 결합·조치를 바꿀 수 없는 계획으로 만든다.
  analyst 요청 → 다른 주체의 responder 승인/거절 → responder 모의 실행이다.
  tenant·요청 키·버전·5분 만료·상태 전이를 검사하며 SQLite 트랜잭션으로
  실행 결과와 actor/시각/메모 이력을 함께 보존한다. 같은 실행자의 정확한 재시도는
  원래 영수증만 반환한다. 동시 요청으로 두 번 실행하거나 거절된 계획을 실행하지 않는다.
- M7: 기존 48세션 공개 인증 파일럿의 데이터·라벨·출처·NOTICE를 원자적으로 복사하고
  SHA-256 anchor로 동결 후보를 검증한다. 원본을 덮어쓰지 않고 외부 anchor를 요구한다.
  독립 라벨 검토 상태는 항상 `pending`이다. 새 holdout·독립 검토 완료를 뜻하지 않는다.
- 일괄 실행: M7 동결 검증, M6 오프라인 모의 공급자 평가, 기존 Linux 전체 회귀,
  관측 mTLS와 CA/DB 인수를 한 명령으로 순차 실행한다. 구현/문서 작성 후 실행한다.
  오래 걸리는 Docker 전체 시험을 기능마다 반복하지 않는다. 실패 후 필요한 재검사는 별도 기록한다.

## API와 보안 경계

`RESPONSE_WORKFLOW_DB_PATH`로 별도 로컬 SQLite를 지정한다. writable 데이터 볼륨의
전용 파일이어야 하며 기존 정책 DB·CA DB 파일을 재사용하지 않는다. 전용 application ID와
테이블 소유권을 검사하며 기존 외부 DB는 초기화하지 않는다.

| API | 역할 | 입력 |
|---|---|---|
| POST /response/plans | analyst | event_id, analysis_id, request_key |
| GET /response/plans/{id} | viewer | 같은 tenant의 계획 ID |
| POST /response/plans/{id}/approve | responder | expected_version, note |
| POST /response/plans/{id}/reject | responder | expected_version, note |
| POST /response/plans/{id}/execute | responder | expected_version, note |

계획은 서버 감사 저장소의 해당 tenant·최신 분석을 참조한다. 클라이언트가 임의 action이나
LLM 답변을 직접 제출할 수 없다. ALLOW는 대응 계획으로 만들 수 없다. 만료·자기 승인·
버전 충돌·승인 전 실행·종결 이후 실행은409, 타 tenant는404, 역할 부족은403이다.
production에서는 로컬 workflow를 노출하지 않는다. 로컬 auth_disabled는 시험 편의 설정이며
두 사람 승인 검증은 서로 다른 인증된 subject로 시험해야 한다.

**실행 결과는 SIMULATED이며 외부 호출·세션 변경은0**이다. 기존 서명 신호에 의한
자동 회수/PEP 차단과 별도 경로다. 승인됐다는 이유로 LLM에 세션 복구·권한 발급 도구를 주지 않는다.
새 승인 원장은 기존 앱 SQLite+JSONL 복원 계약에 포함되지 않는다. 유실 시 새 빈 원장으로
승인 상태를 복원했다고 주장하지 않으며, 기존 계획 ID는 없으므로 실행되지 않는다.
온라인 다중 호스트·원격 변조 방지·고가용성은 보장하지 않는다.

## 남은 계획 대조

| 항목 | 현재 상태 | 완료에 추가로 필요한 증거 |
|---|---|---|
| M1/M2 신호 권한·테넌트·신선도 | 기존 구현 유지, 전체 회귀 대상 | 실제 IdP/EDR 증명과 독립 인수 |
| M3 내구 접수·worker·watchdog | 기존 구현 유지, 관측 통합 대상 | 팀원 독립 재현 |
| M4 GuardDuty 공식 형식·매핑 | 로컬 입력 구현 유지 | 실제 AWS 수신은 비용 없는 이번 범위 밖 |
| M5 독립 PEP·단일 소비·회수 | 이번 관측75·선정37·앱복원13 통과 | 팀원 독립 재현·운영 인수 |
| M5 고위험 모의 조치 승인 | 이번 API·원장·동시성/권한 시험 통과 | 독립 검토, 원장 복원 계약 확장 |
| M6 AI 비교·오류·예산 | 기존 실행기·실호출 자료 유지, 이번은 mock만 실행 | 기존 Jev/OpenAI 소표본과 새 공통 조건 비교를 구분. Laya 미측정·새 실측/독립 평가 대기 |
| M7 공개 자료·세션 분리·동결 | 기존48세션 파일럿·이번 동결 후보 도구 | 독립 라벨 검토·새 평가셋 승인 |
| I2/I6 인증·키 교체 | 기존 구현 유지·CA 인수 포함 | 여러 선택 프로필 전체 장애 행렬과 팀원 대조 |
| I4 앱/CA DB 복원 | 기존 개별 계약 유지 | 승인 원장 포함 통합 복원·운영 RTO/RPO·독립 재현 |
| C01/C02 관측·PEP 선정 | 기존 로컬 조건부 유지 | 현재 후보 동등 조건·독립 재현·운영 판단 |
| C03 일곱 이미지 검사 | PR52 근거 유지 | 잔여 발견의 앱 영향 독립 검토·helper/builder 확대·최종 선정 |
| M8 동결·보고·인수 | 근거와 보류 항목 연결 | 팀원 독립 검토와 최종 동결 승인 |

이 표는 전체 계획 완료 선언이 아니다. 목표 P/R/F1≥95%, FPR≤5%는 유지하고
개선 전 탐지 규칙·임계값·라벨을 변경하지 않는다. 기능 회귀 성공으로 탐지 품질을 대신하지 않는다.

## 일괄 실행

```powershell
.venv\Scripts\python.exe -m scripts.test_week4_batch
```

Docker Linux 엔진이 필요하다. `runtime/c02/infra-batches/week4-*`에 소스·이미지·단계별
결과와 로그를 보존한다. 소유 자원만 정리하며 사용자 ZIP·다른 Docker workload를 지우지 않는다.
AWS 배포·유료 모델 호출은 없다. 공개 도구/이미지 준비 다운로드는 있을 수 있다.
`verification.json`의 completed와 각 자식 report의 cleanup까지 확인한다.
M7 동결 anchor는 동결 디렉터리 밖의 batch report에 보존한다.

## 이번 실행 결과

원자료: `runtime/c02/infra-batches/week4-20261111-final1/`.
앱 코드는 PR52 `c83b857`에 이번 미커밋 변경을 더한 상태에서 검증했다.
실행 결과의 `source_commit`만으로 PR52 원본을 시험했다고 해석하지 않는다.

| 검증 | 실제 결과 | 해석 |
|---|---|---|
| Linux 전체 회귀·Ruff | 2,749 passed, 0 skipped, 기존 경고2, 754.36초. Ruff 통과 | 새 승인·동결 시험21개 포함. 후속 CA 준비 대기·도우미 수정 전 소스 |
| 관측 mTLS 종단 | 75개 통과, 소유 컨테이너/볼륨/망 0/0/0 | 정상 TLS1.3·회수 후403·중복 단일 효과·재시작·경보 |
| C01/C02 선정 재현 | 37개 통과, 576요청, 자원 표본1,918개·오류0, 정리0/0/0 | 기대 허용153/거부423. 대안 제품의 새 동등 비교나 운영 승인 아님 |
| 앱 복원 | 13개 통과, 정리0/0/0 | 복원 중 중단·재개, 기존 토큰403·새 허용200. 과거 전체 복원24개와 구분 |
| M7 동결 후보 | 기존 공개 파일럿48세션 복사·검증 통과 | 개발24/평가24. 새 데이터 확보·독립 라벨 승인 아님 |
| M6 오프라인 계약 | 24사례, mock 요청48건 | 실제 LLM 호출0. 출력·실패·예산 계약 시험이며 실제 모델 비교 아님 |
| 최종 소스 집중·형식 | 승인/동결/갱신 준비·보안 행 보존·진단·CA 준비 순서57개 통과, 전체 Ruff·diff check 통과 | 전체2,749개와 중복 합산하지 않음 |
| 실제 앱 컨테이너 승인 API | 생성201·조회200·자기 승인409, `/data` 원장 저장 통과 | 비루트·읽기 전용 root·망 none. Compose writable 경로 확인 |
| 최초 CA/DB/백업 통합 | 51개 검사 후 실패, 정리0/0/0 | 전체67개 통과로 표시하지 않음. 후속 집중 검증과 별도 기록 |
| 최종 DB·백업 변경 경계 | 25개 통과, 종료코드0, 정리0/0/0 | CA 3회차·DB 종료4회는 직전 부분 실행의 성공 근거와 구분 |
| 탐지 품질 | 개발360·holdout360 측정, 목표 gate 실패 | 아래 기준선 유지. 기능 통과와 구분 |

M7 외부 anchor:
`9bde091bdc8d516816091d2766adf86c7f3e1806e38f6c52485e171e4c8be545`.

전체 회귀의 테스트 이미지 ID는
`sha256:f10c45ffbd10707d701d70331a591fcfe2d17a14c4f3a434f7aa16acddd63ea4`,
소스 묶음 지문은 `d2ed14dfd95cf99662622636f2729d0c150c4b09dcb45a7470cdf6d154727caf`다.
소스 수정 후 실행한 집중 검증을 이전 이미지의 전체 회귀로 바꾸지 않는다.

### CA 실패와 후속 검증 범위

최초 실패는 authority 3회차·DB 전송 교체2회 뒤 정지/재시작 시점이었다.
실패 스냅샷과 같은 세대의 활성 leaf27개가 이미 만료됐고, 가장 먼저 만료된 활성
leaf는 실패 약76초 전 만료였다. 엄격한 만료 검증에서 거부할 조건이 확인됐다.
내부 verifier의 세부 분기는 공개 진단에서 가려져 있으므로 다른 원인까지 배제했다고 주장하지 않는다.
근거는 `ca-failure-analysis.json`이다.

시험 도우미는 긴 정지 구간 전에 **실제 controller의 인증서·개인키 유지보수**를 완료하도록 보완한다.
인증서 유효기간·만료 검증을 완화하지 않는다. 이 프로필의 유지보수는 개인키 교체와
이전 client 인증서의 폐기도 포함하므로 소비·폐기 원장에 새 행이 추가될 수 있다.
폐기된 collector의 인증서는 갱신하지 않고, 정상/실패 경로 모두 기존 스케줄과 pause를 복원한다.
격리 worktree의 관련 집중 시험180개와 Ruff는 통과했다. 이 수치는 전체2,749개와 중복 합산하지 않는다.
첫 집중 Docker 재시도는 초기 CA health 호출 중 시간 초과로 검사0개에서 끝났고,
소유 자원은0/0/0이었다. 실제 교체·복원 경계를 통과한 것으로 계산하지 않는다.
후속 집중 실행의 최종 결과는 아래 후속 기록을 따른다.

두 번째 집중 실행은 CA root/JWK/issuer 3회차, DB 전송2회차, 실제 실행기 종료4회,
정상 재시작·변조 거부까지20개를 통과한 뒤 보안 행 비교에서 실패했다. 정리는0/0/0이었다.
이 실행에서 추가한 두 번째 정상 leaf 갱신 뒤에도 갱신 전 `used_ott` 전체와 같아야 한다고
비교한 시험 기준을 보완했다. 서버 leaf 재발급은 `/1.0/sign`의 새 일회용 nonce를 소비한다.
처음에는 폐기 행의 완전 동일성과 서버 generation 증가분에 맞는 nonce 수를 검사했으나,
후속 실측에서 유지보수가 개인키 재발급·기존 client 인증서 폐기까지 수행함을 확인했다.
따라서 준비 구간에서는 **기존 소비·폐기 행의 원형을 모두 유지**해야 하며 추가 행은
관측값으로 남긴다. 준비 뒤 전체 스냅샷을 새로 고정하고, DB 교체·재시작 동안에는
그 전체 스냅샷이 정확히 같아야 한다. 기존 행 삭제·덮어쓰기·폐기 취소를 허용하지 않는다.
준비 구간의 허용된 증분을 DB 교체 구간에 적용하지 않는다.

별도 작은 계측의 첫 회차는 used_ott 50→79(추가29/삭제0), revoked_x509_certs
29→110(추가81/삭제0)이었고 server/client generation은 각각29/81 증가했다.
이 계측은 기존 폐기 원장까지 같아야 한다던 잘못된 조건에서 중단됐으며 backup은 실행되지 않았다.
해당 false·정리0/0/0을 보존한다. 생산 코드의 키 교체·폐기 동작을 끄지 않고 시험 기준을 수정했다.

또한 [step-ca v0.30.2 토큰 처리](https://github.com/smallstep/certificates/blob/v0.30.2/authority/authorize.go)는
발급 절차 완료 전에 소비 기록을 저장하므로, 발급 성공 세대 수와 nonce 수가 항상
같다는 가정을 보안 판정에 사용하지 않는다. 새 수치는 성능·공격 표본이 아닌 유지보수 관측값이다.

시간 단축을 위해 시도했던 epoch0의 DB/백업 경로는 검사7개 뒤 자식 실행기가 다음
checkpoint 전에 종료돼 실패했고, 소유 자원은0/0/0이었다. 그 실행에서는 자식 stderr를
보존하지 않아 세부 원인을 확정하지 못했다. 검증되지 않은 `--skip-authority-rotations`
옵션은 최종 소스에서 제거했다. 기존 CA 3회차 준비를 포함한 `--transport-backup-only`
경로로 돌아가 확인했다. 자식 실행기의 고정 오류 분류·저장소 코드 위치·종료코드만
원자적으로 남기고 부모가 해당 실행 token과 대조해 기록하도록 보완했다.
원문 예외·인자·지역변수·비밀값은 저장하지 않으며 그 시점에는 진단3개를 포함한 집중36개가 통과했다.
서로 다른 실행을 합쳐 전체 통합 인수에 통과했다고 표시하지 않는다.

다음 집중 실행도 초기 구동에서 검사0개로 종료됐고 정리는0/0/0이었다.
반복된 경로는 CA health를 확인하는 Docker exec의 `TimeoutExpired`가
준비 대기 predicate 밖으로 빠져나가는 것이었다. `AuthorityRuntime.before_start`의
기존30초 준비 대기에서 이 예외도 아직 준비되지 않은 상태로 처리해 재시도하도록 보완했다.
명령별 timeout·전체 준비 대기 기준·TLS/CA 시각·issued-at·만료 검증은 변경하지 않았다.
정상 건강 상태를 확인하기 전 grant를 만들지 않으며 준비되지 않으면 실패한다.
실제 timeout→불건강→정상 전이와 끝내 준비되지 않는 거부 경로를 기존 인수 시험에 추가했다.
해당20개를 포함한 최종 집중57개와 전체 Ruff가 통과했다. 최종 Docker 결과와는 별도다.

보완 뒤 CA 3회차·실행기 종료4회·DB 첫 회차는 통과했지만 준비 원장 비교에서17개로
중단된 실행도 별도로 보존한다. 이후 위 작은 계측으로 추가 폐기 행을 확인했다.
변경된 경계는 `--db-transport-backup-only`로 두 DB 교체·재시작·변조 거부·백업을
집중 검증한다. 초기 authority epoch을 고정해 유지하며 CA root/JWK/issuer 교체와
강제 종료4회를 재실행하지 않는다. 이 두 항목은 직전 실행의 성공 근거와 구분한다.

집중 환경은 CA A/B와 공유 PostgreSQL 단일 DB를 포함한18서비스다.
DB 복제·관리 호스트·격리 Docker 데몬 복구는 별도 선택 프로필이며 이번 집중 실행에서
그 장애 행렬 전체를 다시 수행하지 않았다. 같은 PC의 서비스·볼륨 격리를 물리 호스트 HA로 해석하지 않는다.

### 11/12 최종 변경 경계 검증

`--db-transport-backup-only`의 **25개 모두 통과**, `completed:true`, 종료코드0이다.
최종 사전 점검과 컨테이너·볼륨·네트워크 정리0/0/0까지 확인했다.
새 profile의 authority epoch0을 유지한 채 DB 전송 epoch1·2를 검증했다.
CA root/JWK/issuer 3회차와 DB 실행기 종료4회는 직전 실행에서 확인한 별도 근거다.
이번 모드의 `process_faults_replayed:false`는 그 DB 종료4회를 반복하지 않았다는 뜻이며,
백업 게시 후 실제 프로세스 종료 시험은 이번에도 수행했다.

- 기존 DB client의 정상 접속 후 옛 client 거부, 두 CA의 실제 DB mTLS·DB anchor를 확인했다.
- 준비 구간의 nonce11행·폐기27행 추가와 기존 두 원장의 삭제0을 관측했다.
  두 번째 DB 교체·정상 재시작·전환 기록 변조 거부 후에는 준비 후 전체 원장이 정확히 유지됐다.
- 암호화 백업 게시 후 실제 실행기 종료·같은 archive 재개, 변조 ciphertext 거부,
  network none/tmpfs PostgreSQL 복원과 보안 테이블5개 일치를 확인했다.
- 재시작 후 backup journal 유지·복원 컨테이너 잔존0, 새 archive 생성 후 첫 archive의
  독립 복원까지 확인했다. 실제 운영 DB에 과거 백업을 덮어쓰는 시험은 아니다.

원자료는 격리 worktree의 `runtime/c02/ca-transport-retest-20261111-06/verification.json`이다.
공개 요약은 이 파일의 SHA-256, 각 검사, 이전 실패·작은 계측과 최종 소스 LF 지문을 연결한다.
최종 인수 이미지: `sha256:dad59b670e6694109dea11d79c5adc3b2902cd9a1abe5a9637c84688ee95c13b`.
초기 전체 묶음의 실패를 성공으로 바꾸거나 다른 소스의 검사 수를 합산하지 않았다.

### 탐지 품질: 개선 전 기준선 유지

| 분할 | TP / FP / FN / TN | 정밀도 | 재현율 | F1 | 오탐률 |
|---|---|---|---|---|---|
| 개발360 | 170 / 50 / 10 / 130 | 77.27% | 94.44% | 85.00% | 27.78% |
| holdout360 | 90 / 50 / 90 / 130 | 64.29% | 50.00% | 56.25% | 27.78% |

정밀도·재현율·F1≥95%, 오탐률≤5% 목표는 **미달**이다. 규칙·임계값·라벨은 이번에
바꾸지 않았다. 이 결과는 Sigma 이벤트 탐지 기준선이며 LLM 또는 세션 회수 정확도가 아니다.
동일 시나리오 변형이 포함된 합성 평가이며 실제 기업 분포나 독립 외부 blind 평가가 아니다.

### 공급망 검사 후속

현재 앱·관측 이미지에 같은 갱신 DB로 Syft/Grype/Trivy 워밍업+3반복과
양성/음성 대조군을 수행했다. 최초 실행은 외부 실행기의3,600초 제한에서 중단됐고,
관측 이미지 반복 검사가 끝난 뒤 대조군 도중이었다. 원래 `completed:false`와
`verification.interrupted.json`, `summary.interrupted.json`을 보존했다.
남은 대조군을 실제 재실행하고 DB 지문·소스 고정·원본 DB 불변·이미지 내부 소스와
런타임 보안23개를 재확인한 **후속 검사**가 완료됐다. 이미지 반복 검사는 재실행하지 않았다.
후속 검사 소유 자원은0이다. 기본/확장 실행기의 실패 기록을 성공으로 덮어쓰지 않았다.

| 이미지 | Grype native 발견 | Trivy native 발견 | 검사 이미지 ID |
|---|---|---|---|
| 앱 | 209 | 209 | `sha256:bd73a09797f3744d52b2bf990a701aacf198a0e3fc752ce73c98d53a9327c210` |
| 관측 | 214 | 212 | `sha256:6d43157db19ffa87cf82a3788a36bec04d1b649797117eec5cd9c5bd45e6d5e5` |

도구별 native 항목을 더해 고유 취약점 수로 계산하지 않는다. 잔여 발견이 있으며,
앱 영향의 독립 검토·운영 승인은 남는다. 이번은 두 이미지 검사이고 PR52의 일곱 이미지
검사를 새로 반복했다고 표시하지 않는다. 이후 변경은 CA 준비 대기의 timeout 재시도·시험 도우미·Compose writable 경로·문서이므로
검사한 스냅샷과 최종 소스의 차이를 남긴다. 탐지 규칙·앱 의존성은 변경하지 않았다.
원자료는 `runtime/c03/week4-20261111-final1/verification.json`과 각 이미지의
`summary.json`, `proof.json`, `review.json`이다.

### 재현 명령과 남은 인수

기본 묶음 뒤 같은 검증 단계에서 다음 기존 실행기도 순차 실행했다.
실행 시간이 긴 전체 시험을 각 기능 변경마다 반복하지 않았다.

```powershell
.venv\Scripts\python.exe -m scripts.test_infra_selection_runtime --directory runtime/c02/infra-batches/week4-20261111-final1/selection
.venv\Scripts\python.exe -m scripts.test_recoverable_mtls_runtime --directory runtime/c02/infra-batches/week4-20261111-final1/app-restore
.venv\Scripts\python.exe -m scripts.evaluate_detection_benchmark --output-dir runtime/c02/infra-batches/week4-20261111-final1/detection-quality --require-targets
.venv\Scripts\python.exe -m scripts.test_current_supply_chain_runtime --directory runtime/c03/week4-20261111-final1
.venv\Scripts\python.exe -m scripts.test_database_backup_runtime --db-transport-backup-only --directory runtime/c02/week4-db-backup-replay
```

위 경로는 이미 사용했으므로 재현 시에는 새 경로를 지정한다. 품질 gate의 종료코드1은
관측된 목표 미달이며 시험 실행기 고장으로 숨기지 않는다.
최초 기본/확장 묶음의 `completed:false`는 보존하고 후속 결과를 별도로 연결한다.
AWS·유료 API 호출은0이며 공개 다운로드를 포함한 로컬 검증이다.

남은 인수는 팀원의 독립 실행·라벨 확인, 새 모델의 동일 조건 실측,
C01~C10 최종 결정과 운영 승인, M8 최종 동결 승인이다. 실제 기업 IdP/EDR·AWS 수신,
물리 호스트 장애까지 이 로컬 결과로 대체하지 않는다. 이번 Codex 구현·도구 실행을
김택희의 직접 수행이나 독립 검토 완료로 기재하지 않는다.
