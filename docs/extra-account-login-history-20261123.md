# 인증 결과와 계정별 선행 로그인 이력 연결

`extra` · 로컬 Keycloak 연동 · 독립 공개 RBA 재생.

## 동작

로컬 Keycloak의 `LOGIN`·`LOGIN_ERROR` 감사 이벤트를 읽어, realm의 고유 ID와 OAuth 클라이언트, 공급자의 신원 ID가 일치하는 행을 묶는다. 성공한 현재 로그인은 서명·발급자·수신자·만료를 확인한 OTP 토큰의 주체와 세션에 정확히 일치해야 한다. 동일한 시간에 여러 결과가 있거나 앞선 이벤트에 계정이 빠지면 기존 경보를 유지한다. 다른 계정, 미래 결과, 갱신 토큰으로 대체하지 않는다. 결과에 사용자 ID, 세션 ID, 원본 주소, 토큰, 비밀번호를 출력하지 않는다. [Keycloak 이벤트 API](https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealm_events)

기존 반복 실패 규칙의 3회 기준을 같은 계정의 10분 이력으로 재현했다. 현재 성공과 직전 24시간 안의 성공이 같은 기록상 출발 주소에서 발생했고 그 직전 성공 이후의 실패가 없을 때, 반복 실패 경보만 완화하는 후보를 비교했다. 이때 출발 주소는 이력 비교 신호다. 기기 신뢰나 사용자 확인을 대신하지 않는다. 첫 성공·새 주소·새 실패·결측·독립적인 위험 경보에서는 기존 판단을 유지한다. 운영 위험 점수, 접근 허용, 세션 회수에는 연결하지 않았다.

## 독립 공개 평가

RBA v2의 ZIP SHA-256·CSV SHA-256·ZIP CRC를 확인했다. 공개 로그인 이력은 실서비스 통계에 맞춰 합성한 자료다. 이미 고정한 사용자 분할의 예약 계정 647,026개 전체를 사용했다. 이전 개발 검토에 사용한 계정은 제외했다. 별도 원본에서 가져온 로그인 결과와 계정 참조를 이용했고, 시간대가 없는 기록은 같은 기록 시계의 상대 순서와 간격으로만 비교했다. ATO 정답은 별도 파일에 보관하고 예측 파일을 봉인한 뒤 점수 계산에서 결합했다. [공개 RBA 원본](https://zenodo.org/records/6782156) · [기존 사용자 분할 감사](extra-rba-metadata-audit.md)

| 동일 평가 범위 | 기존 반복 실패 경보 | 계정 이력 후보 | 변화 |
| --- | ---: | ---: | ---: |
| 성공 로그인 1,879,300건의 오탐 | 4,606건 | 3,627건 | 979건 감소 · 21.25% 감소 |
| 성공 로그인 오탐률 | 0.2451% | 0.1930% | −0.0521%p |
| 전체 2,575,003건의 오탐 | 33,794건 | 32,815건 | 979건 감소 |
| 전체 오탐률 | 1.3124% | 1.2744% | −0.0380%p |
| 계정 탈취 탐지 | 0/26건 | 0/26건 | 미탐 26건 유지 |
| 정밀도 · 재현율 · F1 | 각각 0% | 각각 0% | 95% 목표 미달 |

새 오탐은 0건이고 두 방식의 실패 로그인 경보 수는 29,188건으로 같았다. 기존 탐지 손실도 0건이며, 이 데이터에서 반복 실패 기준이 애초에 잡은 ATO가 없었다. 미표식 사례에 확인되지 않은 공격 시도가 포함될 수 있으므로, 여기서 오탐은 발행자의 ATO 정답에 대한 수치다. 오탐률 5% 조건만 충족했고 운영 적용은 보류한다.

앞선 공개 crAPI·VAmPI 성공 POST 5,216건에는 이 후보에 필요한 인증원 감사 이벤트와 검증된 계정 연결이 없다. 결측을 넣어 재생한 결과 모든 기존 웹 모델·CRS 판정이 그대로 반환됐다. 해당 웹 평가 지표의 개선은 미측정이다. [기존 웹 성능과 자료 범위](extra-public-post-crs-rules-transfer-20261123.md)

## 로컬 Keycloak 통합 확인

기존 로컬 Keycloak 26.8.0 이미지에서 첫 성공 전 `LOGIN_ERROR` 3건, 앞선 `LOGIN` 1건, 현재 `LOGIN`의 검증된 세션 일치를 확인했다. 같은 출발 주소의 후속 성공에서 반복 실패 경보만 해제했고, 독립 위험 경보는 유지했다. 기존 잘못된 OTP·누락 OTP·범위 밖 접근 거부와 역할 제거·로그아웃 뒤 토큰 거부도 통과했다. 첫 통합 실행에서는 후속 OTP를 기다리는 동안 이전 실패 신호의 유효 시간이 지나 기존 확인이 실패했다. 실패 신호 검증을 앞으로 옮겨 재실행했고 전체 통합 시험 통과와 시험 컨테이너 제거를 확인했다.

## 재현

기존에 고정한 RBA ZIP과 [개발 probe 기록](extra-rba-acquisition-and-probe.md)을 사용한다. 원본 CSV를 파일로 풀지 않고 스트리밍으로 관측과 정답을 분리한다. 전체 31,269,264행을 검사한 뒤 예약 행 2,575,003건만 추출한다. 개별 관측·예측·정답은 Git이 무시하는 `runtime` 아래에 보관한다.

```powershell
go run scripts/experiments/rba_login_projection/main.go <rba.zip> <probe.json> <projection-output>
python -m scripts.evaluate_public_login_history <projection-output> <new-evaluation-output>
python -m scripts.evaluate_public_login_history <projection-output> <new-evaluation-output> --score-seal <seal-sha256>
python -m scripts.run_keycloak_remote_acceptance <new-keycloak-report.json>
```

최종 코드로 RBA 전체 예측을 다시 실행해 봉인 SHA-256이 일치하는지 확인했다. 관련 회귀 135개와 Ruff를 통과했다. 유료 API 및 AWS 호출은 0회다. [집계와 검증 기록](infrastructure-results/account-login-history-20261123.json)
