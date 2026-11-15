# M7 공개 인증 로그 파일럿

KREONET / KAFE Research의 OIDC 및 SAML 기반 공개 합성 인증 로그에서 개발용과 평가용 세션을 준비했다. 게시자 원본은 130,767개 이벤트와 22,750개 인증 흐름을 담고 있다. 원본 91,592,665바이트의 SHA-256은 `445f69377a2e12b4203a68f15cd9a4013fbc7e0ef21c19843969f671b1334a30`이다. 고정 리비전, 원본 링크, 라이선스와 라벨별 원본 세션 수는 [출처 계약](../infra/m7/source.json)에 기록했다. 배포하는 파생 자료에는 [CC BY 4.0 출처 표시](../infra/m7/NOTICE.md)를 적용한다.

| 분할 | 정상 세션 | 위협 세션 | 이벤트 |
| --- | ---: | ---: | ---: |
| 개발 | 12 | 12 | 146 |
| 평가 | 12 | 12 | 138 |

## 세션 분할과 라벨

- 게시자의 `trace_id`를 기준으로 한 인증 흐름 전체를 한 세션으로 묶는다. 이벤트는 시각과 원본 줄 번호 순서로 정렬한다. 같은 세션에서 게시자의 라벨, 범주, 하위 범주가 다르면 원본을 거부한다.
- 게시자 라벨 `benign`은 정상, `attack`은 위협으로 매핑한다. `anomaly`로 표시된 4,089개 원본 세션은 정상이나 위협으로 합치지 않고 이진 분류 파일럿에서 제외한다.
- 2026년 3월 1일 00:00 KST 이전에 끝난 세션은 개발 후보, 이 시각부터 시작한 세션은 평가 후보로 둔다. 경계를 걸치는 세션은 선택에서 제외한다. 정상 계열은 게시자 범주, 위협 계열은 하위 범주를 포함한 계열 지문으로 분할한다.
- 평가 후보가 개발셋의 사용자, 대리 행위자, 클라이언트 IP 지문과 겹치면 제외한다. IP는 연결 중복을 줄이는 데 사용하는 보조 기준이며 원본에는 별도의 기기 ID가 없다. 이벤트의 모듈, HTTP 메서드, 상태 코드, 로그 수준의 순서가 같은 세션은 지연 값이나 식별자가 달라도 한 번만 선택한다.
- 변환 결과에서 세션, 이벤트 지문, 사용자와 대리 행위자, 클라이언트, 계열, 신호 패턴의 분할 간 중복은 각각 0건이다. 분할 검증의 범위는 이번에 고른 표본과 입력 변환 과정이다. 게시자 원본과 라벨은 공개 자료다. 게시자 라벨의 독립 검토와 최종 평가셋 동결은 후속 작업이다. [파일별 해시와 검증 결과](../infra/m7/pilot/manifest.json)

`development.jsonl`과 `evaluation.jsonl`에는 세션 ID, 순서대로 배열한 관측값, 근거 이벤트 ID가 들어간다. `labels.jsonl`에는 기대 라벨과 게시자 라벨, 원본 줄 위치와 시각, 지문이 들어간다. 모델에는 관측값과 근거 ID를 전달하고, 점수를 계산할 때 별도 라벨 파일을 세션 ID로 대조한다. 원본의 계정과 IP, 메시지, 페이로드, `event_type`은 모델 입력에서 제외한다. 공개 합성 자료에서 고른 균형 표본이므로 운영 트래픽의 클래스 비율이나 실제 탐지 성능은 별도 평가가 필요하다.

## 재현과 검증

저장소 루트에서 배포된 파일의 해시와 분할을 확인한다. 이 명령은 네트워크 없이 실행한다.

```sh
python -m scripts.prepare_m7 verify --directory infra/m7/pilot
```

원본으로부터 배포된 파일까지 대조하려면 고정 리비전에서 원본을 받아 실행한다. `prepare`의 출력에는 새 디렉터리를 사용한다.

```sh
mkdir -p runtime/m7
curl --fail --location \
  https://raw.githubusercontent.com/KREONET/auth-anomaly-dataset/5fd5cae2001a6b67cafb952709db37e366cfa276/iam_anomaly_2026.jsonl \
  --output runtime/m7/iam_anomaly_2026.jsonl
python -m scripts.prepare_m7 prepare --source runtime/m7/iam_anomaly_2026.jsonl \
  --directory runtime/m7/prepared
python -m scripts.prepare_m7 verify --source runtime/m7/iam_anomaly_2026.jsonl \
  --directory infra/m7/pilot
```

원본을 지정한 검증은 원본 SHA-256을 확인하고 `m7-auth-pilot-1` 형식으로 다시 변환하여 배포된 파일의 바이트와 비교한다.

## 개발셋 모의 실행

저장소 루트에서 M6 실행기에 M7 파일럿 디렉터리를 지정한다.

```sh
python -m scripts.evaluate_m6 --m7-development infra/m7/pilot
python -m scripts.evaluate_m6 --m7-development infra/m7/pilot --max-requests 3 \
  --output runtime/m6/m7-development-request-limit.json
```

실행기는 개발셋과 라벨 파일의 SHA-256을 매니페스트와 대조한다. 두 모의 후보는 개발셋 24세션에 포함된 이벤트 146건의 관측값과 근거 ID를 세션별로 같은 순서로 받는다. 개발셋의 기준 라벨은 세션 ID로 대조해 로컬 집계에만 사용한다. 평가셋은 독립 라벨 검토를 마친 뒤 모델 비교에 사용한다.

기본 결과 경로는 `runtime/m6/m7-development.json`이다. 세션별 판정과 실패 상태, 후보별 집계, 입력 파일의 해시를 기록한다. 실제 공급자 호출 수와 비용은 0이다. 동결된 Sigma 규칙 기준선은 [기존 M6 벤치마크 모의 실행](m6-evaluation-contract.md#오프라인-모의-평가-실행)에서 집계한다.

### 관측값 보강 모의 실행

고정 리비전의 원본 로그를 내려받았다면 `--m7-source`로 보강 모드를 실행한다. 이 옵션을 생략하면 기본 개발셋 모의 실행 경로를 사용한다.

```sh
python -m scripts.evaluate_m6 --m7-development infra/m7/pilot \
  --m7-source runtime/m7/iam_anomaly_2026.jsonl
```

전체 원본을 스트리밍해 출처 계약에 기록된 크기와 SHA-256을 검증한다. 개발셋 24세션의 이벤트 146건에 해당하는 원본 줄만 해석한다. 각 줄의 해시와 관측값, 집계에 쓰는 라벨을 원본과 대조하고 다음 필드를 추가한다.

| 필드 | 의미 |
| --- | --- |
| `auth_stage` | 인증 흐름에서 관측된 단계를 정해진 코드로 표현한다. 인식할 수 없는 단계는 `unknown`이다. |
| `failure_reason` | 관측된 실패 사유를 허용 목록의 운영 코드로 표현한다. 대응하는 코드가 없으면 `null`이다. |
| `since_previous_ms` | 같은 세션의 직전 이벤트 기록 시각과의 차이를 밀리초로 내림한다. 첫 이벤트는 `null`이고 시각이 같으면 0이다. |

두 후보에 기존 관측값과 근거 ID, 보강된 세 필드를 같은 순서로 전달한다. 게시자 라벨과 시나리오 범주, 원본 추적 ID, 원본 이벤트 종류, 계정, IP, 절대 시각, 페이로드는 로컬에 둔다. 보강 전 개발셋, 보강한 입력, 원본의 SHA-256을 결과에 기록한다. 기본 결과는 `runtime/m6/m7-enriched-development.json`이며 실제 공급자 호출과 비용은 0이다.

기기 인증 단계를 알아도 기기 코드와 요청 주체의 연결이나 토큰 발급 결과는 별도 관측이 필요하다. 보강 방식 검토에 사용한 사례와 별개로 평가 자료를 준비해 최종 성능을 확인한다.

## 최종 평가용 새 표본 준비

고정된 게시자 원본과 기존 파일럿을 지정해 새 디렉터리에 표본을 만든다. `verify`는 같은 원본에서 표본을 다시 생성해 저장된 파일과 바이트 단위로 대조한다.

```sh
python -m scripts.prepare_m7_holdout prepare --source runtime/m7/iam_anomaly_2026.jsonl \
  --pilot infra/m7/pilot --directory runtime/m7/final-holdout
python -m scripts.prepare_m7_holdout verify --source runtime/m7/iam_anomaly_2026.jsonl \
  --pilot infra/m7/pilot --directory runtime/m7/final-holdout
```

2026년 3월 1일 00:00 KST 이후에 시작한 인증 세션에서 정상 12건과 위협 12건을 고른다. 각 세션의 이벤트는 최대 8건이다. 기존 개발셋 및 검토한 평가셋 각각과 세션 ID, 사용자와 대리 행위자 지문, 클라이언트 지문, 원본 기록, 기본 신호 패턴의 중복을 검사한다. 위협 계열은 두 분할에서 사용한 계열을 제외한다. 정상 계열은 겹칠 수 있으며 매니페스트에 중복 수를 기록한다.

| 파일 | 용도 |
| --- | --- |
| `observations.jsonl` | 세션 ID와 순서대로 정리한 보강 이벤트다. 모델 입력에는 이 파일의 관측값과 근거 ID를 사용한다. |
| `scoring-labels.jsonl` | 세션 ID로 연결되는 잠정 게시자 라벨이다. 로컬에서 채점할 때 사용하며 확정 전 검토가 필요하다. |
| `manifest.json` | 원본과 산출물의 해시, 표본 수, 기존 두 분할과의 중복 검사 결과를 기록한다. |
| `NOTICE.md` | 원본 출처, CC BY 4.0 라이선스와 변환 내용을 기록한다. |

보강 이벤트는 개발셋과 같은 허용 필드로 구성한다. `verify`는 고정 원본과 선택 규칙으로 관측값과 채점 라벨을 따로 재현해 정답이나 원본 필드가 모델 입력에 섞였는지 확인한다. 이 명령의 검증 범위는 표본 선정과 입력 분리이며, 모델 호출은 0건이다.

## 로컬 OIDC 토큰 검증 자료

별도 로컬 실험에서 정상과 위협 각각 10개 시나리오를 10회씩 실행한다. 실험 주체, 자격 증명과 대상의 권한 관계로 라벨을 사전 선언한다. 정상 사용자의 거절과 복제된 유효 자격 증명의 성공을 모두 포함한다.

```sh
python -m scripts.prepare_m7_local prepare --directory runtime/m7/local-oidc-evaluation
python -m scripts.prepare_m7_local verify --directory runtime/m7/local-oidc-evaluation
```

로컬 JWKS로 앱의 OIDC bearer 검증, 서명된 허용 발급, 보호 자원 접근을 실행한다. `private/plan.jsonl`을 요청 전에 저장한다. `private/evidence.jsonl`은 인증된 주체, HTTP 결과, 콘텐츠 반환, 저널 일치 여부를 기록하고, `private/scoring-labels.jsonl`은 로컬 채점에 쓴다.

모델 입력은 `observations.jsonl`의 보강 관측값이다. 실행 순서와 분리된 검토 ID를 사용한다. 로컬 요청 처리 시간은 기록하고 실험 제어기의 이벤트 간격은 채점 근거 파일에 둔다. 매니페스트에는 기존 세 코호트와의 ID 중복, 클래스별 실제 HTTP 결과, 두 라벨에서 공유하는 관측 패턴 수가 남는다. `verify`는 보관된 계획과 관측 근거로 입력 및 라벨을 다시 만들고 저장본과 대조한다.
