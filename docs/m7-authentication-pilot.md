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

`development.jsonl`과 `evaluation.jsonl`에는 세션 ID, 순서대로 배열한 관측값, 근거 이벤트 ID가 들어간다. `labels.jsonl`에는 기대 라벨과 게시자 라벨, 원본 줄 위치와 시각, 지문이 들어간다. 모델에는 관측 파일만 전달하고, 점수를 계산할 때 별도 라벨 파일을 세션 ID로 대조한다. 원본의 계정과 IP, 메시지, 페이로드, `event_type`은 모델 입력에서 제외한다. 공개 합성 자료에서 고른 균형 표본이므로 운영 트래픽의 클래스 비율이나 실제 탐지 성능은 별도 평가가 필요하다.

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

원본을 지정한 검증은 원본 SHA-256을 확인하고 `m7-auth-pilot-1` 형식으로 다시 변환하여 배포된 파일의 바이트와 비교한다. 기존 공개 재현 표본과 합성 벤치마크, M6 비교 실행기는 각자의 입력을 계속 사용한다.
