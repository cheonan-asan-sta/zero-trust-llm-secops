# M7 자료 출처와 이용 조건

`pilot/`은 KREONET / KAFE Research가 공개한 **IAM Anomaly Detection Dataset 2026**의 일부를 세션별로 정리한 파생 자료다. Copyright (c) 2026 KAFE Research. 이 자료는 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) 조건으로 제공된다. [공개 데이터와 형식 설명](https://github.com/KREONET/auth-anomaly-dataset/tree/5fd5cae2001a6b67cafb952709db37e366cfa276), [게시자 라이선스](https://github.com/KREONET/auth-anomaly-dataset/blob/5fd5cae2001a6b67cafb952709db37e366cfa276/LICENSE)

변환 과정에서 공개 합성 이벤트를 `trace_id`별로 묶고 시간과 시나리오 계열로 분할했다. 허용된 관측 필드만 입력에 남겼으며, 식별자는 지문으로 바꾸고 게시자 라벨과 원본 줄 위치를 별도 파일에 기록했다. 전체 원본의 고정 리비전과 해시는 [source.json](source.json)에 기록되어 있다.
