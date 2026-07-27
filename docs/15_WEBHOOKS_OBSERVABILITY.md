# 웹훅과 관측성

## 아웃박스 구조

상태변화가 발생하면 외부 URL을 즉시 호출하기 전에 SQLite `webhook_events` 테이블에 이벤트를 기록합니다.

```text
PENDING → SENDING → DELIVERED
              └→ RETRY → SENDING
                       └→ FAILED
```

- 전송 작업은 원자적으로 이벤트를 선점합니다.
- `SENDING` 임대가 만료되면 프로세스 중단으로 판단하고 `RETRY`로 복구합니다.
- 재시도 간격은 1, 2, 4, 8분 방식으로 증가하며 최대 60분입니다.
- HTTP 리다이렉트는 따르지 않습니다.
- 완료·최종실패 이력만 보존정책으로 삭제하며 PENDING·RETRY·SENDING은 삭제하지 않습니다.

## 설정

```json
{
  "ops": {
    "url": "https://receiver.example/vulnflow",
    "secret": "long-shared-secret",
    "events": ["finding.workflow_changed", "risk_acceptance.requested"]
  }
}
```

`events`에 `*`를 지정하면 모든 지원 이벤트를 받습니다.

지원 이벤트:

- `import.completed`
- `intelligence.refreshed`
- `finding.workflow_changed`
- `risk_acceptance.requested`
- `risk_acceptance.decided`
- `maintenance.completed`

## 서명 검증

전송 본문은 UTF-8 JSON이며 다음 헤더가 포함됩니다.

- `X-VulnFlow-Event-ID`
- `X-VulnFlow-Event-Type`
- `X-VulnFlow-Signature: sha256=<hex>`

검증식:

```text
HMAC-SHA256(webhook_secret, raw_request_body)
```

파싱된 JSON을 다시 직렬화한 값이 아니라 **수신한 원문 바이트**를 검증해야 합니다.

## 요청 추적

- 요청의 `X-Request-ID`가 안전한 형식이면 유지합니다.
- 없거나 형식이 잘못되면 새 ID를 생성합니다.
- 모든 응답에 `X-Request-ID`를 반환합니다.
- JSON 로그에 요청 ID, 경로, 상태, 지연시간, 사용자·역할을 기록합니다.

## 상태·메트릭

인증 예외 최소정보 상태:

- `/health/live`
- `/health/ready`
- `/health`

인증 필요 Prometheus 텍스트 메트릭:

- `/metrics`
- 요청 수와 누적 처리시간
- 현재 취약점 수
- 대기 웹훅 수
- 웹훅 전송 결과 수

메트릭은 단일 프로세스 메모리에 존재하므로 다중 프로세스 합산이나 장기 보존은 외부 수집기가 담당해야 합니다.


## 43.0 전송 시도 영수증

각 webhook 전송 시도는 `WEBHOOK_DELIVERY` receipt를 생성합니다. 전송 성공은 `DELIVERED`, 재시도 예정은 `RETRY`, 영구 실패는 `FAILED`로 기록됩니다. payload·오류 원문은 receipt에 저장하지 않습니다. 최종 실패 receipt는 관리자 사유와 함께 새 webhook event로 한 번 replay할 수 있습니다.
