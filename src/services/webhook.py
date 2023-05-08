import json
import uuid
from datetime import timezone, datetime, timedelta

import validators
import jwt

import internals
import models
import services.aws


def send(event_name: models.WebhookEvent, account: models.MemberAccount, data: dict):
    for webhook in account.webhooks:  # type: ignore pylint: disable=not-an-iterable
        if not hasattr(webhook, event_name.value):
            internals.logger.warning(f"Invalid webhook event {event_name}")
            continue
        if not webhook.endpoint or validators.url(webhook.endpoint) is not True:  # type: ignore
            continue
        internals.logger.info(f"Webhook enabled for {account.name}")
        if getattr(webhook, event_name.value) is True:
            internals.logger.info(f"Sending webhook event {event_name}")
            _sign_and_send(
                event_name=event_name,
                webhook=webhook,
                data=data,
                account_name=account.name,
            )


def _sign_and_send(
    event_name: models.WebhookEvent,
    webhook: models.Webhooks,
    data: dict,
    account_name: str,
):
    payload = models.WebhookPayload(
        event_id=uuid.uuid4(),
        event_name=event_name,
        timestamp=datetime.now(timezone.utc),
        payload=data,
    )
    raw_body = json.dumps(payload.dict(), cls=internals.JSONEncoder)
    internals.logger.debug(f"raw_body {raw_body}")
    services.aws.store_s3(
        f"{internals.APP_ENV}/accounts/{account_name}/webhooks/{payload.event_name}/{payload.event_id}.json",
        raw_body,
    )
    self_contained_token = jwt.encode(
        payload={
            # mandatory claims
            "iat": datetime.now(tz=timezone.utc),
            "nbf": datetime.now(tz=timezone.utc) + timedelta(seconds=3),
            "exp": datetime.now(tz=timezone.utc) + timedelta(days=1),
            "aud": [f"urn:trivialsec:webhook:client_endpoint:{account_name}"],
            "iss": internals.DASHBOARD_URL,
            "sub": internals.NAMESPACE.hex,
            # custom claims
            "cep": webhook.endpoint,
            "eid": payload.event_id.urn,
            "evn": payload.event_name.value,
        },
        key=webhook.signing_secret.encode("utf8"),  # type: ignore
        algorithm="HS256",
    )
    internals.trace_tag({payload.event_id.hex: f"urn:trivialsec:webhook:{account_name}:{event_name.value}"})
    internals.post_beacon(
        url=webhook.endpoint,
        body=payload.dict(),
        headers={
            "Authorization": self_contained_token,
            "User-Agent": "Trivial Security",
        },
    )
