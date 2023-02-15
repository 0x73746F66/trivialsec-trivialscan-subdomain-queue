import json
import hmac
import uuid
import hashlib
from datetime import timezone, datetime

import validators

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
                account_name=account.name
            )


def _sign_and_send(
    event_name: models.WebhookEvent,
    webhook: models.Webhooks,
    data: dict,
    account_name: str,
    algorithm: str = "sha3_512",
):
    def _make_header(identifier: str, mac: str, ts: int, alg: str = "sha3_512"):
        """
        Never hint the alg when signed requests purpose is for real
        authorization. This is fine, and helpful, for webhooks.
        """
        return f'HMAC id="{identifier}", mac="{mac}", ts="{ts}", alg="{alg}"'

    payload = models.WebhookPayload(
        event_id=uuid.uuid4(),
        event_name=event_name,
        timestamp=datetime.now(timezone.utc),
        payload=data,
    )
    raw_body = json.dumps(payload.dict(), cls=internals.JSONEncoder)
    unix_ts = round(datetime.now(timezone.utc).replace(microsecond=0).timestamp() * 1000)
    client_mac = internals.HMAC(
        authorization_header=_make_header(account_name, "na", unix_ts),
        request_url=str(webhook.endpoint),
        method="POST",
        raw_body=raw_body,
        algorithm=algorithm,
    )
    client_mac = hmac.new(
        webhook.signing_secret.encode("utf8"),  # type: ignore
        client_mac.canonical_string.encode("utf8"),
        hashlib.sha3_512,
    ).hexdigest()
    services.aws.store_s3(f"{internals.APP_ENV}/accounts/{account_name}/webhooks/{payload.event_name}/{payload.event_id}.json", json.dumps(data, cls=internals.JSONEncoder))
    internals.post_beacon(
        url=webhook.endpoint,
        body=payload.dict(),
        headers={
            "Authorization": _make_header(account_name, client_mac, unix_ts, algorithm),
            "User-Agent": "Trivial Security signed webhook",
        },
    )
