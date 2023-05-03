import os
import json
import subprocess
from uuid import uuid5
from time import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel
from tldextract import TLDExtract

import internals
import models
import services.aws
import services.webhook


class EventAttributes(BaseModel):
    ApproximateReceiveCount: int
    SentTimestamp: datetime
    SenderId: str
    ApproximateFirstReceiveTimestamp: datetime


class EventRecord(BaseModel):
    messageId: str
    receiptHandle: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str
    hostname: str
    ports: list[int]
    type: models.ScanRecordType
    md5OfBody: str
    path_names: list[str]
    attributes: EventAttributes
    account_name: str
    queued_by: Optional[str]
    queued_timestamp: datetime

    def __init__(self, **kwargs):
        body = json.loads(kwargs["body"])
        kwargs["account_name"] = kwargs["messageAttributes"]["account"]["stringValue"]
        kwargs["path_names"] = body.get("path_names", ["/"])
        if kwargs["messageAttributes"].get("queued_by"):
            kwargs["queued_by"] = kwargs["messageAttributes"]["queued_by"]["stringValue"]
        kwargs["queued_timestamp"] = int(kwargs["messageAttributes"]["queued_timestamp"]["stringValue"])
        kwargs["hostname"] = body['hostname']
        kwargs["ports"] = body.get('ports', [body.get("port", 443)])
        kwargs["type"] = body['type']
        super().__init__(**kwargs)


def handler(event, context):
    for _record in event["Records"]:
        record = EventRecord(**_record)
        internals.logger.info(f"Triggered by {record}")
        account = models.MemberAccount(name=record.account_name)
        if not account.load():
            internals.logger.info(f"Missing account {record.account_name}")
            services.aws.complete_sqs(
                queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                receipt_handle=record.receiptHandle,
            )
            continue
        scanner_record = models.ScannerRecord(account_name=account.name)  # type: ignore
        if not scanner_record.load():
            scanner_record = models.ScannerRecord(account_name=account.name)

        tld = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{record.hostname}")
        if tld.registered_domain != record.hostname:
            internals.logger.info(f"Not an Apex domain {record.hostname}")
            services.aws.complete_sqs(
                queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                receipt_handle=record.receiptHandle,
            )
            continue
        checkpoint_path = f"{internals.APP_ENV}/checkpoints/subdomains/{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}/{record.hostname}"
        if services.aws.object_exists(checkpoint_path):
            internals.logger.info(f"Already processed today {record.hostname}")
            services.aws.complete_sqs(
                queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                receipt_handle=record.receiptHandle,
            )
            continue

        internals.logger.info(f"PROCESSING {record.hostname}")
        executable = os.path.realpath(os.path.join(os.path.dirname(__file__), 'vendored', 'amass', 'amass'))
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            internals.logger.error(f"Not executable {executable}")
            services.aws.complete_sqs(
                queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                receipt_handle=record.receiptHandle,
            )
            continue
        config_path = os.path.realpath(os.path.join(os.path.dirname(__file__), 'amass.ini'))
        word_list = os.path.realpath(os.path.join(os.path.dirname(__file__), 'vendored', 'amass', internals.AMASS_WORD_LIST))
        output_file = f'{internals.CACHE_DIR}/amass_{record.hostname}.json'
        params = [
            executable,
            'enum',
            '-nocolor',
            '-config',
            config_path,
            '-json',
            output_file,
            '-timeout',
            internals.AMASS_TIMEOUT,
            '-w',
            word_list,
            '-d',
            record.hostname
        ]
        internals.logger.info(f"Executing {' '.join(params)}")
        proc = subprocess.run(params, check=False, capture_output=True)
        internals.logger.info(proc.stdout.decode('utf-8').strip())
        if console_output := proc.stderr.decode('utf-8').strip():
            if console_output.endswith("Discoveries are being migrated into the local database"):
                internals.logger.info(console_output)
            else:
                internals.logger.error(console_output)
                services.aws.complete_sqs(
                    queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                    receipt_handle=record.receiptHandle,
                )
                continue

        result_json = Path(output_file)
        if not result_json.exists():
            internals.logger.warning("No results")
            services.aws.complete_sqs(
                queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                receipt_handle=record.receiptHandle,
            )
            continue
        for line in result_json.read_text(encoding='utf8').strip().splitlines():
            try:
                result = json.loads(line.strip())
            except json.decoder.JSONDecodeError:
                internals.logger.error(f"JSONDecodeError {line}")
                services.aws.complete_sqs(
                    queue_name=f'{internals.APP_ENV.lower()}-subdomains',
                    receipt_handle=record.receiptHandle,
                )
                continue
            for address in result.get("addresses", []):
                item = models.ObservedIdentifier(
                    id=uuid5(namespace=internals.NAMESPACE, name=f"{account.name}{address['ip']}{address.get('asn')}"),
                    account_name=account.name,
                    source=models.ObservedSource.OSINT,
                    source_data={
                        'hostname': result.get("name"),
                        'cidr': address.get("cidr"),
                        'asn': address.get("asn"),
                        'asn_desc': address.get("desc"),
                        'sources': ",".join(result.get("sources", [])),
                    },
                    address=address['ip'],
                    date=datetime.now(timezone.utc).timestamp() * 1000
                )
                services.aws.put_dynamodb(
                    table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                    item=item.dict()
                )
            if result.get("name") == record.hostname:
                continue
            internals.logger.info(f"Found {result}")
            ports = [443]
            path_names = ["/"]
            for monitor_host in scanner_record.monitored_targets:
                if monitor_host.hostname == result.get('name'):
                    ports = monitor_host.ports
                    path_names = monitor_host.path_names
                    break

            queue_name = f"{internals.APP_ENV.lower()}-reconnaissance"
            queued_timestamp = round(time() * 1000)  # JavaScript support
            internals.logger.info(f"queue {queue_name} {result.get('name')}")
            services.aws.store_sqs(
                queue_name=queue_name,
                message_body=json.dumps(
                    {
                        "hostname": result.get("name"),
                        "ports": ports,
                        "path_names": path_names,
                        "type": models.ScanRecordType.INTERNAL,
                    },
                    default=str,
                ),
                deduplicate=False,
                account=account.name,
                queued_timestamp=queued_timestamp,
            )
            services.webhook.send(
                event_name=models.WebhookEvent.HOSTED_SCANNER,
                account=account,
                data={
                    "hostname": result.get("name"),
                    "ports": ports,
                    "http_paths": path_names,
                    "type": models.ScanRecordType.SUBDOMAINS,
                    "status": "queued",
                    "account": account.name,
                    "queued_timestamp": queued_timestamp,
                    "addresses": result.get("addresses"),
                    "sources": result.get("sources"),
                },
            )
        services.aws.store_s3(checkpoint_path, '1')
        services.aws.complete_sqs(
            queue_name=f'{internals.APP_ENV.lower()}-subdomains',
            receipt_handle=record.receiptHandle,
        )
