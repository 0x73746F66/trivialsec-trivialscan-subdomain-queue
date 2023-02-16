import json
import subprocess
from time import time
from os import path, getcwd
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
            continue
        scanner_record = models.ScannerRecord(account=account)  # type: ignore
        if not scanner_record.load():
            scanner_record = models.ScannerRecord(account=account)

        tld = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{record.hostname}")
        if tld.registered_domain != record.hostname:
            internals.logger.info(f"Not an Apex domain {record.hostname}")
            continue
        checkpoint_path = f"{internals.APP_ENV}/checkpoints/subdomains/{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}/{record.hostname}"
        if services.aws.object_exists(checkpoint_path):
            internals.logger.info(f"Already processed today {record.hostname}")
            continue

        internals.logger.info(f"Processing {record.hostname}")
        executable = path.realpath(path.join(getcwd(), 'vendored', 'amass', 'amass'))
        config_path = path.realpath(path.join(getcwd(), 'amass.ini'))
        word_list = path.realpath(path.join(getcwd(), 'vendored', 'amass', internals.AMASS_WORD_LIST))
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
        if err := proc.stderr.decode('utf-8').strip():
            internals.logger.error(err)
            continue
        result_json = Path(output_file)
        if not result_json.exists():
            internals.logger.warning("No results")
            continue
        for line in result_json.read_text(encoding='utf8').strip().splitlines():
            try:
                result = json.loads(line.strip())
            except json.decoder.JSONDecodeError:
                internals.logger.error(f"JSONDecodeError {line}")
                continue
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
