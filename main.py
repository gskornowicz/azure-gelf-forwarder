import os
import json
import socket
import asyncio
import logging
import dataclasses
from datetime import datetime, timezone
from dateutil.parser import isoparse
from dotenv import load_dotenv
import aiohttp
from azure.eventhub.aio import EventHubConsumerClient
from azure.eventhub.extensions.checkpointstoreblobaio import BlobCheckpointStore
from azure.identity.aio import DefaultAzureCredential

# Load environment variables from .env file
load_dotenv()

log_level = os.getenv("LOG_LEVEL", "WARNING").upper()

# Configure logging
logging.basicConfig(
    level=getattr(logging, log_level, logging.WARNING),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configure email handler if SMTP settings are provided
smtp_host = os.getenv("SMTP_HOST")
smtp_port = int(os.getenv("SMTP_PORT", "587"))
smtp_from = os.getenv("SMTP_FROM")
smtp_to = os.getenv("SMTP_TO")  # Comma-separated list of recipients
smtp_subject = os.getenv("SMTP_SUBJECT", "Azure Logs Forwarder - Error Alert")
smtp_username = os.getenv("SMTP_USERNAME")
smtp_password = os.getenv("SMTP_PASSWORD")
smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
smtp_use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"  # For port 465
smtp_log_level = os.getenv("SMTP_LOG_LEVEL", "ERROR").upper()
smtp_batch_interval = int(os.getenv("SMTP_BATCH_INTERVAL", "15"))

# Global queue for batched emails
email_queue = asyncio.Queue()


class AsyncQueuedSMTPHandler(logging.Handler):
    """Logging handler that pushes records to an async queue for batched delivery."""

    def emit(self, record):
        """Push record to queue. This is called from the synchronous logging call."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(email_queue.put_nowait, record)
        except Exception:
            self.handleError(record)


async def email_flush_worker(
    host, port, from_addr, to_addrs, subject,
    username=None, password=None, secure=None, interval=15
):
    """Background task that periodically flushes the email queue and sends a batched email."""
    import smtplib
    from email.message import EmailMessage

    logger.info("Email flush worker started with %ss interval", interval)

    while True:
        await asyncio.sleep(interval)

        records = []
        while not email_queue.empty():
            try:
                records.append(email_queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        if not records:
            continue

        logger.info("Flushing %d log records to email", len(records))

        try:
            ehlo_domain = from_addr.split("@")[-1] if "@" in from_addr else "localhost"

            body_parts = []
            for rec in records:
                timestamp = datetime.fromtimestamp(rec.created, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                body_parts.append("--- %s %s ---\n%s" % (timestamp, rec.levelname, rec.getMessage()))

            full_body = "\n\n".join(body_parts)

            def send_sync_email():
                smtp = smtplib.SMTP(host, port, timeout=30, local_hostname=ehlo_domain)

                msg = EmailMessage()
                msg['From'] = from_addr
                msg['To'] = ','.join(to_addrs)
                msg['Subject'] = "%s (%d events)" % (subject, len(records))
                msg.set_content(full_body)

                if secure is not None:
                    smtp.starttls(*secure)

                if username:
                    smtp.login(username, password)

                smtp.send_message(msg)
                smtp.quit()

            await asyncio.to_thread(send_sync_email)

        except Exception as e:
            logger.error("Failed to send batched email: %s", e)


if smtp_host and smtp_from and smtp_to:
    recipients = [email.strip() for email in smtp_to.split(",")]

    email_handler = AsyncQueuedSMTPHandler()
    email_handler.setLevel(getattr(logging, smtp_log_level, logging.ERROR))
    email_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s\n\n%(message)s"
    ))
    logger.addHandler(email_handler)
    logger.info("Email batching enabled: %s:%s (interval: %ss)", smtp_host, smtp_port, smtp_batch_interval)


# ---------------------------------------------------------------------------
# Shared utility functions
# ---------------------------------------------------------------------------

def _to_unix_seconds(ts_value) -> float:
    """
    Convert timestamp to GELF-compatible format (seconds as float).
    Graylog expects GELF timestamp as seconds (float), not milliseconds.
    Handles various input formats: int, float, ISO string.
    """
    if ts_value is None:
        return datetime.now(tz=timezone.utc).timestamp()

    if isinstance(ts_value, (int, float)):
        if ts_value > 10_000_000_000:
            return float(ts_value) / 1000.0
        return float(ts_value)

    if isinstance(ts_value, str):
        try:
            return isoparse(ts_value).timestamp()
        except Exception:
            logger.warning("Failed to parse timestamp: %s", ts_value)
            return datetime.now(tz=timezone.utc).timestamp()

    return datetime.now(tz=timezone.utc).timestamp()


def _flatten_records(payload) -> list:
    """
    Flatten Azure diagnostic log payload.
    Azure sources sometimes send {"records":[...]} or a single dict.
    This normalizes the input to always return a list of records.
    """
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return payload["records"]
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    return []


# ---------------------------------------------------------------------------
# Log transformers: rec -> list[gelf_dict]
# Each transformer receives a single record and returns one or more GELF dicts.
# ---------------------------------------------------------------------------

def _transform_azure_firewall(rec: dict, hostname: str, level: int) -> list:
    """Map Azure Firewall log record to GELF format."""

    def _build_short_message() -> str:
        category = rec.get("category") or rec.get("Category") or ""
        action = rec.get("action") or rec.get("Action") or ""
        protocol = rec.get("protocol") or rec.get("Protocol") or ""
        src_ip = rec.get("srcIp") or rec.get("SourceIP") or rec.get("sourceIp") or ""
        dst_ip = rec.get("dstIp") or rec.get("DestinationIP") or rec.get("destinationIp") or ""
        dst_port = rec.get("dstPort") or rec.get("DestinationPort") or rec.get("destinationPort") or ""
        fqdn = rec.get("fqdn") or rec.get("Fqdn") or ""
        rule = rec.get("rule") or rec.get("Rule") or rec.get("ruleCollection") or rec.get("RuleCollection") or ""

        parts = []
        if category:
            parts.append("[%s]" % category)
        if action:
            parts.append(action.upper())
        if protocol:
            parts.append(protocol.upper())
        if src_ip:
            flow = src_ip
            if dst_ip:
                flow += " -> %s" % dst_ip
                if dst_port:
                    flow += ":%s" % dst_port
            parts.append(flow)
        if fqdn:
            parts.append("FQDN: %s" % fqdn)
        if rule:
            parts.append("Rule: %s" % rule)

        if parts:
            return " ".join(parts)[:250]

        msg = (
            rec.get("msg")
            or rec.get("message")
            or rec.get("Message")
            or rec.get("operationName")
            or "Azure Firewall log"
        )
        return str(msg)[:250]

    ts = (
        rec.get("time")
        or rec.get("TimeGenerated")
        or rec.get("timeGenerated")
        or rec.get("timestamp")
    )

    gelf = {
        "version": "1.1",
        "host": hostname,
        "short_message": _build_short_message(),
        "full_message": json.dumps(rec, ensure_ascii=False),
        "timestamp": _to_unix_seconds(ts),
        "level": level,
    }

    def add(k, v):
        if v is not None and v != "":
            gelf["_%s" % k] = v

    add("azure_category", rec.get("category") or rec.get("Category"))
    add("azure_resource_id", rec.get("resourceId") or rec.get("ResourceId"))
    add("azure_operation", rec.get("operationName") or rec.get("OperationName"))
    add("fw_rule_collection_group", rec.get("ruleCollectionGroup") or rec.get("RuleCollectionGroup"))
    add("fw_rule_collection", rec.get("ruleCollection") or rec.get("RuleCollection"))
    add("fw_rule", rec.get("rule") or rec.get("Rule"))
    add("fw_action", rec.get("action") or rec.get("Action"))
    add("fw_policy", rec.get("policy") or rec.get("Policy"))
    add("network_protocol", rec.get("protocol") or rec.get("Protocol"))
    add("src_ip", rec.get("srcIp") or rec.get("SourceIP") or rec.get("sourceIp"))
    add("src_port", rec.get("srcPort") or rec.get("SourcePort") or rec.get("sourcePort"))
    add("dst_ip", rec.get("dstIp") or rec.get("DestinationIP") or rec.get("destinationIp"))
    add("dst_port", rec.get("dstPort") or rec.get("DestinationPort") or rec.get("destinationPort"))
    add("fqdn", rec.get("fqdn") or rec.get("Fqdn"))
    add("target_url", rec.get("targetUrl") or rec.get("TargetUrl"))
    add("web_category", rec.get("webCategory") or rec.get("WebCategory"))
    add("threat_intel", rec.get("threatIntel") or rec.get("ThreatIntel"))
    add("threat_description", rec.get("threatDescription") or rec.get("ThreatDescription"))
    add("dns_query", rec.get("query") or rec.get("Query") or rec.get("dnsQuery"))
    add("dns_query_type", rec.get("queryType") or rec.get("QueryType"))
    add("idps_signature_id", rec.get("signatureId") or rec.get("SignatureId"))
    add("idps_action", rec.get("idpsAction") or rec.get("IdpsAction"))

    return [gelf]


def _transform_azure_nsg(rec: dict, hostname: str, level: int) -> list:
    """
    Map NSG flow log record to GELF format.

    NSG flow logs have a nested structure: record -> properties.flows[] -> flows[] -> flowTuples[].
    Each flow tuple becomes a separate GELF message.

    Flow tuple format (v2): timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,action,
                             flowState,packetsD2R,bytesD2R,packetsR2D,bytesR2D
    """
    ts = rec.get("time") or rec.get("TimeGenerated")
    resource_id = rec.get("resourceId") or rec.get("ResourceId")
    category = rec.get("category") or rec.get("Category")
    props = rec.get("properties", {})
    full_message = json.dumps(rec, ensure_ascii=False)

    gelf_messages = []

    for rule_flow in props.get("flows", []):
        rule_name = rule_flow.get("rule", "")
        for mac_flow in rule_flow.get("flows", []):
            mac = mac_flow.get("mac", "")
            for tuple_str in mac_flow.get("flowTuples", []):
                parts = tuple_str.split(",")
                if len(parts) < 8:
                    continue

                tuple_ts = parts[0]
                src_ip = parts[1]
                dst_ip = parts[2]
                src_port = parts[3]
                dst_port = parts[4]
                proto = parts[5]       # T=TCP, U=UDP
                direction = parts[6]   # I=Inbound, O=Outbound
                action = parts[7]      # A=Allow, D=Deny

                proto_name = {"T": "TCP", "U": "UDP"}.get(proto, proto)
                dir_name = {"I": "Inbound", "O": "Outbound"}.get(direction, direction)
                action_name = {"A": "Allow", "D": "Deny"}.get(action, action)

                short_msg = "[NSG] %s %s %s %s:%s -> %s:%s Rule:%s" % (
                    action_name, proto_name, dir_name,
                    src_ip, src_port, dst_ip, dst_port, rule_name
                )

                gelf = {
                    "version": "1.1",
                    "host": hostname,
                    "short_message": short_msg[:250],
                    "full_message": full_message,
                    "timestamp": _to_unix_seconds(tuple_ts),
                    "level": level,
                    "_azure_category": category,
                    "_azure_resource_id": resource_id,
                    "_nsg_rule": rule_name,
                    "_nsg_mac": mac,
                    "_src_ip": src_ip,
                    "_src_port": src_port,
                    "_dst_ip": dst_ip,
                    "_dst_port": dst_port,
                    "_network_protocol": proto_name,
                    "_direction": dir_name,
                    "_fw_action": action_name,
                }

                # Optional v2 traffic volume fields
                if len(parts) >= 13:
                    if parts[9]:
                        gelf["_packets_d2r"] = parts[9]
                    if parts[10]:
                        gelf["_bytes_d2r"] = parts[10]
                    if parts[11]:
                        gelf["_packets_r2d"] = parts[11]
                    if parts[12]:
                        gelf["_bytes_r2d"] = parts[12]

                gelf_messages.append(gelf)

    # If no flow tuples found, send the record as-is
    if not gelf_messages:
        gelf_messages.append({
            "version": "1.1",
            "host": hostname,
            "short_message": "[NSG] %s log" % (category or "NetworkSecurityGroup"),
            "full_message": full_message,
            "timestamp": _to_unix_seconds(ts),
            "level": level,
            "_azure_category": category,
            "_azure_resource_id": resource_id,
        })

    return gelf_messages


def _transform_azure_waf(rec: dict, hostname: str, level: int) -> list:
    """Map Azure Application Gateway WAF log record to GELF format."""
    ts = rec.get("time") or rec.get("TimeGenerated")
    props = rec.get("properties", {})

    action = props.get("action", "")
    rule_id = props.get("ruleId", "")
    rule_set = props.get("ruleSetType", "")
    message = props.get("message", "")
    client_ip = props.get("clientIp", "")
    request_uri = props.get("requestUri", "")

    if message:
        short_msg = "[WAF] %s %s" % (action, message[:150])
    else:
        short_msg = "[WAF] %s %s:%s %s %s" % (action, rule_set, rule_id, client_ip, request_uri)

    gelf = {
        "version": "1.1",
        "host": hostname,
        "short_message": short_msg[:250],
        "full_message": json.dumps(rec, ensure_ascii=False),
        "timestamp": _to_unix_seconds(ts),
        "level": level,
    }

    def add(k, v):
        if v is not None and v != "":
            gelf["_%s" % k] = v

    add("azure_category", rec.get("category") or rec.get("Category"))
    add("azure_resource_id", rec.get("resourceId") or rec.get("ResourceId"))
    add("azure_operation", rec.get("operationName") or rec.get("OperationName"))
    add("waf_action", action)
    add("waf_rule_id", rule_id)
    add("waf_rule_set", rule_set)
    add("waf_rule_set_version", props.get("ruleSetVersion"))
    add("waf_rule_group", props.get("ruleGroup"))
    add("waf_message", message)
    add("waf_site", props.get("site"))
    add("src_ip", client_ip)
    add("request_uri", request_uri)
    add("waf_hostname", props.get("hostname"))
    add("transaction_id", props.get("transactionId"))
    add("policy_id", props.get("policyId"))
    add("instance_id", props.get("instanceId"))

    return [gelf]


def _transform_generic(rec: dict, hostname: str, level: int) -> list:
    """
    Generic passthrough transformer for unknown log types.
    Sends all scalar fields as GELF additional fields.
    """
    ts = (
        rec.get("time")
        or rec.get("TimeGenerated")
        or rec.get("timeGenerated")
        or rec.get("timestamp")
    )

    short_msg = (
        rec.get("operationName")
        or rec.get("OperationName")
        or rec.get("category")
        or rec.get("Category")
        or rec.get("message")
        or rec.get("Message")
        or "Azure log"
    )

    gelf = {
        "version": "1.1",
        "host": hostname,
        "short_message": str(short_msg)[:250],
        "full_message": json.dumps(rec, ensure_ascii=False),
        "timestamp": _to_unix_seconds(ts),
        "level": level,
    }

    skip_keys = {"time", "TimeGenerated", "timeGenerated", "timestamp"}
    for key, value in rec.items():
        if key in skip_keys:
            continue
        if isinstance(value, (str, int, float, bool)) and value != "":
            gelf["_%s" % key] = value

    return [gelf]


LOG_TRANSFORMERS = {
    "azure_firewall": _transform_azure_firewall,
    "azure_nsg": _transform_azure_nsg,
    "azure_waf": _transform_azure_waf,
    "generic": _transform_generic,
}


# ---------------------------------------------------------------------------
# Forwarder configuration
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ForwarderConfig:
    name: str
    eventhub_name: str
    consumer_group: str
    blob_container: str
    log_type: str
    gelf_hostname: str
    gelf_level: int
    starting_position: object


def _parse_starting_position(value: str):
    """Convert EVENTHUB_STARTING_POSITION string to SDK-compatible value."""
    if value in ("-1", "@earliest"):
        return -1
    return value  # "@latest" or other string values


def load_forwarder_configs() -> list:
    """
    Load forwarder configurations from environment variables.

    Required: FORWARDER_NAMES=firewall,nsg,waf
    Per forwarder (prefix = name uppercased):
        FIREWALL_EVENTHUB_NAME, FIREWALL_CONSUMER_GROUP,
        FIREWALL_BLOB_CONTAINER, FIREWALL_LOG_TYPE, FIREWALL_GELF_HOSTNAME,
        FIREWALL_GELF_LEVEL (optional), FIREWALL_STARTING_POSITION (optional)
    """
    names_str = os.environ["FORWARDER_NAMES"].strip()

    configs = []
    for raw_name in names_str.split(","):
        name = raw_name.strip()
        prefix = name.upper()
        configs.append(ForwarderConfig(
            name=name.lower(),
            eventhub_name=os.environ["%s_EVENTHUB_NAME" % prefix],
            consumer_group=os.getenv("%s_CONSUMER_GROUP" % prefix, "$Default"),
            blob_container=os.environ["%s_BLOB_CONTAINER" % prefix],
            log_type=os.getenv("%s_LOG_TYPE" % prefix, "generic"),
            gelf_hostname=os.getenv("%s_GELF_HOSTNAME" % prefix, socket.gethostname()),
            gelf_level=int(os.getenv("%s_GELF_LEVEL" % prefix, os.getenv("GELF_LEVEL", "6"))),
            starting_position=_parse_starting_position(
                os.getenv(
                    "%s_STARTING_POSITION" % prefix,
                    os.getenv("EVENTHUB_STARTING_POSITION", "@latest")
                )
            ),
        ))

    return configs


# ---------------------------------------------------------------------------
# GELF sender
# ---------------------------------------------------------------------------

class GelfHttpSender:
    """Async GELF HTTP sender with retry logic."""

    def __init__(self, session: aiohttp.ClientSession, url: str, max_retries: int = 5):
        self.session = session
        self.url = url
        self.max_retries = max_retries

    async def send(self, gelf: dict) -> None:
        """Send GELF message to Graylog with retries."""
        last_error = None

        for attempt in range(self.max_retries):
            try:
                async with self.session.post(
                    self.url,
                    json=gelf,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status < 300:
                        return

                    text = await resp.text()
                    last_error = RuntimeError("Graylog returned %d: %s" % (resp.status, text[:300]))

                    # Don't retry on client errors (4xx)
                    if 400 <= resp.status < 500:
                        raise last_error

            except asyncio.TimeoutError:
                last_error = asyncio.TimeoutError(
                    "Timeout sending to Graylog (attempt %d)" % (attempt + 1)
                )
                logger.warning("Timeout sending to Graylog, attempt %d/%d", attempt + 1, self.max_retries)
            except aiohttp.ClientError as e:
                last_error = e
                logger.warning("Connection error to Graylog: %s, attempt %d/%d", e, attempt + 1, self.max_retries)

            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** (attempt + 1))  # Exponential backoff

        raise last_error


# ---------------------------------------------------------------------------
# Per-hub consumer coroutine
# ---------------------------------------------------------------------------

async def run_forwarder(
    config: ForwarderConfig,
    credential,
    eh_fqdn: str,
    blob_account_url: str,
    sender: GelfHttpSender,
) -> None:
    """Run a single Event Hub consumer that forwards logs to Graylog."""

    transformer = LOG_TRANSFORMERS.get(config.log_type, LOG_TRANSFORMERS["generic"])
    tag = "[%s]" % config.name

    checkpoint_store = BlobCheckpointStore(
        blob_account_url=blob_account_url,
        container_name=config.blob_container,
        credential=credential,
    )

    client = EventHubConsumerClient(
        fully_qualified_namespace=eh_fqdn,
        eventhub_name=config.eventhub_name,
        consumer_group=config.consumer_group,
        credential=credential,
        checkpoint_store=checkpoint_store,
    )

    events_processed = 0
    errors_count = 0

    async def on_event(partition_context, event):
        nonlocal events_processed, errors_count

        if event is None:
            logger.debug("%s[Partition %s] heartbeat", tag, partition_context.partition_id)
            return

        body = event.body_as_str(encoding="UTF-8")
        pid = partition_context.partition_id

        logger.info("%s[Partition %s] Received event, size=%d bytes", tag, pid, len(body))

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            logger.warning("%s[Partition %s] Non-JSON event", tag, pid)
            gelf = {
                "version": "1.1",
                "host": config.gelf_hostname,
                "short_message": "%s log (raw)" % config.name,
                "full_message": body,
                "timestamp": datetime.now(tz=timezone.utc).timestamp(),
                "level": config.gelf_level,
            }
            try:
                await sender.send(gelf)
                events_processed += 1
                logger.info("%s[Partition %s] Sent raw event to Graylog", tag, pid)
            except Exception as e:
                errors_count += 1
                logger.error("%s[Partition %s] Failed to send raw event: %s", tag, pid, e)

            await partition_context.update_checkpoint(event)
            return

        records = _flatten_records(payload)
        logger.info("%s[Partition %s] Parsed %d records from event", tag, pid, len(records))

        for rec in records:
            gelf_messages = transformer(rec, config.gelf_hostname, config.gelf_level)
            for gelf in gelf_messages:
                try:
                    await sender.send(gelf)
                    events_processed += 1
                except Exception as e:
                    errors_count += 1
                    logger.error("%s[Partition %s] Failed to send GELF: %s", tag, pid, e)

        await partition_context.update_checkpoint(event)

        if events_processed % 100 == 0 and events_processed > 0:
            logger.info("%s Processed %d events, %d errors", tag, events_processed, errors_count)

    async def on_error(partition_context, error):
        if partition_context:
            logger.error("%s[Partition %s] Error: %s", tag, partition_context.partition_id, error)
        else:
            logger.error("%s Consumer error: %s", tag, error)

    async def on_partition_initialize(partition_context):
        logger.info("%s[Partition %s] Initialized", tag, partition_context.partition_id)

    async def on_partition_close(partition_context, reason):
        logger.info("%s[Partition %s] Closed, reason: %s", tag, partition_context.partition_id, reason)

    logger.info(
        "%s Starting consumer for hub '%s' (type: %s, group: %s)",
        tag, config.eventhub_name, config.log_type, config.consumer_group
    )

    async with client:
        await client.receive(
            on_event=on_event,
            on_error=on_error,
            on_partition_initialize=on_partition_initialize,
            on_partition_close=on_partition_close,
            starting_position=config.starting_position,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    """Main entry point: starts all configured Event Hub forwarders concurrently."""

    eh_fqdn = os.environ["EVENTHUB_FQDN"]
    blob_account_url = os.environ["BLOB_ACCOUNT_URL"]
    graylog_url = os.environ["GRAYLOG_GELF_HTTP_URL"]

    configs = load_forwarder_configs()

    logger.info("Event Hub namespace: %s", eh_fqdn)
    logger.info("Graylog endpoint: %s", graylog_url)
    logger.info("Starting %d forwarder(s): %s", len(configs), [c.name for c in configs])

    managed_identity_client_id = os.getenv("AZURE_CLIENT_ID")
    if managed_identity_client_id:
        logger.info("Using User Assigned Managed Identity (Client ID: %s)", managed_identity_client_id)
        credential = DefaultAzureCredential(managed_identity_client_id=managed_identity_client_id)
    else:
        logger.info("Using DefaultAzureCredential (System IAM or local developer credentials)")
        credential = DefaultAzureCredential()

    async with aiohttp.ClientSession() as session:
        sender = GelfHttpSender(session, graylog_url)

        email_task = None
        if smtp_host and smtp_from and smtp_to:
            email_task = asyncio.create_task(email_flush_worker(
                host=smtp_host,
                port=smtp_port,
                from_addr=smtp_from,
                to_addrs=[e.strip() for e in smtp_to.split(",")],
                subject=smtp_subject,
                username=smtp_username,
                password=smtp_password,
                secure=() if smtp_use_tls else None,
                interval=smtp_batch_interval
            ))

        try:
            await asyncio.gather(*[
                run_forwarder(cfg, credential, eh_fqdn, blob_account_url, sender)
                for cfg in configs
            ])
        finally:
            if email_task:
                email_task.cancel()
                try:
                    await email_task
                except asyncio.CancelledError:
                    pass

    await credential.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        raise
