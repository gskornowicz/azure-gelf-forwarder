# Azure GELF Forwarder
Universal Azure Event Hub -> Graylog GELF forwarder

No need to pay $15k/yr for Graylog Enterprise and it's "Azure Event Hubs Input" to get logs from Azure into Graylog :)

Curerrently supports diagnostic logs from: Azure Firewall, Azure NSG Flow Logs, Azure WAF, and generic logs which won't be transformed.

Feel free to contribute and add support for other Azure services with diagnostic logs in Event Hub.

Why container based app and not an Azure Function? Because Functions have execution limit, which is not suitable for continuous log forwarding. Container can run indefinitely and handle long-running processes like consuming from Event Hub. Also you can deploy this forwarder to any environment that supports containers, not just Azure.

## Architecture

```
Logs -> Event Hub -> [this service] -> Graylog (GELF HTTP)
```

## Requirements
- Python 3.10+
- Azure Event Hub with Azure diagnostic logs
- Azure Blob Storage for checkpoints
- Graylog with GELF HTTP input enabled

## Local installation & configuration

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```
Copy `.env.example` to `.env` and fill in values as described in the table below.

### Environment variables

| Variable | Description | Required |
|---------|-------------|----------|
| `EVENTHUB_FQDN` | Event Hub namespace FQDN, e.g. `myns.servicebus.windows.net` | ✅ |
| `BLOB_ACCOUNT_URL` | Blob Storage account URL | ✅ |
| `GRAYLOG_GELF_HTTP_URL` | GELF HTTP input URL, e.g. `http://graylog:12201/gelf` | ✅ |
| `FORWARDER_NAMES` | Comma-separated forwarder names (e.g. `firewall,nsg,waf`) | ✅ |
| `LOG_LEVEL` | Python logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | ❌ |
| `GELF_LEVEL` | Default syslog severity for GELF messages (default 6=info) | ❌ |
| `EVENTHUB_STARTING_POSITION` | Default starting position (`@latest` or `-1`) | ❌ |
| `AZURE_CLIENT_ID` | Optional user-assigned managed identity client ID; leave empty for system identity | ❌ |

#### Per-forwarder variables (prefix = uppercased forwarder name)

| Template | Description | Required |
|----------|-------------|----------|
| `<NAME>_EVENTHUB_NAME` | Event Hub name for this forwarder | ✅ |
| `<NAME>_BLOB_CONTAINER` | Blob container for this forwarder's checkpoints | ✅ |
| `<NAME>_LOG_TYPE` | Transformer type: `azure_firewall`, `azure_nsg`, `azure_waf`, `generic` (default `generic`) | ❌ |
| `<NAME>_CONSUMER_GROUP` | Event Hub consumer group (default `$Default`) | ❌ |
| `<NAME>_GELF_HOSTNAME` | Hostname applied to GELF messages (default system hostname) | ❌ |
| `<NAME>_GELF_LEVEL` | Override per-forwarder GELF syslog level | ❌ |
| `<NAME>_STARTING_POSITION` | Override per-forwarder starting position | ❌ |

## Run

### Locally

```bash
python main.py
```

### Docker

```bash
docker build -t azure-gelf-forwarder .
docker run --env-file .env azure-gelf-forwarder
```

### Docker Compose

```yaml
version: '3.8'
services:
  forwarder:
    build: .
    env_file: .env
    restart: unless-stopped
```

## Azure Authentication

The service uses `DefaultAzureCredential`, which supports:

1. Local development via Azure CLI (`az login`)
2. Service Principal via `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

The identity must have permission to read from Event Hub and write checkpoints to Blob Storage.

### Optional SMTP Alerting (if configured)

If `SMTP_HOST`, `SMTP_FROM`, and `SMTP_TO` are set, the forwarder attaches an asynchronous email logging handler.
- It buffers log records and sends batched emails every `SMTP_BATCH_INTERVAL` seconds.
- It only queues log records at or above `SMTP_LOG_LEVEL` (default `ERROR`).
- It connects to SMTP server, optionally starts TLS (`SMTP_USE_TLS=true`), logs in if credentials are provided, and sends a single message with multiple log entries.

This is useful for receiving operational alerts for failures, timeouts, or other errors while forwarding.

Example SMTP env vars:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_FROM=forwarder@example.com
SMTP_TO=ops@example.com,admin@example.com
SMTP_USERNAME=smtp-user
SMTP_PASSWORD=smtp-pass
SMTP_USE_TLS=true
SMTP_BATCH_INTERVAL=15
SMTP_LOG_LEVEL=ERROR
```

Example role assignments in OpenTofu / Terraform:

```terraform
# Role assignment to allow Container App to read from Event Hub
resource "azurerm_role_assignment" "fw_logs_eventhub_receiver" {
  scope                = azurerm_eventhub_namespace.firewall_logs.id
  role_definition_name = "Azure Event Hubs Data Receiver"
  principal_id         = azurerm_container_app.logs_forwarder.identity[0].principal_id
}

# Role assignment to allow Container App to write checkpoints to Blob Storage
resource "azurerm_role_assignment" "fw_logs_blob_contributor" {
  scope                = azurerm_storage_account.fw_logs_checkpoints.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_container_app.logs_forwarder.identity[0].principal_id
}
```

## Logging

The forwarder uses Python's standard `logging` module, outputting to stdout in the format `timestamp - name - level - message`. The log level is controlled by the `LOG_LEVEL` environment variable (default: `WARNING`).

Log output by severity:

| Level | What is logged |
|-------|----------------|
| `DEBUG` | Per-partition heartbeat events (null events from the SDK keep-alive) |
| `INFO` | Consumer lifecycle (startup, partition initialize/close), event received/parsed/sent, progress summary every 100 events, credential selection |
| `WARNING` | Non-JSON event bodies, Graylog timeout and connection errors (before retry) |
| `ERROR` | Failed GELF sends after all retries, partition-level consumer errors |

Each forwarder task runs concurrently via `asyncio.gather`, so log lines from multiple forwarders may interleave; the forwarder name tag (e.g. `[firewall]`) and partition ID in each message identify the source.

Every 100 successfully processed events, the forwarder emits an `INFO` progress line with total events processed and cumulative error count for that forwarder instance.

For alerting on errors via email, see the [SMTP Alerting](#optional-smtp-alerting-if-configured) section above.

## GELF fields

All messages include standard GELF keys: `version`, `host`, `short_message`, `full_message`, `timestamp`, and `level`.

### Azure Firewall log mapping

| GELF field | Azure source field |
|------------|--------------------|
| `_azure_category` | `category` / `Category` |
| `_azure_resource_id` | `resourceId` / `ResourceId` |
| `_azure_operation` | `operationName` / `OperationName` |
| `_fw_rule_collection_group` | `ruleCollectionGroup` / `RuleCollectionGroup` |
| `_fw_rule_collection` | `ruleCollection` / `RuleCollection` |
| `_fw_rule` | `rule` / `Rule` |
| `_fw_action` | `action` / `Action` |
| `_fw_policy` | `policy` / `Policy` |
| `_network_protocol` | `protocol` / `Protocol` |
| `_src_ip` | `srcIp` / `SourceIP` / `sourceIp` |
| `_src_port` | `srcPort` / `SourcePort` / `sourcePort` |
| `_dst_ip` | `dstIp` / `DestinationIP` / `destinationIp` |
| `_dst_port` | `dstPort` / `DestinationPort` / `destinationPort` |
| `_fqdn` | `fqdn` / `Fqdn` |
| `_target_url` | `targetUrl` / `TargetUrl` |
| `_web_category` | `webCategory` / `WebCategory` |
| `_threat_intel` | `threatIntel` / `ThreatIntel` |
| `_threat_description` | `threatDescription` / `ThreatDescription` |
| `_dns_query` | `query` / `Query` / `dnsQuery` |
| `_dns_query_type` | `queryType` / `QueryType` |
| `_idps_signature_id` | `signatureId` / `SignatureId` |
| `_idps_action` | `idpsAction` / `IdpsAction` |

### Azure NSG flow log mapping

For each flow tuple, the forwarder emits one GELF message with:

| GELF field | Azure source field |
|------------|--------------------|
| `_azure_category` | `category` / `Category` |
| `_azure_resource_id` | `resourceId` / `ResourceId` |
| `_nsg_rule` | rule tuple `rule` |
| `_nsg_mac` | MAC segment `mac` |
| `_src_ip` | flow tuple source IP |
| `_src_port` | flow tuple source port |
| `_dst_ip` | flow tuple destination IP |
| `_dst_port` | flow tuple destination port |
| `_network_protocol` | flow tuple protocol (TCP/UDP) |
| `_direction` | flow tuple direction (Inbound/Outbound) |
| `_fw_action` | flow tuple action (Allow/Deny) |
| `_packets_d2r` | optional bytes/packets from tuple |
| `_bytes_d2r` | optional bytes/packets from tuple |
| `_packets_r2d` | optional bytes/packets from tuple |
| `_bytes_r2d` | optional bytes/packets from tuple |

If flow tuples are missing, it emits a single fallback message with category/resource ID.

### Azure WAF log mapping

| GELF field | Azure source field |
|------------|--------------------|
| `_azure_category` | `category` / `Category` |
| `_azure_resource_id` | `resourceId` / `ResourceId` |
| `_azure_operation` | `operationName` / `OperationName` |
| `_waf_action` | `properties.action` |
| `_waf_rule_id` | `properties.ruleId` |
| `_waf_rule_set` | `properties.ruleSetType` |
| `_waf_rule_set_version` | `properties.ruleSetVersion` |
| `_waf_rule_group` | `properties.ruleGroup` |
| `_waf_message` | `properties.message` |
| `_waf_site` | `properties.site` |
| `_src_ip` | `properties.clientIp` |
| `_request_uri` | `properties.requestUri` |
| `_waf_hostname` | `properties.hostname` |
| `_transaction_id` | `properties.transactionId` |
| `_policy_id` | `properties.policyId` |
| `_instance_id` | `properties.instanceId` |

### Generic log mapping

For logs with type `generic`, the forwarder sends the full record and adds all top-level scalar fields as GELF metadata (`_{field}`), excluding known timestamp fields (`time`, `TimeGenerated`, `timeGenerated`, `timestamp`).

`full_message` always includes the complete JSON record.

## Graylog Setup

1. Create a **GELF HTTP** input:
   - System -> Inputs -> Select Input -> GELF HTTP
   - Port: 12201 (or your chosen port)
   - Bind address: 0.0.0.0

2. Verify input is receiving messages:

```bash
curl -X POST http://graylog:12201/gelf \
  -H "Content-Type: application/json" \
  -d '{"version":"1.1","host":"test","short_message":"Test message"}'
```

## Troubleshooting

### Timestamp issues

Graylog expects timestamps in seconds (float), not milliseconds. The service automatically converts millisecond timestamps.

### Consumer group

Use a dedicated consumer group (e.g. `graylog`) to avoid consuming offsets from other consumers.

### Checkpoints

Checkpoints are saved in Blob Storage after processed events. On restart, the service resumes from the last checkpoint.

## AI Usage Note

Documentation and parts of the code in this project were generated with the help of Claude AI.

## Licensing

`azure-gelf-forwarder` is an MIT-licensed community open-source project.
