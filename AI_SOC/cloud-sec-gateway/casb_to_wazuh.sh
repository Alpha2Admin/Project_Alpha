#!/bin/bash
# AI-CASB to Wazuh Bridge Script
# This script is designed to be triggered by a Splunk Alert Action.
# It receives results from Splunk and appends them to a Wazuh-monitored JSON log.

LOG_FILE="/var/log/casb_risk_alerts.json"

# Check if Splunk is passing results (Splunk passes 8th argument as a gzipped file usually, 
# but for a simple script action we can simulate it or pass via stdin).

if [ -f "$8" ]; then
    # Splunk passes a results file in $8. We uncompress and extract fields.
    zcat "$8" | jq -c '.[]' >> "$LOG_FILE"
else
    # Manual/Direct execution (simulation)
    # Expected env variables or stdin
    echo "$1" >> "$LOG_FILE"
fi

echo "✅ [CASB-SIEM] Risk alert forwarded to $LOG_FILE"
