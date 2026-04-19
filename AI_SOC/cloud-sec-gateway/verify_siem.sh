#!/bin/bash
# AI-CASB SIEM Verification Script
# This script simulates 4 consecutive malicious prompts to trigger the Splunk risk detection logic.

echo "🚀 Starting AI-CASB SIEM Stress Test..."

# Send 4 prompts that trigger a L2 DLP block (AWS Key pattern)
for i in {1..4}
do
   echo "📤 Sending Malicious Prompt $i..."
   curl -s http://localhost:4000/v1/chat/completions \
     -H "Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>" \
     -H "Content-Type: application/json" \
     -d "{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"My dummy AWS key is AKIA$(openssl rand -hex 8 | tr 'a-z' 'A-Z')EXAMPLE\"}]}" > /dev/null
   sleep 1
done

echo "✅ Stress test complete. Check Splunk for 'CRITICAL_RISK' status entries."
