#!/usr/bin/env bash
# Start ngrok using the permanent static domain for SentinelReview
echo "Starting ngrok with static domain..."
echo "Webhook URL: https://goldsmith-quiet-sinner.ngrok-free.dev/webhooks/github"
ngrok http --domain=goldsmith-quiet-sinner.ngrok-free.dev 8010
