#!/usr/bin/env bash
# ==============================================================================
# Roam Fleet Compliance - Quick Deploy & Continuous Deployment Helper
# ==============================================================================
set -e

SERVICE_NAME="roam-compliance"
REGION="us-central1"

show_help() {
  echo "Usage: ./deploy.sh [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  (no args)    Pull latest main and deploy immediately to Google Cloud Run"
  echo "  --watch, -w  Keep running in Cloud Shell; auto-deploys whenever a new git commit is pushed"
  echo "  --help, -h   Show this help screen"
  echo ""
}

deploy_now() {
  echo "===================================================================="
  echo "  ROAM COMPLIANCE // Deploying to Google Cloud Run ($REGION)"
  echo "===================================================================="
  echo "[*] Pulling latest code from origin/main..."
  git pull origin main

  echo "[*] Triggering Google Cloud Run deployment..."
  gcloud run deploy "$SERVICE_NAME" --source . --region "$REGION" --quiet

  echo ""
  echo " [OK] Successfully deployed to https://roamcompliance.com"
  echo "===================================================================="
}

watch_and_deploy() {
  echo "===================================================================="
  echo "  ROAM COMPLIANCE // Auto-Deployment Watcher Active"
  echo "===================================================================="
  echo "[*] Monitoring origin/main for new git commits every 10 seconds."
  echo "    Leave this running in your Cloud Shell terminal."
  echo "    Whenever code is pushed to GitHub, Cloud Run will deploy automatically!"
  echo "    (Press Ctrl+C to stop watcher)"
  echo "--------------------------------------------------------------------"

  while true; do
    git fetch origin main >/dev/null 2>&1 || true
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main)

    if [ "$LOCAL" != "$REMOTE" ]; then
      echo ""
      echo "[*] [$(date +'%T')] New commit detected on origin/main ($REMOTE)!"
      echo "[*] Pulling latest updates..."
      git pull origin main
      echo "[*] Deploying container to Cloud Run..."
      gcloud run deploy "$SERVICE_NAME" --source . --region "$REGION" --quiet
      echo " [OK] [$(date +'%T')] Live at https://roamcompliance.com"
      echo "[*] Resuming watcher loop..."
    fi

    sleep 10
  done
}

case "$1" in
  --watch|-w)
    watch_and_deploy
    ;;
  --help|-h)
    show_help
    ;;
  *)
    deploy_now
    ;;
esac
