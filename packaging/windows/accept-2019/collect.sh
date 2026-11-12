#!/usr/bin/env bash
# Fetch the acceptance results, then remove what launch.sh created in AWS.
#   BUCKET=... PREFIX=... SG=... ID=... REGION=... ./collect.sh
set -euo pipefail
: "${BUCKET:?}" "${PREFIX:?}" "${SG:?}" "${ID:?}"
REGION=${REGION:-us-east-1}
OUT=${OUT:-$(mktemp -d)}

state=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text)
echo "instance $ID: $state"
if aws s3 cp --region "$REGION" "s3://$BUCKET/$PREFIX/result.tgz" "$OUT/result.tgz" --only-show-errors; then
  tar -xzf "$OUT/result.tgz" -C "$OUT"
  echo "results in $OUT/shentu-accept (review by hand and with gitleaks before anything is committed)"
else
  echo "no result yet; run again later (the instance stops itself within 3 hours)"
  exit 1
fi
# Cleanup only after the instance is gone: the security group is in use until then.
if [ "$state" != terminated ]; then
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"
fi
aws ec2 delete-security-group --region "$REGION" --group-id "$SG"
aws s3 rm --region "$REGION" --recursive "s3://$BUCKET/$PREFIX/" --only-show-errors
echo "removed the security group and s3://$BUCKET/$PREFIX/"
