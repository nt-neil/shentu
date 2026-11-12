#!/usr/bin/env bash
# Shentu acceptance on Windows Server 2019: one t3.medium in us-east-1 that
# runs userdata.bat (no inbound access, no RDP), uploads its results to a
# private S3 object and terminates itself (3 hours at most). See README.md.
#
# Costs money: run it only after the owner approved the quote.
#   BUCKET=<private bucket you own> AWS_PROFILE=<profile> ./launch.sh
set -euo pipefail
: "${BUCKET:?set BUCKET to a private S3 bucket}"
REGION=${REGION:-us-east-1}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
PREFIX="shentu-accept/$STAMP"
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
WORK=$(mktemp -d)   # holds the rendered user-data (short-lived URLs): trash it after
echo "work dir: $WORK"

GOOS=windows GOARCH=amd64 go build -C "$REPO" -o "$WORK/shentu.exe" .
GOOS=windows GOARCH=amd64 go build -C "$REPO" -o "$WORK/hostfacts.exe" ./cmd/hostfacts/
aws s3 cp --region "$REGION" "$WORK/shentu.exe" "s3://$BUCKET/$PREFIX/shentu.exe" --only-show-errors
aws s3 cp --region "$REGION" "$WORK/hostfacts.exe" "s3://$BUCKET/$PREFIX/hostfacts.exe" --only-show-errors
GET_SHENTU=$(aws s3 presign --region "$REGION" --expires-in 3600 "s3://$BUCKET/$PREFIX/shentu.exe")
GET_FACTS=$(aws s3 presign --region "$REGION" --expires-in 3600 "s3://$BUCKET/$PREFIX/hostfacts.exe")
# aws s3 presign signs GET only; the result upload needs a presigned PUT.
# Credentials go from the CLI to this process's environment, never to a file.
PUT_RESULT=$(eval "$(aws configure export-credentials --format env)" && \
  python3 "$HERE/presign_put.py" "$REGION" "$BUCKET" "$PREFIX/result.tgz" 14400)

python3 - "$HERE/userdata.bat.tmpl" "$WORK/userdata.bat" "$GET_SHENTU" "$GET_FACTS" "$PUT_RESULT" <<'EOF'
import sys
t = open(sys.argv[1]).read()
for k, v in (("{{SHENTU_URL}}", sys.argv[3]), ("{{HOSTFACTS_URL}}", sys.argv[4]), ("{{RESULT_URL}}", sys.argv[5])):
    assert k in t
    t = t.replace(k, v)
open(sys.argv[2], "w").write(t)
EOF

AMI=$(aws ssm get-parameter --region "$REGION" --name /aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base \
  --query Parameter.Value --output text)
VPC=$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SG=$(aws ec2 create-security-group --region "$REGION" --vpc-id "$VPC" --group-name "shentu-accept-$STAMP" \
  --description "Shentu acceptance: no inbound rules" --query GroupId --output text)
ID=$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type t3.medium --count 1 \
  --security-group-ids "$SG" --user-data "file://$WORK/userdata.bat" \
  --instance-initiated-shutdown-behavior terminate \
  --metadata-options HttpTokens=required \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3,DeleteOnTermination=true}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=shentu-accept-2019},{Key=purpose,Value=shentu-acceptance}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "instance $ID (AMI $AMI), security group $SG, results s3://$BUCKET/$PREFIX/result.tgz"
echo "when done: BUCKET=$BUCKET PREFIX=$PREFIX SG=$SG ID=$ID REGION=$REGION ./collect.sh"
