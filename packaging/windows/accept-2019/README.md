# Windows Server 2019 acceptance (cloud, paid)

GitHub has no windows-2019 runner, so Server 2019 is checked on one
short-lived EC2 instance. Nothing here runs without the owner's approval of
the cost.

## What it does

`launch.sh` builds `shentu.exe` and `hostfacts.exe` for windows/amd64,
uploads them to a private S3 prefix, and starts one **t3.medium** (Windows
Server 2019 English Full Base, latest AMI) in **us-east-1** with:

- a new security group with **no inbound rules** (no RDP, no SSH);
- user-data `userdata.bat` (cmd, no PowerShell) that runs everything as
  SYSTEM and uploads `result.tgz` through a presigned PUT URL;
- `shutdown /s /t 10800` first thing and shutdown behaviour `terminate`:
  the instance deletes itself after the run, and after 3 hours at most;
- a 30 GB gp3 root volume deleted on termination; IMDSv2 only.

`userdata.bat`:

1. clean host: `hostfacts`, `hostfacts -checks`, a masked fixture (`-record`);
2. enables IIS (with ASP.NET 4.5) and an `uploads` folder;
3. plants test items, all named `ShentuTest*`: a Run key, a scheduled task,
   a service with an unquoted path, a WMI event subscription
   (filter + CommandLineEventConsumer + binding), a JScript eval webshell in
   `C:\inetpub\wwwroot\uploads`;
4. planted host: the same three outputs, `shentu survey`,
   `shentu patrol --dry-run`, and the service: install, start, status, stop,
   status, uninstall;
5. removes the planted items, tars `C:\shentu-accept`, uploads it, shuts down.

`collect.sh` downloads and unpacks the result, waits for termination, then
deletes the security group and the S3 prefix.

## Pass criteria

- clean host: every fact `ok` or `partial` with a reason; no finding naming
  `ShentuTest`; findings otherwise explainable (no false positives);
- planted host: findings for the Run key, the scheduled task, the unquoted
  service path, the WMI subscription and the webshell in the upload folder;
  `web.server` is `iis` with `C:\inetpub\wwwroot`;
- survey and patrol exit 0; the service reaches `running` and `stopped`
  and uninstalls;
- the fixtures pass review and gitleaks before any of them is committed.

## Running it (after approval)

```
BUCKET=<private bucket> AWS_PROFILE=<profile> ./launch.sh
# about 30-60 minutes later
BUCKET=... PREFIX=... SG=... ID=... REGION=us-east-1 ./collect.sh
```

The rendered user-data in launch.sh's work directory holds short-lived
presigned URLs (downloads 1 hour, the result upload 2 hours): move it to
the trash when done. A run still going after 2 hours cannot upload its
result; it stops itself at 3 hours.
