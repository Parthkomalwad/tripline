# Operations

This guide covers failure modes, break-glass, retention, connector delays, key rotation and release handling. tripline is pre-release. Parts marked "planned" do not exist yet.

## Failure modes

The main rule: tripline going down must never take your AI systems down, and you must always notice.

| Failure | What happens | What you do |
|---|---|---|
| Watcher stops | Sensors keep enforcing the last verified rules. They buffer events on disk (default cap 50 MiB, oldest dropped first) and send them when the watcher returns. The dead man's switch stops pinging, so the outside service alerts. | Restart the watcher. Run `tripline audit verify`. Check the status page for dropped events. |
| Sensor stops | Traffic that uses `HTTPS_PROXY` fails to connect. The status page marks the source `SILENT` after 5 minutes without a heartbeat. | Restart the sensor. See "Fail-open and fail-closed". |
| Sensor cannot reach the watcher | The sensor keeps its rules and buffers events. Bundle updates stop. | Fix the network. The self-test `bundle-current` check warns about a stale sensor. |
| Sensor has no valid rules at start, unsigned mode | `fail_mode: open` (default) allows all traffic and sends a critical event. `fail_mode: closed` denies every CONNECT. | Fix the rules file. |
| Sensor has no verified bundle at start, signed mode | The sensor runs on the floor rules until a verified bundle arrives. It logs an error if the stored bundle fails verification. | Check the trust file and the bundle. |
| Rejected bundle | The current rules stay in force. An alert names the reason. Floor weakening is critical. | Find out who made the bundle. Treat an unexpected one as a key or delivery compromise. |
| Audit log fails to verify | `tripline audit verify` names the first broken entry. | Treat it as tampering until you prove otherwise. Keep a copy of the file. |
| Alert sink fails | The failure is logged and counted. The audit log still records the alert. | Check the sink URL variable. Test the sink. |
| Status page unreachable | `tripline status` reports that the watcher is unreachable. An unreachable watcher is itself a signal. | Check that the watcher runs. |

The sensor buffer holds events only. Enforcement does not depend on the watcher.

## Fail-open and fail-closed

Fail-open means that traffic passes when tripline cannot decide. Fail-closed means that traffic stops.

- The default is fail-open with a critical alert. A broken monitor then does not cause an outage.
- Use `fail_mode: closed` on a sensor only when a blocked AI system costs less than missed exfiltration. Test a restart before you rely on it.
- `fail_mode` applies only when a sensor loads rules from `rules_file` and the file is not valid. With `trust_file`, the sensor falls back to the floor rules.
- The proxy is the only route only if you make it so. If the network allows direct egress, a stopped sensor does not block it. If the network allows only the proxy, a stopped sensor stops egress. Decide which you want.
- Run more than one sensor behind your own load balancer if you need availability.

## Break-glass

Break-glass relaxes a rule for a short time, for example to let an urgent change through when a block stops production.

Use the signed bundle path. It leaves a record and needs two people.

1. Declare the incident. Name the rule, the reason and the end time. Write them in your incident log.
2. Make a new bundle. Raise `version`. Change only the rule you must relax, for example `mode: enforce` to `mode: monitor`, or one added host in an allowlist.
3. Run `tripline rules diff old.yaml new.yaml`. Confirm that only the intended rule changed.
4. Set `effective_at` at least `loosening_delay` after `created_at`. The minimum delay is 1 hour. A bundle with a shorter delay is rejected. The default is 24 hours.
5. Sign with the required number of keys. Run `tripline rules verify`.
6. Copy the bundle to the watcher's `bundle_file`. The watcher alerts on receipt and again when the change takes effect.
7. Make the reverse bundle now. Raise `version` again. Restore the old rule. Keep it signed and ready.
8. At the end time, publish the reverse bundle. Tightening can take effect at once.
9. Record the closing in your incident log. The audit log holds both bundle outcomes.

Limits today:

- There is no automatic expiry. A relaxation stays until someone publishes a bundle that undoes it. Set a reminder. A time-limited, auto-expiring relaxation is not built.
- The delay applies to every loosening, including an urgent one. To act faster, lower `loosening_delay` in the trust file to the 1 hour minimum ahead of time, or use your own network controls for the emergency.
- Floor rules cannot be relaxed by a bundle. To stop a floor rule that causes harm, change the binary or the sensor configuration, and record the decision.
- Do not edit the watcher host files by hand to bypass a bundle. Edits to `bundle.applied.yaml` in the state directory fail verification at the next start.

## Retention

The audit log is `<state_dir>/audit.jsonl`. It only grows. tripline does not rotate it or delete from it.

Rules for the log:

- Never edit, truncate or compress the live file. Any change breaks the chain.
- Back it up by copying the file. Verify the copy with `tripline audit verify -file <copy>`.
- To archive: stop the watcher, copy the file to cold storage, run `tripline audit verify -file <copy>`, record the last entry's `seq` and `hash` in a system that is not on the host, and keep the original in place. The log keeps growing in the same file until you decide to start a new one.
- A new log file starts a new chain, with a zero `prev` value. The old chain and the new chain are not linked by tripline. Record the last `hash` of the old file with the first entry of the new file, in your own records.
- Record the latest `seq` and `hash` on another system on a schedule. This is the external anchor. Without it, deletion of the last entries cannot be detected.
- Keep audit files as long as your incident-response policy needs. One year is a common choice.

Other state in `state_dir`: sensor tokens, the decoy registry, the applied bundle (`bundle.applied.yaml`) and saved correlation state. Back up the token and registry files with care. They are secrets. The sensor state directory holds the event buffer and its applied bundle.

Metrics are in memory. Scrape `/metrics` into your own store if you need history.

## Connector delays (planned)

Key-usage connectors read provider and cloud logs. They are planned for milestone 8 and do not exist yet. When they exist, each connector will document its delay. Provider usage logs often arrive minutes to hours after the event. A key-usage alert is a late signal. It does not replace the trap or the egress sensor.

## Key rotation runbook template

Copy this template. Fill the blanks. Rehearse it before you need it.

**Signing key rotation**

1. Owner: ____. Reason (schedule, departure, suspected theft): ____.
2. Make the new key: `tripline rules keygen -id <name>-<year> -out keys -owner <name>`. Use the new owner's machine.
3. Make a new trust file with the old and new public keys. Keep `required_signatures` unchanged.
4. Install the new trust file on the watcher and every sensor host. The file is root-owned. Restart the watcher and the sensors.
5. Make a new bundle, signed with keys that the new trust file accepts. Raise `version`. Publish it. Check `tripline status` on every sensor.
6. Make the next trust file without the old key. Install it and restart.
7. Destroy the old private key file. Write the date in the incident log.
8. If the cause was theft, treat bundles signed by that key since the theft as suspect. Review `bundle.accepted` entries in the audit log.

**Sensor token rotation**

`tripline sensor add` refuses an ID that already exists. There is no revoke command yet.

1. Run `tripline sensor add -config tripline.yaml <new-sensor-id>`. Store the new token.
2. Set the new `sensor.id` and token variable on the sensor. Restart the sensor.
3. Stop the watcher. Delete the old entry from `<state_dir>/sensors.json`. The file maps token hashes to sensor IDs. Start the watcher.
4. Record the change in your incident log.

**Decoy rotation**

1. Run `tripline init` in a new directory. Plant the new decoys.
2. Remove the old decoy files. The old tokens stay registered, so a late use of an old decoy still alerts.

**Provider keys**

Rotate the real provider keys with the provider. Provider mode (planned) will keep them out of the gateway.

Fill in: who holds each key, where each private key is stored, the date of the last rotation, and the date of the next one.

## Releases and updates

- **Deploy images by digest, never by tag.** A tag can move. A digest cannot. Use `image@sha256:...`. The base image in the repository `Dockerfile` is also pinned by digest. There is no published image yet.
- **Wait 3 days before you adopt a release,** unless it is a security fix. Read the release notes and the changes.
- **Verify before you run.** Planned releases carry keyless signatures, an SBOM and provenance. Verify them with `cosign` before you deploy. Today CI signs only a test artifact.
- **tripline does not update itself.**
- **Run as non-root on a read-only root filesystem.** The image is built for this. `just image-check` tests it.
- **Back up before an update.** Copy `state_dir`. Run `tripline audit verify` before and after.
- **Pin your own rules.** Keep your bundle, trust file and config in git.

## Daily checks

- `tripline status`: no `SILENT` source, no unexpected `NOT WATCHED` type, no rejected events.
- The self-test pass rate is 100 percent. A failed probe raises an alert.
- The dead man's switch service shows recent pings.
- `tripline audit verify` passes, and your external anchor matches.
