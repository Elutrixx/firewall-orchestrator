# Temporary rule-positioning forensics

This instrumentation follows one implementation task from FWO's stored normalized importer output through snapshot creation, Check Point graph interpretation, LayerGuard selection, exact section-name comparison, boundary calculation, and persistence. It deliberately records a large amount of customer policy data. Deploy it only on the test system and revert it after collecting the required evidence.

The importer boundary is `latest_config`: the report proves what the importer handed to FWO at its last successful import. It does not prove what currently exists on the Check Point management server.

## Before the test

1. Deploy the temporary forensic commit through the normal FWO installer/deployment route. The existing middleware `dotnet publish` step includes the collector; no new package, service, database migration, or installer variable is required.
2. Confirm `fworch-middleware` is active.
3. Prefer the existing last successful import. A fresh import is unnecessary when the report's `latest_config.import_id` agrees with the import selected by positioning. If no matching `latest_config` exists, request and separately authorize a new import; the collector never triggers one.
4. Create or retrigger a new applicable implementation task and note its positive implementation-task ID.

The default inventory values used below are `/usr/local/fworch`, `Release`, and .NET `10.0`. If the customer inventory overrides `fworch_home`, `dotnet_mode`, or `dotnet_version`, use the corresponding deployed publish path.

## Create the one-file report

From a directory where the invoking operator may create the report, run:

```bash
IMPL_TASK_ID=42
sudo python3 /usr/local/fworch/middleware/files/FWO.Middleware.Server/bin/Release/net10.0/Diagnostics/rule_positioning_forensics.py \
  "$IMPL_TASK_ID" --output-dir "$PWD"
```

Replace `42` with the real implementation-task ID. The command prints only the final `.txt` path on success. The report is mode `0600`; when invoked through `sudo`, the collector returns ownership to the invoking user.

Copy that single printed file from the customer VM. It contains the full normalized `latest_config`, historical database rows, structured attempt artifacts, exact string representations, a bounded middleware journal window, integrity hashes, and an automatic first-loss conclusion.

Read section `02 COMPLETENESS AND IMPORT DRIFT` first:

- `COMPLETE` means all required local evidence was readable, every attempt had a terminal record, and `latest_config.import_id` stayed stable during collection.
- `INCOMPLETE` lists each missing, inaccessible, corrupt, or drifted source. The remaining evidence is still included.

Section `10 AUTOMATIC CONCLUSION` is an independent reconciliation aid, not a replacement for checking the raw handoff evidence in sections 03-09.

## Remove the temporary instrumentation

After confirming the copied report opens correctly and contains the expected task ID:

1. Revert the single forensic commit.
2. Redeploy through the normal installer/deployment route.
3. Retriggering or calculating another task must no longer create a new directory under `/usr/local/fworch/tmp/rule-positioning-forensics/`.
4. Only after the copied report is confirmed usable, remove the customer-side report and the task's restricted artifact directory. For example, after replacing the ID and verifying the resolved path:

   ```bash
   sudo rm -r -- /usr/local/fworch/tmp/rule-positioning-forensics/impltask-42
   ```

The copied report itself contains sensitive policy and workflow data. Store and transfer it with the same controls used for customer configuration exports.
