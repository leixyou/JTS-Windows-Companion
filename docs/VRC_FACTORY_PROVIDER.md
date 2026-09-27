# VRC Factory structured worker provider

The Windows Companion can bridge JTS Terminal's `jts_windows_task` MCP tool to the existing VRC Factory `WorkerRuntime` without SSH, Tailscale, an extra listener, or a task-controlled command line. The bridge runs in the logged-in RDP user's session and communicates only over `JTS.Companion.v1`.

## Installation boundary

The installer supplies both values when it registers the Companion startup command:

```powershell
--vrc-worker "C:\Program Files\JTS Terminal\VRC Factory\vrc-factory-worker.exe" `
--vrc-worker-sha256 <64-hex-sha256>
```

Both switches are required together and may appear only once. The worker path must be a fully qualified local `.exe`; UNC paths are rejected. Before every operation, the Companion rejects a missing, directory, or reparse-point executable and compares the full file SHA-256 in constant time. Release packaging must additionally Authenticode-sign the executable and validate that signature in the Windows release matrix.

The executable is an installed fixed-entry wrapper around the existing VRC Factory worker CLI. It must preserve the existing `VRC_FACTORY_WORKER_SPOOL`, `WorkerRuntime`, `FixedUnityOperations`, journal, lease, recovery, ZIP manifest, and result validation behavior. The Companion does not reimplement Unity operations.

## Exact DVC methods

The public surface is intentionally smaller than a general task runner:

| DVC method | Exact accepted parameters | Fixed process invocation |
| --- | --- | --- |
| `worker.doctor` | `{}` | `vrc-factory-worker.exe doctor` |
| `worker.submit` | `{jobId, transferId, totalBytes, bundleSha256}` | `vrc-factory-worker.exe submit-stdin` with the verified spool file streamed to stdin |
| `worker.status` | `{jobId}` | `vrc-factory-worker.exe status --job-id <validated-id>` |
| `worker.cancel` | `{jobId}` | `vrc-factory-worker.exe cancel --job-id <validated-id>` |
| `worker.collect` | `{jobId}` | `vrc-factory-worker.exe collect-stdout --job-id <validated-id>` streamed to a reserved spool file |

Unknown or missing fields are rejected. In particular, a request cannot provide `executable`, `command`, `shell`, `script`, `arguments`, `workingDirectory`, or environment variables. `ProcessStartInfo.ArgumentList` is used with `UseShellExecute=false`; no command shell performs parsing.

Job IDs must match `[a-z0-9][a-z0-9_-]{1,95}`. JSON output and stderr are bounded, per-operation timeouts are fixed, and cancellation kills the process tree. The provider never returns process stderr or an exception message over DVC.

## Integrity and response shape

- `submit` resolves only a finalized `vrc-worker-submit` transfer whose ID, byte count, and SHA-256 exactly match the request. It streams that private spool file to worker stdin and requires the worker's structured response to contain the same `jobId`, a known state, and the same `bundleSha256`.
- `status` and `cancel` require the exact requested `jobId` and a known worker state.
- `collect` streams successful non-empty binary stdout into a private `vrc-worker-result` transfer and returns `{ok, jobId, state, transferId, totalBytes, bundleSha256}`. The Mac downloads and verifies that transfer before restoring the existing MCP `bundleBase64` result field. The existing `collect-stdout` command remains responsible for validating the signed result ZIP and binding it to the job before it writes bytes.
- `doctor` requires the local `platform`, `python`, `unity`, `vpm`, `worker`, `spool`, and `consumer` checks. It intentionally removes the legacy Tailscale check and reports `workerProtocol: fixed-dvc-v1`, because the DVC transport has no SSH/Tailscale dependency.

JTS Terminal adds `transportProof.channel: companion-dvc` after the signed DVC response. Screenshots, OCR, UIA text, or visual success claims never enter this provider and cannot advance VRC production state.

## Binary transfer boundary

The Mac and Windows agents use DVC binary frames with 4 MiB application chunks and a 512 MiB per-transfer limit. Windows keeps payloads in a unique per-agent-session spool rather than in control JSON or managed process memory. Upload resume requires the exact next offset; an already received chunk is accepted only when its bytes match exactly. Download resume starts at the Mac's verified received length. Finalization requires exact byte count, a final marker, and the full SHA-256 digest. At most four transfers may exist concurrently, idle entries expire after 15 minutes, explicit release deletes the file, and agent shutdown removes the session spool.

The external MCP adapter intentionally preserves the existing VRC `bundleBase64` request/result shape so `WorkerClient` commands do not change. That compatibility layer still holds encoded data on the Mac side; the Windows DVC and fixed worker path do not. A future file-backed MCP resource can remove the remaining Mac-side base64 allocation without changing the Companion protocol.

Windows 10/11 x64 execution, Authenticode verification, a real `clean-install-auto` job, result ZIP recovery, and the final `WINDOWS_QA` to `AWAIT_VR` gate remain mandatory real-machine release evidence.
