# Implementation Plan: Robustness and Error Handling Improvements

## Objective
Enhance the reliability and user-friendliness of the scanner by implementing subscription retries and improving resource exhaustion handling.

## Changes

### 1. `scanner/subscriptions.py` (Subscription Retry Logic)
- **Modify `fetch_subscription`**:
    - Implement a retry loop with exponential backoff.
    - Retry on `httpx.RequestError` and `httpx.TimeoutException`.
    - Do **not** retry on `ValueError` (payload issues) or `httpx.HTTPStatusError` (unless it's a 5xx server error).
    - Limit retries (e.g., max 3 attempts).

### 2. `scanner/main.py` (Resource Exhaustion Safety)
- **Enhance `PortPool`**:
    - Update `acquire` to use a timeout instead of blocking indefinitely.
- **Harden `test_node`**:
    - Catch timeouts from `ports.acquire()`.
    - If a port isn't available, mark the node as `ERROR` with a descriptive message: `"Could not acquire local port (timeout/exhaustion)"`.
- **Improve Threading Robustness**:
    - Ensure `RuntimeError` from `pool.submit` (thread exhaustion) is caught and logged with a clear message.

### 3. `README.md` (Documentation)
- Add a section for "New Features" including the **Interactive HTML Report**.
- Add a section for "Reliability Improvements" (Retries, Resource Safety).

### 4. Git (Deployment)
- Commit all changes.
- Push to the current branch.

## Verification
- Verify that `fetch_subscription` actually retries on network errors.
- Verify that `test_node` handles port acquisition failures gracefully without crashing the sweep.
- Confirm the HTML report and README updates are present.