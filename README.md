# okta events hook
A lambda function that receives events from okta and forward the data as logs to logz.io

## User Guide
### Configuring an Okta Event Hook for Your Logz.io

This guide explains how to configure an Okta Event Hook that sends selected System Log events to logz.io. The integration requires custom headers (`logzio_token`, `logzio_region`) for authentication and region routing.

---

### Prerequisites

- **Okta Admin Access** – To configure event hooks.
- **Logz.io shipping token** (32-character) 
- **Logz.io region** – e.g., `us`, `au`, `eu`, `uk`, `ca`
---

### 1. Create the Event Hook in Okta

#### 1.1 Navigate to Event Hooks

1. Sign in to the Okta Admin Console.
2. Go to **Workflow → Event Hooks**.

#### 1.2 Add a New Event Hook

1. Click **Create Event Hook**.
2. **Name**: e.g., `LogzIoEventHook`
3. **Endpoint URL**: Logz.io Lambda URL:
   ```
   https://okta.listener-logz.io
   ```

#### 1.3 Configure Authentication & Headers

2. **Headers**:
    - `logzio_token`: your Logz.io shipping token
    - `logzio_region`: your Logz.io region (`us`, `au`, `eu`, `ca`, `uk`)

#### 1.4 Select Events

- Choose one or more events to subscribe to, e.g., `user.lifecycle.deactivate`, `user.session.start`.

#### 1.5 Verify Ownership

1. Save the hook.
2. Okta will send a one-time **GET** request with the `x-okta-verification-challenge` header.
---

### 2. Preview & Test the Hook

#### 2.1 Preview Mode

- Use Okta's **Preview** feature to simulate an event and inspect the payload.

#### 2.2 Live Testing

- Trigger an actual Okta event and confirm it appears in your logs and Logz.io dashboard.

---
## Development
### How to create function.zip
```
make function
```
