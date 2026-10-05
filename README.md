# EVR: the service industry's receipt format

EVR (Verified Receipt) is an open format for one thing: proving what happened after a customer conversation.

Every receipt answers four questions in the same shape:

1. Disposition: Booked, Follow-up owned, Escalated, or No conversation
2. Next action: the single next step
3. Owner: the named person or role who owns it
4. Due time: when it is due, with timezone

It works the same for AI agents, people, or both (`handled_by`).

## Write EVR-compatible receipts

Any phone system, CRM, answering service or field service tool can write EVR receipts. No permission and no fee.

1. Produce JSON that matches `schema/evr-core-1.1.0.json`
2. Check it free at https://echocody.ai/evr-schema (free checker on the page)
3. If it passes, you may call your output "EVR-compatible"

See `examples/booked-example.json` for a passing receipt.

## Versions

| Version | Change |
|---|---|
| 1.0.0 | First public release |
| 1.1.0 | Adds optional `handled_by` (ai, human, hybrid). 1.0.0 receipts stay valid |

Minor versions only add optional fields. A breaking change requires a new major version.

## Canonical spec

https://echocody.ai/evr-schema

## License

Specification and schema: Creative Commons Attribution 4.0 (CC BY 4.0). See LICENSE.

Maintained by EchoCody.
