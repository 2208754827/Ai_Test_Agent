---
name: case-design
description: Generate structured QA cases, assertions, preconditions, steps, and expected outcomes.
---

# Case Design

Use this skill to transform requirements or risks into executable test coverage.

## Tool Workflow

1. Generate structured cases with `test-case-generator`.
2. When the user requests an Excel file, pass the generated `cases` to `test-case-xlsx-exporter`.
3. Include the returned `download_markdown` unchanged in the response.

Each case should include:
- Scenario title
- Preconditions and test data
- Steps
- Expected result
- Assertions
- Priority and risk rationale
- Automation feasibility
