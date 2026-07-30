---
name: case-design
description: Generate structured QA cases, assertions, preconditions, steps, and expected outcomes. Export to xlsx when download is requested.
---

# Case Design

Use this skill to transform requirements or risks into executable test coverage.

## Tool Workflow

When the user requests test case generation, follow this workflow:

1. **Generate test cases**: Call the `test-case-generator` tool with the feature name, requirements, acceptance criteria, and risk focus extracted from the user's request.
2. **Export to xlsx** (when the user asks for a downloadable file or Excel export): Call the `test-case-xlsx-exporter` tool, passing the `cases` array from step 1 and the `feature` name. The tool will return `download_urls` and `download_markdown` in its output.
3. **Provide download link**: After the xlsx exporter returns, you MUST include the download link in your response. **Copy the `download_markdown` string verbatim into your response** — do NOT reformat it, do NOT write the URL as plain text. The `download_markdown` field contains a ready-to-use markdown link like `[点击下载 filename.xlsx](/api/v1/sessions/.../artifacts/.../content)`. This format is required for the frontend to render a clickable download button.

## Case Structure

Each case should include:
- Scenario title
- Preconditions and test data
- Steps
- Expected result
- Assertions
- Priority and risk rationale
- Automation feasibility

## Important

- Do NOT invent tool names. Use exactly: `test-case-generator` for generation and `test-case-xlsx-exporter` for xlsx export.
- The `test-case-generator` produces structured cases with id, title, type, priority, platforms, preconditions, steps, assertions, and risk_focus.
- The `test-case-xlsx-exporter` accepts a `cases` array (from the generator output) and an optional `feature` name.
- When the user asks for a downloadable file, you MUST call `test-case-xlsx-exporter` instead of outputting raw text tables. The xlsx exporter will produce a downloadable file automatically.
- After the xlsx exporter completes, you MUST copy the `download_markdown` field from the tool output into your response **verbatim**. Do NOT write the download URL as plain text — it must be a markdown link for the frontend to render a clickable download button.
