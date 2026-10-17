# Guidance for AI coding agents

For broker use, read `skills/vmware-guest-agent-broker/SKILL.md` first. For source
changes, read `CONTRIBUTING.md`, the relevant `docs/COMMANDS.md` entries and
`docs/VALIDATION.md`.

- Never place credentials in command-line arguments, environment variables, files,
  helper/supervisor IPC, logs or messages. Use the broker's private native-VIX path.
- Use one exact registered VM name. Do not infer a target from ordering or paths.
- Configured operations run without per-operation approval prompts; setup and
  private credential enrollment/storage are still separate.
- Use only disposable fixtures for mutation. Inspect state after unknown outcomes;
  do not replay clones, deletes or transfers blindly.
- Do not change host networking or expose an existing host directory as a shortcut.
- Report synthetic, local and live evidence separately. Never claim all 47 variants
  passed because the catalog contains 47 command names.
- Run the relevant build/tests and report skipped checks truthfully.
