# Support

## Questions and how-to

Check the [README](README.md) and [docs/](docs/) first — `docs/checks.md`
(the generated check catalog), `docs/methodology.md`, and
`docs/core-vs-cloud.md` cover most "how does this work" questions.

For anything else, use [GitHub Discussions](https://github.com/Scovant/scovant-core/discussions)
if enabled on this repository; otherwise open an issue with the `question`
label.

## Bugs and false positives

- A crash, a wrong exit code, or unexpected behavior from the CLI or the
  library: use the [bug report](.github/ISSUE_TEMPLATE/bug_report.yml)
  template.
- A check that fired (or stayed silent) on a real site when it should not
  have: use the [false positive](.github/ISSUE_TEMPLATE/false_positive.yml)
  template — include the check id and the report JSON snippet, that's the
  fastest way to get it fixed.

## Security

Do not open a public issue for a security report. See [SECURITY.md](SECURITY.md)
for the disclosure process (email or GitHub's private vulnerability
reporting).

## Commercial support

Scovant Core is maintained by the team behind [Scovant](https://scovant.com),
which offers hosted scanning, browser-based agent simulation, and CI
regression detection built on the same evidence layer. For commercial
support, custom checks, or integration help, see https://scovant.com.
