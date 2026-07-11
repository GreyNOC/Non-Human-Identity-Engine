"""Generate a synthetic benchmark corpus for the GreyNOC NHI engine.

Creates two trees under the given output root:
  perf_repo/   - large repo for timing (mostly clean source + noise dirs)
  detect_repo/ - labeled corpus: planted/<id>.<ext> files each containing ONE
                 fake-but-format-valid secret, and placebo/ files that must NOT fire.

All secret values are synthetic (random) but follow real provider formats.
"""
from __future__ import annotations

import random
import shutil
import string
import sys
from pathlib import Path

random.seed(42)

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"


def r(chars: str, n: int) -> str:
    return "".join(random.choice(chars) for _ in range(n))


# ---------------------------------------------------------------- planted secrets
# id -> (filename, content). Each file plants exactly one secret.
def planted_files() -> dict[str, tuple[str, str]]:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + r(ALNUM, 40)
        + "."
        + r(ALNUM + "-_", 43)
    )
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(r(B64, 64) for _ in range(6))
        + "\n-----END RSA PRIVATE KEY-----\n"
    )
    items: dict[str, tuple[str, str]] = {
        "aws_akia": (".env", f"AWS_ACCESS_KEY_ID=AKIA{r(string.ascii_uppercase + string.digits, 16)}\nAWS_SECRET_ACCESS_KEY={r(B64, 40)}\n"),
        "github_pat_classic": ("config.py", f'GITHUB_TOKEN = "ghp_{r(ALNUM, 36)}"\n'),
        "github_pat_fine": ("deploy.sh", f'export GH_TOKEN="github_pat_{r(ALNUM, 22)}_{r(ALNUM, 59)}"\n'),
        "github_oauth": ("app.js", f'const token = "gho_{r(ALNUM, 36)}";\n'),
        "gitlab_pat": (".gitlab-ci.yml", f"variables:\n  GITLAB_TOKEN: glpat-{r(ALNUM + '-_', 20)}\n"),
        "slack_bot": ("bot.py", f'SLACK_BOT_TOKEN = "xoxb-{r(string.digits, 12)}-{r(string.digits, 12)}-{r(ALNUM, 24)}"\n'),
        "slack_webhook": ("notify.ts", f'const url = "https://hooks.slack.com/services/T{r(string.ascii_uppercase + string.digits, 8)}/B{r(string.ascii_uppercase + string.digits, 8)}/{r(ALNUM, 24)}";\n'),
        "stripe_live": ("payments.rb", f'Stripe.api_key = "sk_live_{r(ALNUM, 32)}"\n'),
        "stripe_restricted": ("settings.ini", f"[stripe]\nkey = rk_live_{r(ALNUM, 32)}\n"),
        "openai_project": (".env", f"OPENAI_API_KEY=sk-proj-{r(ALNUM + '-_', 74)}\n"),
        "openai_svcacct": ("gateway.yaml", f"api_key: sk-svcacct-{r(ALNUM + '-_', 74)}\n"),
        "anthropic": ("claude.py", f'client = Anthropic(api_key="sk-ant-api03-{r(ALNUM + "-_", 93)}")\n'),
        "google_api": ("firebase.json", '{"apiKey": "AIza' + r(ALNUM + "-_", 35) + '"}\n'),
        "npm_token": (".npmrc", f"//registry.npmjs.org/:_authToken=npm_{r(ALNUM, 36)}\n"),
        "pypi_token": (".pypirc", f"[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmc{r(ALNUM + '-_', 60)}\n"),
        "huggingface": ("model_load.py", f'token = "hf_{r(ALNUM, 34)}"\n'),
        "sendgrid": ("mailer.js", f'const key = "SG.{r(ALNUM + "-_", 22)}.{r(ALNUM + "-_", 43)}";\n'),
        "twilio_sid": ("sms.py", f'client = Client("AC{r(HEX, 32)}", "{r(ALNUM, 32)}")\nTWILIO_AUTH_TOKEN = "{r(HEX, 32)}"\n'),
        "digitalocean": ("infra.tf", f'variable "do_token" {{\n  default = "dop_v1_{r(HEX, 64)}"\n}}\n'),
        "databricks": ("dbx.cfg", f"[DEFAULT]\ntoken = dapi{r(HEX, 32)}\n"),
        "jwt_token": ("session.md", f"Use this token:\n\n    Authorization: Bearer {jwt}\n"),
        "pem_key": ("server_key.txt", pem),
        "postgres_url": (".env", f"DATABASE_URL=postgres://svc_app:{r(ALNUM, 24)}@db.internal:5432/prod\n"),
        "mongodb_srv": ("db.yaml", f"uri: mongodb+srv://admin:{r(ALNUM, 24)}@cluster0.abcde.mongodb.net/app\n"),
        "discord_bot": ("discord_bot.py", f'TOKEN = "{r(ALNUM, 24)}.{r(ALNUM, 6)}.{r(ALNUM + "-_", 27)}"\nbot.run(TOKEN)\n'),
        "telegram_bot": ("tg.env", f"TELEGRAM_BOT_TOKEN={r(string.digits, 10)}:AA{r(ALNUM + '-_', 33)}\n"),
        "azure_storage": ("appsettings.json", '{"ConnectionStrings": {"blob": "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=' + r(B64, 86) + '==;EndpointSuffix=core.windows.net"}}\n'),
        "cloudflare": ("cf_deploy.sh", f'export CLOUDFLARE_API_TOKEN="{r(ALNUM + "-_", 40)}"\n'),
        "vercel": (".env.production", f"VERCEL_TOKEN={r(ALNUM, 24)}\n"),
        "fly_token": ("fly_deploy.ps1", f'$env:FLY_API_TOKEN = "fm2_{r(B64, 40)}"\n'),
        "doppler": ("ci.yml", f"env:\n  DOPPLER_TOKEN: dp.st.prd.{r(ALNUM, 40)}\n"),
        "linear_api": ("linear.ts", f'const key = "lin_api_{r(ALNUM, 40)}";\n'),
        "generic_entropy": ("legacy_config.conf", f"service_password = {r(B64, 48)}\n"),
        "mcp_env_secret": (".mcp.json", '{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_' + r(ALNUM, 36) + '"}}}}\n'),
        "gha_secret_echo": (".github/workflows/deploy.yml", "on: push\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.PROD_DEPLOY_KEY }} > key.pem\n"),
        "k8s_secret_env": ("k8s/app.yaml", f"apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      env:\n        - name: API_SECRET\n          value: {r(B64, 32)}\n"),
    }
    return items


# ---------------------------------------------------------------- placebo files (must NOT fire)
def placebo_files() -> dict[str, tuple[str, str]]:
    return {
        "aws_docs_example": ("readme_snippet.md", "Example: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
        "env_example": (".env.example", "OPENAI_API_KEY=\nDATABASE_URL=postgres://user:password@localhost:5432/dev\nSTRIPE_KEY=sk_test_" "xxxxxxxxxxxxxxxxxxxxxxxx\n"),
        "placeholder_changeme": ("setup.cfg", "[app]\napi_key = CHANGEME\npassword = changeme123\n"),
        "placeholder_angle": ("install.md", 'Set `API_KEY="<YOUR_API_KEY_HERE>"` before running.\n'),
        "placeholder_your": ("config.sample.yaml", "token: your-token-here\nsecret: REPLACE_WITH_SECRET\n"),
        "all_x": ("template.env", "SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"),
        "lorem_b64ish": ("notes.txt", "The quick brown fox jumps over the lazy dog repeatedly today.\n"),
        "test_dummy": ("test_auth.py", 'def test_login():\n    fake_key = "sk_test_00000000000000000000000000"\n    assert fake_key.startswith("sk_test_")\n'),
    }


# ---------------------------------------------------------------- perf repo
PY_BODY = '''"""Module {i} for the synthetic benchmark app."""
import json
import os


def handler_{i}(event, context):
    payload = json.loads(event.get("body") or "{{}}")
    result = {{"ok": True, "id": payload.get("id"), "n": {i}}}
    return {{"statusCode": 200, "body": json.dumps(result)}}


def helper_{i}(values):
    total = 0
    for v in values:
        total += int(v) * {i}
    return total
'''

TS_BODY = '''// service module {i}
export interface Item{i} {{ id: string; count: number }}

export function process{i}(items: Item{i}[]): number {{
  return items.reduce((acc, it) => acc + it.count * {i}, 0);
}}
'''

YAML_BODY = '''# pipeline fragment {i}
stages:
  - build
  - test
build_{i}:
  stage: build
  script:
    - make build-{i}
'''


def build_perf_repo(root: Path, n_src: int = 3000, n_noise: int = 2000) -> None:
    src = root / "src"
    for i in range(n_src):
        sub = src / f"pkg{i % 40}"
        sub.mkdir(parents=True, exist_ok=True)
        if i % 3 == 0:
            (sub / f"mod_{i}.py").write_text(PY_BODY.format(i=i), encoding="utf-8")
        elif i % 3 == 1:
            (sub / f"svc_{i}.ts").write_text(TS_BODY.format(i=i), encoding="utf-8")
        else:
            (sub / f"cfg_{i}.yaml").write_text(YAML_BODY.format(i=i), encoding="utf-8")
    # noise dirs that must be pruned
    nm = root / "node_modules"
    for i in range(n_noise):
        sub = nm / f"pkg-{i % 100}"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"index_{i}.js").write_text(f"module.exports = {i};\n", encoding="utf-8")
    git = root / ".git" / "objects"
    for i in range(200):
        sub = git / f"{i:02x}"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"obj{i}").write_bytes(b"\x00" * 64)
    # a sprinkle of real config files
    (root / ".env").write_text("APP_ENV=production\nLOG_LEVEL=info\n", encoding="utf-8")
    (root / "package.json").write_text('{"name": "bench-app", "scripts": {"build": "tsc", "deploy": "sh deploy.sh"}}\n', encoding="utf-8")
    (root / "docker-compose.yml").write_text("services:\n  app:\n    image: bench:latest\n", encoding="utf-8")
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text("on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: make test\n", encoding="utf-8")


def build_detect_repo(root: Path) -> None:
    planted = root / "planted"
    for pid, (fname, content) in planted_files().items():
        d = planted / pid
        target = d / fname
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    placebo = root / "placebo"
    for pid, (fname, content) in placebo_files().items():
        d = placebo / pid
        target = d / fname
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "bench_corpus")
    if out.exists():
        shutil.rmtree(out)
    build_perf_repo(out / "perf_repo")
    build_detect_repo(out / "detect_repo")
    n_files = sum(1 for _ in (out / "perf_repo").rglob("*") if _.is_file())
    print(f"perf_repo files: {n_files}")
    print(f"planted secrets: {len(planted_files())}")
    print(f"placebo cases:   {len(placebo_files())}")
    print(f"corpus at: {out.resolve()}")


if __name__ == "__main__":
    main()
