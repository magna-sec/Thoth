"""web.config parser — connection strings, secrets, keys, credentials and URLs."""
import io

import pytest

from app.extensions import db
from app.models import Artifact
from app.webconfigparse import looks_like_webconfig, parse_webconfig

WC = r"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="Main" providerName="System.Data.SqlClient"
         connectionString="Server=sql01.corp.local;Database=AppDb;User ID=appsvc;Password=S3cr3t!Pass;" />
    <add name="Win" connectionString="Data Source=db2;Initial Catalog=Reports;Integrated Security=SSPI;" />
  </connectionStrings>
  <appSettings>
    <add key="ApiEndpoint" value="https://api.internal.corp/v2/" />
    <add key="StorageAccountKey" value="Zm9vYmFyYmF6cXV4MTIzNA==" />
    <add key="FeatureFlag" value="true" />
  </appSettings>
  <system.web>
    <machineKey validationKey="ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
                decryptionKey="1111222233334444555566667777888899990000AAAABBBB" validation="SHA1" decryption="AES" />
    <compilation debug="true" targetFramework="4.7" />
    <customErrors mode="Off" />
    <authentication mode="Forms">
      <forms><credentials passwordFormat="Clear">
        <user name="admin" password="P@ssw0rd123" />
      </credentials></forms>
    </authentication>
    <identity impersonate="true" userName="CORP\svc_web" password="ImpersonateMe1" />
    <trace enabled="true" localOnly="false" />
  </system.web>
  <system.net><mailSettings>
    <smtp from="noreply@corp.local"><network host="smtp.corp.local" port="587"
          userName="mailer" password="Mail3rPass" /></smtp>
  </mailSettings></system.net>
</configuration>"""

# A hardened file: auto-generated key, Windows auth, no plaintext secrets.
SAFE = r"""<configuration>
  <appSettings><add key="Safe" value="42" /></appSettings>
  <system.web>
    <machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps" />
    <customErrors mode="RemoteOnly" />
  </system.web>
</configuration>"""


def test_extracts_connection_string_password():
    d = parse_webconfig(WC)
    cs = {c["name"]: c for c in d["files"][0]["connection_strings"]}
    assert cs["Main"]["parsed"]["password"] == "S3cr3t!Pass"
    assert cs["Main"]["parsed"]["server"] == "sql01.corp.local"
    assert cs["Main"]["parsed"]["user"] == "appsvc" and cs["Main"]["has_password"]
    assert cs["Win"]["parsed"]["integrated"] and not cs["Win"]["has_password"]


def test_flags_the_juicy_bits():
    titles = {f["title"] for f in parse_webconfig(WC)["findings"]}
    assert {"Connection-string password", "Static machineKey",
            "Forms-auth plaintext credentials", "Impersonation identity",
            "SMTP credentials", "Secret in appSettings",
            "compilation debug=\"true\"", "customErrors mode=\"Off\"",
            "ASP.NET trace enabled"} <= titles


def test_secrets_and_urls_and_appsettings():
    f = parse_webconfig(WC)["files"][0]
    settings = {a["key"]: a for a in f["app_settings"]}
    assert settings["StorageAccountKey"]["secret"] and not settings["FeatureFlag"]["secret"]
    assert settings["ApiEndpoint"]["is_url"]
    assert "https://api.internal.corp/v2/" in f["urls"]


def test_autogenerate_machinekey_not_flagged_static():
    d = parse_webconfig(SAFE)
    assert d["files"][0]["machine_key"]["static"] is False
    titles = {f["title"] for f in d["findings"]}
    assert "Static machineKey" not in titles


def test_multiple_documents_named_by_header():
    blob = ("===== C:\\inetpub\\wwwroot\\app\\web.config =====\n" + WC
            + "\n===== C:\\inetpub\\wwwroot\\other\\web.config =====\n" + SAFE)
    d = parse_webconfig(blob)
    assert d["summary"]["files"] == 2
    names = [f["name"] for f in d["files"]]
    assert names[0].endswith("app\\web.config") and names[1].endswith("other\\web.config")
    # findings carry their source file so a mixed upload stays attributable
    pw = [f for f in d["findings"] if f["title"] == "Connection-string password"][0]
    assert pw["file"].endswith("app\\web.config")


def test_detection_and_rejection():
    assert looks_like_webconfig(WC)
    assert not looks_like_webconfig("just some prose, no config here")
    with pytest.raises(ValueError):
        parse_webconfig("")
    with pytest.raises(ValueError):
        parse_webconfig("<nmaprun><host/></nmaprun>")


def test_plugin_registered_with_collect_command():
    from app.plugins import get_parser
    p = get_parser("webconfig")
    assert p is not None and p.kind == "artifact"
    assert "web.config" in p.collect and "Get-ChildItem" in p.collect


def test_route_parses_renders_and_advertises_collect(client, app, workspace):
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": WC, "kind": "auto"},
                       follow_redirects=True).data.decode()
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace, kind="webconfig").one()
        assert art.data_json["summary"]["connection_strings"] == 2
    assert "S3cr3t!Pass" in page and "Static machineKey" in page
    hub = client.get(f"/workspaces/{workspace}").data.decode()
    assert "web.config" in hub


def test_upload_multiple_files_at_once(client, app, workspace):
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"kind": "webconfig", "content": "", "file": [
                    (io.BytesIO(WC.encode()), "app.web.config"),
                    (io.BytesIO(SAFE.encode()), "other.web.config"),
                ]}, content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace, kind="webconfig").one()
        assert art.data_json["summary"]["files"] == 2
        assert art.name == "app.web.config, other.web.config"
