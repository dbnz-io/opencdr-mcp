"""Request-scoped IAM Core target using the same bounded SigV4 transport as Fleet."""

from .fleet import FleetClient, FleetConnection, FleetError


class CoreTarget:
    def __init__(self, config):
        identity = config.get("deployment", {})
        if set(identity) != {"account_id", "home_region", "stage"}:
            raise FleetError("IAM Core requires account_id, home_region and stage")
        connection = FleetConnection(
            config["url"],
            config.get("aws_profile", ""),
            identity["account_id"],
            identity["home_region"],
            identity["stage"],
            identity=config.get("identity"),
        )
        access = config.get("access", "operator")
        if access not in {
            "observer",
            "delivery",
            "triage",
            "operator",
            "responder",
            "administrator",
        }:
            raise FleetError("Invalid Core management access")
        self.client = FleetClient(connection)
        self.client.path_prefix = "/"
        self.client.base_url = connection.url.rstrip("/") + "/management/" + access
        self.identity = identity
        self.report = None

    def verify(self):
        code, report = self.client.request("GET", "/status")
        if (
            code != 200
            or not isinstance(report, dict)
            or report.get("product") != "OpenCDR Core"
            or report.get("deployment") != self.identity
            or str(report.get("management_contract_version", "")).split(".")[0] != "2"
            or not report.get("capabilities", {}).get("iam_management")
        ):
            raise FleetError("Core identity or IAM contract mismatch; no operation sent")
        self.report = report

    def request(self, method, path, **kwargs):
        if path.startswith("//"):
            raise FleetError("Invalid Core path")
        if self.report is None:
            self.verify()
        return self.client.request(
            method, path, json_body=kwargs.get("json"), params=kwargs.get("params")
        )
