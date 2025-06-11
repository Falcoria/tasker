from app.config import config
from app.connectors.base import BaseConnector


ROUTES = {
    "ips_list": "projects/{project_id}/ips"
}


class ScanledgerConnector(BaseConnector):
    def __init__(self, scanledger_base_url: str, auth_token: str):
        super().__init__(scanledger_base_url, auth_token)

    async def get_ips(self, project_id: str, has_ports: bool = True):
        query = {"has_ports": has_ports}
        endpoint = ROUTES["ips_list"].format(project_id=project_id)
        response = await self.make_request(endpoint, query_params=query)
        return self._handle_response(response)
    
    async def post_ips(self, project_id: str, body: dict, query: dict = None):
        endpoint = ROUTES["ips_list"].format(project_id=project_id)
        response = await self.make_request(endpoint, method="POST", json=body, query_params=query)
        return self._handle_response(response)


scanledger_connector = ScanledgerConnector(
    scanledger_base_url=config.scanledger_base_url,
    auth_token=config.tasker_auth_token
)