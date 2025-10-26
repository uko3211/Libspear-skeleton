import json
import base64
import re
from typing import Any, Dict
import aiohttp
from .utils.escape import joern_literal, strip_ansi


class JoernClient:
    """Python Joern client using synchronous HTTP query endpoint.

    Communicates only over HTTP to `/query-sync`, which returns
    `{ success, stdout, stderr, uuid }` in a single response.
    """
    
    def __init__(self, host: str, username: str = 'admin', password: str = 'admin') -> None:
        """Initialize the Joern client.
        
        Args:
            host: Host and port in format 'hostname:port'
            username: Username for authentication
            password: Password for authentication
        """
        self.host = host
        self.username = username
        self.password = password
        self._auth_header = self._create_auth_header()
        
    def _create_auth_header(self) -> str:
        """Create Basic Auth header."""
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
        
    async def _post_query(self, data: str) -> Dict[str, Any]:
        """Post a query to the Joern server and return the JSON result."""
        url = f"http://{self.host}/query-sync"
        headers = {
            'Authorization': self._auth_header,
            'Content-Type': 'application/json'
        }
        payload = {'query': data}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if not response.ok:
                    raise Exception(f"HTTP error! status: {response.status}")
                return await response.json()
    
    
    async def q(self, query_template: str, *args: Any) -> Any:
        """Execute a query using template string interpolation.
        
        This is the Python equivalent of the TypeScript template literal method.
        
        Args:
            query_template: Query template with {} placeholders for arguments
            *args: Arguments to interpolate into the template
            
        Returns:
            Query result
        """
        if args:
            
            joern_args = [joern_literal(arg) for arg in args]
            data = query_template.format(*joern_args)
        else:
            data = query_template
        
        result = await self._post_query(data)
        
        if not result['success']:
            raise Exception(f"Query failed: {result['stderr']}")
        
        stdout = strip_ansi(result['stdout'])
        
        stdout = re.sub(r'^val res\d+:.*?= ', '', stdout).strip()
        
        if ((stdout.startswith('"{') and stdout.endswith('}"')) or
            (stdout.startswith('"[') and stdout.endswith(']"'))):
            stdout = json.loads(json.loads(stdout))
        elif ((stdout.startswith('"""{') and stdout.endswith('}"""')) or
              (stdout.startswith('"""[') and stdout.endswith(']"""'))):
            stdout = json.loads(stdout[3:-3])
        
        return stdout
    
    async def close(self) -> None:
        """No-op for sync mode (kept for API compatibility)."""
        return None


    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()