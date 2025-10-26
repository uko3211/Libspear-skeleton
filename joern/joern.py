from typing import Optional
from .client import JoernClient


class Joern:
    """Python port of the TypeScript Joern class.
    
    Main interface for interacting with Joern server.
    Provides high-level methods for code analysis operations.
    """
    
    def __init__(self, host: str, username: str = 'admin', password: str = 'admin'):
        """Initialize Joern client.
        
        Args:
            host: Host and port in format 'hostname:port'
            username: Username for authentication (default: 'admin')
            password: Password for authentication (default: 'admin')
        """
        self.client = JoernClient(host, username, password)
    
    async def close(self, project_name: Optional[str] = None) -> str:
        """Close project by name.
        
        Args:
            project_name: Name of project to close (optional)
            
        Returns:
            Query result
        """
        if project_name:
            return await self.client.q("close({})", project_name)
        else:
            return await self.client.q("close")
    
    async def delete(self, project_name: str) -> str:
        """Close and remove project from disk.
        
        Args:
            project_name: Name of project to delete
            
        Returns:
            Query result
        """
        return await self.client.q("delete({})", project_name)
    
    async def exit(self) -> str:
        """Exit the Joern REPL.
        
        Returns:
            Query result
        """
        return await self.client.q("exit")
    
    async def import_code(self, 
                         input_path: str, 
                         project_name: Optional[str] = None,
                         namespaces: Optional[str] = None,
                         language: Optional[str] = None) -> str:
        """Create new project from code.
        
        Args:
            input_path: Path to the input code
            project_name: Name for the project (optional)
            namespaces: Namespaces to include (optional)
            language: Programming language (optional)
            
        Returns:
            Query result
        """
        template = ["importCode(inputPath={}"]
        args = [input_path]
        if project_name is not None:
            template.append(", projectName={}")
            args.append(project_name)
        if namespaces is not None:
            template.append(", namespaces={}")
            args.append(namespaces)
        if language is not None:
            template.append(", language={}")
            args.append(language)
        template.append(")")
        return await self.client.q("".join(template), *args)
    
    async def import_cpg(self,
                        cpg_path: str,
                        project_name: Optional[str] = None,
                        enhance: Optional[bool] = None) -> str:
        """Create new project from existing CPG.
        
        Args:
            cpg_path: Path to the CPG file
            project_name: Name for the project (optional)
            enhance: Whether to enhance the CPG (optional)
            
        Returns:
            Query result
        """
        template = ["importCpg(cpgPath={}"]
        args = [cpg_path]
        if project_name is not None:
            template.append(", projectName={}")
            args.append(project_name)
        if enhance is not None:
            template.append(", enhance={}")
            args.append(enhance)
        template.append(")")
        return await self.client.q("".join(template), *args)
    
    async def open(self, project_name: str) -> str:
        """Open project by name.
        
        Args:
            project_name: Name of project to open
            
        Returns:
            Query result
        """
        return await self.client.q("open({})", project_name)
    
    async def open_for_input_path(self, input_path: str) -> str:
        """Open project for input path.
        
        Args:
            input_path: Input path for the project
            
        Returns:
            Query result
        """
        return await self.client.q("openForInputPath({})", input_path)
    
    async def project(self) -> str:
        """Get currently active project.
        
        Returns:
            Query result with current project info
        """
        return await self.client.q("project")
    
    async def save(self) -> str:
        """Write all changes to disk.
        
        Returns:
            Query result
        """
        return await self.client.q("save")
    
    async def switch_workspace(self, workspace: str) -> str:
        """Close current workspace and open a different one.
        
        Args:
            workspace: Path to the new workspace
            
        Returns:
            Query result
        """
        return await self.client.q("switchWorkspace({})", workspace)
    
    async def workspace(self) -> str:
        """Access to the workspace directory.

        Returns:
            Query result with workspace info
        """
        return await self.client.q("workspace")