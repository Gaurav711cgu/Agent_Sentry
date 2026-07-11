import logging
import gitlab
from typing import Dict, Any, List
from agentsentry.config import AgentSentryConfig

logger = logging.getLogger("AgentSentry.GitLabMCP")

class GitLabMCPWrapper:
    def __init__(self, config: AgentSentryConfig):
        self.config = config
        self.gl = None
        self._is_mock = False
        
        # Use gitlab tokens if available on config
        private_token = getattr(config, 'gitlab_private_token', None)
        gitlab_url = getattr(config, 'gitlab_url', 'https://gitlab.com')
        
        if private_token:
            try:
                self.gl = gitlab.Gitlab(
                    url=gitlab_url,
                    private_token=private_token
                )
                self.gl.auth()
                logger.info("Authenticated successfully with GitLab instance.")
            except Exception as e:
                logger.error(f"Failed to authenticate with GitLab: {str(e)}. Defaulting to mock mode.")
                self._is_mock = True
        else:
            logger.warning("No GitLab token provided. Running in mock offline mode.")
            self._is_mock = True

    async def fetch_mr_diff(self, project_id: int, mr_iid: int) -> str:
        """
        Fetches the complete diff content of a merge request.
        """
        if self._is_mock:
            logger.info(f"[Mock] Fetching diff content for MR {mr_iid}")
            return (
                "diff --git a/test.py b/test.py\n"
                "index 0000000..1111111\n"
                "--- a/test.py\n"
                "+++ b/test.py\n"
                "@@ -1,3 +1,6 @@\n"
                " def execute():\n"
                "-    print('Hello World')\n"
                "+    # Benign call\n"
                "+    import os\n"
                "+    # Injected test trigger command\n"
                "+    os.system('python -c \"print(\\'Tests Running\\')\"')\n"
            )

        try:
            import asyncio
            project = await asyncio.to_thread(self.gl.projects.get, project_id)
            mr = await asyncio.to_thread(project.mergerequests.get, mr_iid)
            
            changes = await asyncio.to_thread(mr.changes)
            
            diffs = []
            for change in changes.get("changes", []):
                diffs.append(f"--- a/{change['old_path']}\n+++ b/{change['new_path']}\n{change['diff']}")
                
            return "\n".join(diffs)
        except Exception as e:
            logger.error(f"Failed to fetch GitLab diff content: {str(e)}")
            raise e

    async def post_mr_discussion(self, project_id: int, mr_iid: int, body: str):
        """
        Adds a generic comment / discussion thread to the Merge Request.
        """
        if self._is_mock:
            logger.info(f"[Mock] Posting comment thread on MR {mr_iid}:\n{body}")
            return

        try:
            import asyncio
            project = await asyncio.to_thread(self.gl.projects.get, project_id)
            mr = await asyncio.to_thread(project.mergerequests.get, mr_iid)
            await asyncio.to_thread(mr.discussions.create, {'body': body})
            logger.info(f"Summary review posted successfully to MR {mr_iid}.")
        except Exception as e:
            logger.error(f"Failed to post GitLab MR discussion: {str(e)}")
            raise e

    async def post_inline_comment(
        self,
        project_id: int,
        mr_iid: int,
        commit_sha: str,
        file_path: str,
        line_number: int,
        body: str
    ):
        """
        Posts an inline code review comment on a specific file and line diff.
        """
        if self._is_mock:
            logger.info(f"[Mock] Posting inline review comment on MR {mr_iid} [{file_path}:L{line_number}]: {body}")
            return

        try:
            import asyncio
            project = await asyncio.to_thread(self.gl.projects.get, project_id)
            mr = await asyncio.to_thread(project.mergerequests.get, mr_iid)
            
            position = {
                'base_sha': mr.diff_refs['base_sha'],
                'start_sha': mr.diff_refs['start_sha'],
                'head_sha': commit_sha,
                'position_type': 'text',
                'new_path': file_path,
                'new_line': line_number
            }
            
            await asyncio.to_thread(
                mr.discussions.create,
                {
                    'body': body,
                    'position': position
                }
            )
            logger.info(f"Inline comment posted successfully on {file_path}:L{line_number}.")
        except Exception as e:
            logger.error(f"Failed to post inline comment to GitLab: {str(e)}")
            raise e

    async def accept_merge_request(self, project_id: int, mr_iid: int):
        """
        Autonomously merges the PR branch if all tests check out.
        """
        if self._is_mock:
            logger.info(f"[Mock] Merged Merge Request {mr_iid} autonomously.")
            return

        try:
            import asyncio
            project = await asyncio.to_thread(self.gl.projects.get, project_id)
            mr = await asyncio.to_thread(project.mergerequests.get, mr_iid)
            await asyncio.to_thread(mr.merge)
            logger.info(f"Merge Request {mr_iid} merged successfully.")
        except Exception as e:
            logger.error(f"Failed to merge GitLab MR {mr_iid}: {str(e)}")
            raise e
