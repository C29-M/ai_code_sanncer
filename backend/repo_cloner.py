import re
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

from git import GitCommandError, Repo

from exceptions import InvalidRepoUrlError, RepoCloneError

GITHUB_HTTPS_PATTERN = re.compile(
    r"^https://github\.com/[\w.\-]+/[\w.\-]+(?:\.git)?/?$",
    re.IGNORECASE,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPOSITORIES_DIR = PROJECT_ROOT / "temp" / "repositories"


def validate_github_url(repo_url: str) -> str:
    """Normalize and validate a public GitHub HTTPS URL."""
    parsed = urlparse(repo_url.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise InvalidRepoUrlError("Only HTTPS GitHub URLs are supported.")

    segments = [part for part in parsed.path.split("/") if part]
    if len(segments) != 2:
        raise InvalidRepoUrlError(
            "URL must point to a repository (https://github.com/owner/repo)."
        )

    owner, repo = segments
    repo = repo.removesuffix(".git")
    normalized = f"https://github.com/{owner}/{repo}"
    if not GITHUB_HTTPS_PATTERN.match(normalized):
        raise InvalidRepoUrlError("Repository URL format is invalid.")

    return normalized


def _destination_name(repo_url: str) -> str:
    segments = [part for part in urlparse(repo_url).path.split("/") if part]
    owner, repo = segments[0], segments[1].removesuffix(".git")
    suffix = uuid.uuid4().hex[:8]
    return f"{owner}_{repo}_{suffix}"


def clone_repository(repo_url: str) -> Path:
    """
    Clone a GitHub repository into ./temp/repositories/.

    Returns the local path to the cloned repository.
    """
    normalized_url = validate_github_url(repo_url)
    REPOSITORIES_DIR.mkdir(parents=True, exist_ok=True)

    destination = REPOSITORIES_DIR / _destination_name(normalized_url)

    if destination.exists():
        shutil.rmtree(destination, ignore_errors=True)

    try:
        Repo.clone_from(
            normalized_url,
            destination,
            depth=1,
        )
    except GitCommandError as exc:
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise RepoCloneError(f"Git clone failed: {exc}") from exc
    except OSError as exc:
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise RepoCloneError(f"Filesystem error during clone: {exc}") from exc

    return destination
