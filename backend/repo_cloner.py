import re
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

from git import GitCommandError, Repo

from exceptions import InvalidRepoUrlError, RepoCloneError, RepoTooLargeError

# Plan-mandated allowlist of supported git hosts.
ALLOWED_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")

GIT_HTTPS_PATTERN = re.compile(
    r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[\w.\-]+/[\w.\-]+(?:\.git)?/?$",
    re.IGNORECASE,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPOSITORIES_DIR = PROJECT_ROOT / "temp" / "repositories"

# Plan: reject repos > 100 MB to prevent disk-fill / DoS via giant repos.
MAX_REPO_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


def validate_git_url(repo_url: str) -> str:
    """Normalize and validate a public HTTPS URL on an allowlisted git host."""
    parsed = urlparse(repo_url.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() not in ALLOWED_HOSTS:
        raise InvalidRepoUrlError(
            f"Only HTTPS URLs on {', '.join(ALLOWED_HOSTS)} are supported."
        )

    segments = [part for part in parsed.path.split("/") if part]
    if len(segments) != 2:
        raise InvalidRepoUrlError(
            "URL must point to a repository (https://<host>/owner/repo)."
        )

    host = parsed.netloc.lower()
    owner, repo = segments
    repo = repo.removesuffix(".git")
    normalized = f"https://{host}/{owner}/{repo}"
    if not GIT_HTTPS_PATTERN.match(normalized):
        raise InvalidRepoUrlError("Repository URL format is invalid.")

    return normalized


# Backwards-compatible alias — older callers may still import this name.
validate_github_url = validate_git_url


def _measure_repo_size(repo_dir: Path) -> int:
    """Return total size in bytes of all files inside repo_dir."""
    total = 0
    for path in repo_dir.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except OSError:
            # Ignore unreadable entries — they can't contribute to the count.
            continue
    return total


def _destination_name(repo_url: str) -> str:
    segments = [part for part in urlparse(repo_url).path.split("/") if part]
    owner, repo = segments[0], segments[1].removesuffix(".git")
    suffix = uuid.uuid4().hex[:8]
    return f"{owner}_{repo}_{suffix}"


def clone_repository(repo_url: str) -> Path:
    """
    Clone a public git repository into ./temp/repositories/ and enforce the
    plan-mandated 100 MB size cap.

    Returns the local path to the cloned repository. Raises RepoTooLargeError
    if the clone exceeds MAX_REPO_SIZE_BYTES.
    """
    normalized_url = validate_git_url(repo_url)
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

    # Enforce repo size cap immediately after clone — before any scanner runs.
    size_bytes = _measure_repo_size(destination)
    if size_bytes > MAX_REPO_SIZE_BYTES:
        shutil.rmtree(destination, ignore_errors=True)
        size_mb = round(size_bytes / (1024 * 1024), 1)
        cap_mb = round(MAX_REPO_SIZE_BYTES / (1024 * 1024))
        raise RepoTooLargeError(
            f"Repository is {size_mb} MB, which exceeds the {cap_mb} MB limit."
        )

    return destination
