"""Build the cohesity.dataprotect docsite locally with antsibull-docs and Sphinx.

Usage (from anywhere, with the packages from dev-requirements.txt installed)::

    python docs/build_docs.py            # build into ./built-docs/html
    python docs/build_docs.py --strict   # treat Sphinx warnings as errors
    python docs/build_docs.py --serve    # build, then serve locally
    python docs/build_docs.py --serve --bind 0.0.0.0 --port 8767  # reachable on the VM IP

The generated ``index.rst`` is post-processed so that the sidebar shows captioned
guide sections and a single Modules group instead of one undifferentiated flat list.
"""
from __future__ import annotations

import argparse
import errno
import functools
import http.server
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

COLLECTION_ROOT = Path(__file__).resolve().parent.parent
NAMESPACE, NAME = "cohesity", "dataprotect"
FQCN = f"{NAMESPACE}.{NAME}"

# (caption, [(sidebar title, document)]). Documents are relative to the rst root.
GUIDES = [
    (
        "User Guide",
        [
            ("Overview", "docsite/guide_overview"),
            ("Prerequisites", "docsite/guide_prerequisites"),
            ("Setup", "docsite/guide_setup"),
            ("Configure your Ansible inventory", "docsite/guide_inventory"),
            ("Frequently Asked Questions", "docsite/guide_faq"),
            ("Feedback", "docsite/guide_feedback"),
        ],
    ),
    (
        "Scenario Guides",
        [
            ("Migrate VMware virtual machines", "docsite/guide_vmware_migration"),
        ],
    ),
]

# Sidebar order for module pages (must match every module in the collection).
MODULES = [
    "cohesity_agent",
    "cohesity_cancel_migration",
    "cohesity_clone_vm",
    "cohesity_facts",
    "cohesity_finalize_migration",
    "cohesity_job",
    "cohesity_migrate_vm",
    "cohesity_migration_status",
    "cohesity_oracle_job",
    "cohesity_oracle_restore",
    "cohesity_oracle_source",
    "cohesity_plugin",
    "cohesity_policy",
    "cohesity_restore_file",
    "cohesity_restore_vm",
    "cohesity_restore_vmware_file",
    "cohesity_source",
    "cohesity_storage_domain",
    "cohesity_sync_objects",
    "cohesity_uda_protection_group",
    "cohesity_uda_source",
    "cohesity_view",
    "cohesity_win_agent",
]

THEME_OPTIONS = "html_theme_options = {'collapse_navigation': True, 'navigation_depth': 2}\n"

# Collection guides/modules do not cross-ref Jinja2; skip remote objects.inv fetch.
CONF_PY_APPEND = (
    THEME_OPTIONS
    + "\n# Drop unused Jinja2 intersphinx (avoids fetch warnings).\n"
    + "intersphinx_mapping.pop('jinja2', None)\n"
)


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def antsibull_secure_dir(path: Path) -> None:
    """antsibull-docs requires dest dirs to exist, be owned by the user, and mode 0700."""
    if not path.exists():
        path.mkdir(mode=0o700)
    else:
        path.chmod(0o700)


def toctree(caption: str, entries: list[tuple[str, str]]) -> str:
    lines = [".. toctree::", "    :caption: " + caption, "    :hidden:", "    :maxdepth: 1", ""]
    lines += [f"    {title} <{doc}>" for title, doc in entries]
    return "\n".join(lines) + "\n"


def doc_links(entries: list[tuple[str, str]]) -> str:
    return "\n".join(f"* :doc:`{title} <{doc}>`" for title, doc in entries) + "\n"


def rewrite_index(index: Path) -> None:
    text = index.read_text(encoding="utf-8")

    start = text.index(".. _changelog_section_for_")
    head = text[:start]
    # The first, empty toctree is emitted by antsibull-docs when there are no plugin docs
    # of other kinds; drop it so it does not create an empty sidebar entry.
    head = re.sub(r"\.\. toctree::\n    :maxdepth: 1\n\s*$", "", head).rstrip() + "\n\n"

    plugin_list = re.search(r"(\.\. _module_plugins_in_.*?)\n\.\. toctree::", text, re.S)
    if not plugin_list:
        raise SystemExit("Could not find the module list in the generated index.rst")

    modules = list(MODULES)
    listed = re.findall(r"cohesity\.dataprotect\.(\w+)#module", plugin_list.group(1))
    if sorted(modules) != sorted(listed):
        missing = sorted(set(listed) - set(modules))
        extra = sorted(set(modules) - set(listed))
        raise SystemExit(f"MODULES out of sync with collection. Missing: {missing}; unknown: {extra}")

    out = [head]
    for caption, entries in GUIDES:
        out.append(f"{caption}\n{'-' * len(caption)}\n\n{doc_links(entries)}\n{toctree(caption, entries)}\n")

    out.append(
        ".. _plugin_index_for_cohesity.dataprotect:\n\nPlugin Index\n------------\n\n"
        "These are the plugins in the cohesity.dataprotect collection:\n\n"
    )
    out.append(plugin_list.group(1).rstrip() + "\n\n")
    out.append(toctree("Modules", [(m, f"{m}_module") for m in MODULES]) + "\n")

    out.append(
        ".. _changelog_section_for_cohesity.dataprotect:\n\nChangelog\n---------\n\n"
        "* :doc:`Release notes <changelog>`\n\n"
        + toctree("Changelog", [("Release notes", "changelog")])
    )
    index.write_text("".join(out), encoding="utf-8")


def _local_ipv4_addresses() -> list[str]:
    """Best-effort list of non-loopback IPv4 addresses for preview URLs."""
    addrs: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                addrs.add(ip)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            addrs.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(addrs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=COLLECTION_ROOT / "built-docs", help="output directory")
    parser.add_argument("--strict", action="store_true", help="treat Sphinx warnings as errors")
    parser.add_argument("--serve", action="store_true", help="serve the built site on --port")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        metavar="ADDRESS",
        help="address to listen on (use 0.0.0.0 to open the preview to other machines on the network)",
    )
    args = parser.parse_args()

    for tool in ("antsibull-docs", "sphinx-build"):
        if not shutil.which(tool):
            print(f"{tool} not found; run: pip install -r dev-requirements.txt", file=sys.stderr)
            return 1

    work = Path(tempfile.mkdtemp(prefix="cohesity-docs-"))  # mode 0700, required by antsibull-docs
    try:
        collections = work / "collections"
        link = collections / "ansible_collections" / NAMESPACE / NAME
        link.parent.mkdir(parents=True)
        link.symlink_to(COLLECTION_ROOT, target_is_directory=True)

        env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(collections))
        site = work / "site"
        site.mkdir(mode=0o700)

        run(
            ["antsibull-docs", "sphinx-init", "--use-current", "--squash-hierarchy", "--dest-dir", str(site), FQCN],
            link,
            env,
        )
        antsibull_secure_dir(site / "rst")
        run(
            [
                "antsibull-docs",
                "--config-file",
                str(site / "antsibull-docs.cfg"),
                "collection",
                "--use-current",
                "--squash-hierarchy",
                "--cleanup",
                "everything",
                "--dest-dir",
                str(site / "rst"),
                FQCN,
            ],
            link,
            env,
        )
        rewrite_index(site / "rst" / "index.rst")
        with (site / "conf.py").open("a", encoding="utf-8") as conf:
            conf.write("\n" + CONF_PY_APPEND)

        sphinx = ["sphinx-build", "-M", "html", "rst", "build", "-c", ".", "--keep-going"]
        if args.strict:
            sphinx.append("-W")
        run(sphinx, site, env)

        html = args.output / "html"
        if html.exists():
            shutil.rmtree(html)
        args.output.mkdir(parents=True, exist_ok=True)
        shutil.copytree(site / "build" / "html", html)
        print(f"\nDocs built in {html}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if args.serve:
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(html))

        class _HTTPServer(http.server.ThreadingHTTPServer):
            allow_reuse_address = True

        bind = args.bind
        try:
            httpd = _HTTPServer((bind, args.port), handler)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            print(
                f"Port {args.port} is already in use. Either stop the other process or pick another port, e.g.:\n"
                f"  python docs/build_docs.py --serve --bind {bind} --port {args.port + 1}\n"
                f"  ss -tlnp | grep ':{args.port}'",
                file=sys.stderr,
            )
            return 1
        print(f"Serving {html} at http://127.0.0.1:{args.port}/ (Ctrl-C to stop)")
        if bind not in ("127.0.0.1", "localhost", "::1"):
            for ip in _local_ipv4_addresses():
                print(f"  Also reachable at http://{ip}:{args.port}/")
            print("  Ensure your laptop can reach this VM (VPN / same network) and that the port is not blocked.")
        with httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
