"""
Convert Markdown documentation to clean, publication-grade executive PDFs
using Python's markdown parser and headless Microsoft Edge.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
import markdown

ROOT = Path(__file__).resolve().parent.parent

CSS = """
@page {
    size: A4;
    margin: 18mm 15mm 18mm 15mm;
    @bottom-center {
        content: "Page " counter(page);
        font-size: 9pt;
        color: #64748b;
    }
}

* {
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #1e293b;
    background: #ffffff;
    line-height: 1.6;
    font-size: 10pt;
    margin: 0;
    padding: 0;
}

h1, h2, h3, h4, h5, h6 {
    color: #0f172a;
    font-weight: 700;
    margin-top: 1.5em;
    margin-bottom: 0.5em;
    line-height: 1.25;
    page-break-after: avoid;
}

h1 {
    font-size: 22pt;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 6px;
    margin-top: 0;
    color: #0369a1;
}

h2 {
    font-size: 15pt;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 4px;
    color: #0f172a;
}

h3 {
    font-size: 12pt;
    color: #1e293b;
}

h4 {
    font-size: 11pt;
    color: #334155;
}

p {
    margin: 0 0 0.8em 0;
}

a {
    color: #0284c7;
    text-decoration: none;
}

strong {
    font-weight: 600;
    color: #0f172a;
}

code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 8.5pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 2px 5px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
}

pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 12px 14px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 8.5pt;
    line-height: 1.45;
    margin: 0.8em 0 1.2em 0;
    page-break-inside: avoid;
}

pre code {
    background: transparent;
    color: inherit;
    padding: 0;
    border: none;
    font-size: 8.5pt;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 9pt;
    page-break-inside: avoid;
}

th, td {
    padding: 7px 10px;
    border: 1px solid #cbd5e1;
    text-align: left;
    vertical-align: top;
}

th {
    background-color: #f1f5f9;
    font-weight: 600;
    color: #0f172a;
}

tr:nth-child(even) td {
    background-color: #f8fafc;
}

ul, ol {
    margin: 0 0 1em 0;
    padding-left: 24px;
}

li {
    margin-bottom: 0.35em;
}

blockquote {
    margin: 1em 0;
    padding: 8px 14px;
    border-left: 4px solid #0284c7;
    background: #f0f9ff;
    color: #0369a1;
    border-radius: 0 4px 4px 0;
    page-break-inside: avoid;
}

blockquote p {
    margin: 0;
}

hr {
    border: 0;
    height: 1px;
    background: #e2e8f0;
    margin: 1.8em 0;
}

img {
    max-width: 100%;
    height: auto;
}

.center-header {
    text-align: center;
    margin-bottom: 1.5em;
}

.center-header h1 {
    border-bottom: none;
    margin-bottom: 0.2em;
}

.badge {
    display: inline-block;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 600;
    border-radius: 9999px;
    background: #e0f2fe;
    color: #0369a1;
    border: 1px solid #bae6fd;
    margin-right: 4px;
}
"""


def convert_md_to_pdf(md_path: Path, pdf_path: Path, title: str = "Chronos Documentation") -> Path:
    print(f"Reading {md_path.name}...")
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # Convert markdown to html with tables and fenced code
    html_body = markdown.markdown(
        md_text,
        extensions=[
            "extra",
            "tables",
            "fenced_code",
            "nl2br",
            "sane_lists",
        ],
    )

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
{CSS}
    </style>
</head>
<body>
{html_body}
</body>
</html>
"""

    temp_html_path = md_path.parent / f"{md_path.stem}_temp.html"
    with open(temp_html_path, "w", encoding="utf-8") as f:
        f.write(full_html)

    edge_paths = [
        Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
        Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
    ]

    edge_exe = None
    for ep in edge_paths:
        if ep.exists():
            edge_exe = ep
            break

    if not edge_exe:
        raise RuntimeError("Microsoft Edge executable not found for PDF rendering")

    print(f"Rendering PDF to {pdf_path.name} via headless Edge...")
    cmd = [
        str(edge_exe),
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}",
        str(temp_html_path.resolve()),
    ]

    subprocess.run(cmd, check=True, capture_output=True)

    if temp_html_path.exists():
        temp_html_path.unlink()

    print(f"Created: {pdf_path} ({os.path.getsize(pdf_path):,} bytes)")
    return pdf_path


def main():
    print("=" * 60)
    print("  CHRONOS: Markdown to PDF Generator")
    print("=" * 60)

    # 1. Generate PDF of README.md
    readme_md = ROOT / "README.md"
    readme_pdf = ROOT / "CHRONOS_PROJECT_OVERVIEW.pdf"
    if readme_md.exists():
        convert_md_to_pdf(readme_md, readme_pdf, title="CHRONOS: Project Documentation")

    # 2. Generate PDF of HACKATHON_DEMO_AND_DEFENSE_GUIDE.md
    guide_md = ROOT / "HACKATHON_DEMO_AND_DEFENSE_GUIDE.md"
    guide_pdf = ROOT / "CHRONOS_HACKATHON_DEFENSE_GUIDE.pdf"
    if guide_md.exists():
        convert_md_to_pdf(guide_md, guide_pdf, title="CHRONOS: Hackathon Defense Guide")

    print("\nPDF Generation Complete!")


if __name__ == "__main__":
    main()
