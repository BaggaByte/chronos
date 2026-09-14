#!/usr/bin/env python3
"""
generate_presentation_deck.py - Generates the official Chronos Hackathon Presentation Deck (.pptx).
"""

from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# Dark Theme Palette
DARK_BG = RGBColor(15, 23, 42)        # Slate 900
SURFACE_BG = RGBColor(30, 41, 59)     # Slate 800
CARD_BG = RGBColor(51, 65, 85)        # Slate 700
ACCENT_CYAN = RGBColor(56, 189, 248)  # Cyan 400
ACCENT_GREEN = RGBColor(74, 222, 128) # Green 400
ACCENT_RED = RGBColor(248, 113, 113)  # Red 400
ACCENT_GOLD = RGBColor(251, 191, 36)  # Amber 400
TEXT_MAIN = RGBColor(241, 245, 249)   # Slate 100
TEXT_MUTED = RGBColor(148, 163, 184)  # Slate 400


def set_slide_background(slide, color=DARK_BG):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_header(slide, title_text: str, subtitle_text: str = ""):
    # Header container
    tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.7), Inches(1.1))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p1 = tf.paragraphs[0]
    p1.text = title_text
    p1.font.size = Pt(24)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_MAIN

    if subtitle_text:
        p2 = tf.add_paragraph()
        p2.text = subtitle_text
        p2.font.size = Pt(13)
        p2.font.color.rgb = ACCENT_CYAN
        p2.space_before = Pt(4)


def add_card(slide, left: float, top: float, width: float, height: float, title: str, body_bullets: list, accent_color=ACCENT_CYAN):
    # Card background box
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    shape.fill.solid()
    shape.fill.fore_color.rgb = SURFACE_BG
    shape.line.color.rgb = accent_color
    shape.line.width = Pt(1.5)

    # Content
    tb = slide.shapes.add_textbox(Inches(left + 0.25), Inches(top + 0.2), Inches(width - 0.5), Inches(height - 0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p_title = tf.paragraphs[0]
    p_title.text = title
    p_title.font.size = Pt(15)
    p_title.font.bold = True
    p_title.font.color.rgb = accent_color

    for b in body_bullets:
        p = tf.add_paragraph()
        p.text = f"•  {b}"
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_MAIN
        p.space_before = Pt(6)


def create_deck(output_path: Path):
    prs = Presentation()
    # 16:9 Widescreen dimensions
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: Title Slide
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1, DARK_BG)

    tb1 = s1.shapes.add_textbox(Inches(1.2), Inches(2.0), Inches(11.0), Inches(3.5))
    tf1 = tb1.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "⏱️ CHRONOS"
    p.font.size = Pt(44)
    p.font.bold = True
    p.font.color.rgb = ACCENT_CYAN

    p = tf1.add_paragraph()
    p.text = "Automated Multi-Source Incident Timeline Reconstruction & Live Attack Monitoring Engine"
    p.font.size = Pt(22)
    p.font.bold = True
    p.font.color.rgb = TEXT_MAIN
    p.space_before = Pt(12)

    p = tf1.add_paragraph()
    p.text = "Real-World Cyber Forensics (DFIR) · Mathematical Clock Drift Detection · Real-Time ATT&CK Correlation"
    p.font.size = Pt(13)
    p.font.color.rgb = ACCENT_GREEN
    p.space_before = Pt(16)

    # =========================================================================
    # SLIDE 2: Problem Overview & Storyline Context
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2, DARK_BG)
    add_header(s2, "1. Incident Storyline & The Multi-Source Log Crisis", "Aerospace Design Bureau Data Exfiltration Case Study")

    add_card(s2, 0.8, 1.8, 5.6, 5.0, "🏢 The Aerospace Breach Storyline", [
        "Unauthorized exfiltration of sensitive aircraft blueprints discovered.",
        "Forensics team collected 100+ GB of heterogeneous log telemetry.",
        "Sources spanned: Linux auth.log, Windows EVTX, Apache web access logs, Cisco ASA firewall syslogs, and AWS CloudTrail.",
        "Crucial Mission: Reconstruct the exact causal attack progression from initial phishing to S3 cloud exfiltration.",
    ], ACCENT_CYAN)

    add_card(s2, 6.8, 1.8, 5.6, 5.0, "⚠️ The Problem with Current Solutions", [
        "Disparate Formats: Logs formatted in Epoch, Syslog, ISO8601, and Apache strings.",
        "Naive Timezones: Windows & Linux logs omitted timezone headers entirely.",
        "Physical Clock Drift: A compromised workstation had a 47-second clock lag.",
        "High Noise Ratio: Over 85% of logs were routine benign background noise.",
        "Manual spreadsheets & grep take days and misinterpret causal event sequences.",
    ], ACCENT_RED)

    # =========================================================================
    # SLIDE 3: Key Objectives & Deliverables
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3, DARK_BG)
    add_header(s3, "2. Key Objectives & Functional Capabilities", "Engineered to satisfy 100% of the Hackathon Core Requirements")

    add_card(s3, 0.8, 1.8, 3.6, 5.0, "📥 Multi-Format Ingestion", [
        "Modular parsers for Windows EVTX, Linux auth.log, Apache, Cisco ASA, and AWS CloudTrail.",
        "Suricata EVE JSON parser for network NIDS alerts.",
        "SHA-256 pre-ingest hashing creating a court-admissible chain of custody.",
    ], ACCENT_CYAN)

    add_card(s3, 4.8, 1.8, 3.6, 5.0, "⏱️ Universal UTC Engine", [
        "2-Phase blind timezone inference engine.",
        "Mathematically deduces unknown offsets via cross-host flow correlation.",
        "Detects sub-minute physical clock drift (47s) and aligns events to true UTC.",
    ], ACCENT_GREEN)

    add_card(s3, 8.8, 1.8, 3.6, 5.0, "🎯 ATT&CK & Visualization", [
        "Automated mapping to MITRE ATT&CK (T1566, T1003, T1021, T1041, T1110).",
        "Z-score volume spike and dwell gap detection.",
        "Interactive React/Tailwind visual dashboard and executive PDF exports.",
    ], ACCENT_GOLD)

    # =========================================================================
    # SLIDE 4: Architecture Diagram
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4, DARK_BG)
    add_header(s4, "3. Chronos High-Level System Architecture", "Hybrid Dual-Engine: Post-Mortem Forensic Reconstruction + Live Ingestion Hub")

    add_card(s4, 0.8, 1.8, 3.6, 5.0, "Layer 1: Ingestion & Integrity", [
        "SHA-256 Evidence Manifest.",
        "Extensible BaseParser interfaces.",
        "Supports Windows EVTX, Linux Auth, Apache, Cisco Syslog, CloudTrail, Suricata.",
        "Guarantees data authenticity.",
    ], ACCENT_CYAN)

    add_card(s4, 4.8, 1.8, 3.6, 5.0, "Layer 2: Inference & Correlation", [
        "Phase A: Explicit UTC extraction.",
        "Phase B: Blind network flow correlation.",
        "Clock skew residual estimation.",
        "Graph clustering by Actor IP, User account, and Session IDs.",
    ], ACCENT_GREEN)

    add_card(s4, 8.8, 1.8, 3.6, 5.0, "Layer 3: Delivery & Live Sensor", [
        "Interactive React / TanStack Web UI.",
        "Server-Sent Events (SSE) live feed.",
        "Windows OpenSSH & Linux log collectors.",
        "Single-click Executive PDF / CSV export.",
    ], ACCENT_GOLD)

    # =========================================================================
    # SLIDE 5: The Mathematical Breakthrough
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5, DARK_BG)
    add_header(s5, "4. Technical Breakthrough: Blind Timezone & Skew Inference", "How Chronos solves the unsolvable without cheating or analyst priors")

    add_card(s5, 0.8, 1.8, 5.6, 5.0, "🔬 The Challenge of Naive Logs", [
        "Traditional SIEMs plot naive logs (e.g. Syslog 'Sep 12 01:17:34') in local host time.",
        "Result: Cisco firewall log at 01:17 appears 8 hours before Apache login at 09:14.",
        "Windows machine had 47-second clock drift causing credential dump to appear after lateral movement.",
    ], ACCENT_RED)

    add_card(s5, 6.8, 1.8, 5.6, 5.0, "✨ The Chronos Mathematical Solution", [
        "Identifies shared causal IP connections across hosts.",
        "Calculates the delta between explicit timestamps and naive timestamps.",
        "Solves for the integer offset: WIN-ENG-07 = -240 min (EDT), fw-edge-01 = -420 min (PDT).",
        "Calculates residual sub-minute drift: 47s detected and corrected.",
        "Achieved 100% precision validated against ground-truth.",
    ], ACCENT_GREEN)

    # =========================================================================
    # SLIDE 6: Reconstructed Attack Narrative
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6, DARK_BG)
    add_header(s6, "5. Reconstructed Aerospace Breach Killchain", "12 Correlated Malicious Events Isolated from 80+ Benign Background Noise Logs")

    add_card(s6, 0.8, 1.8, 11.6, 5.0, "⚔️ The 5-Stage Reconstructed Attacker Thread", [
        "Stage 1: Initial Access (13:16 UTC) — Spear-phishing login on London web portal (web-portal-01, T1566/T1190) from 203.0.113.77.",
        "Stage 2: Perimeter Breach (13:19 UTC) — Cisco edge firewall (fw-edge-01) allows inbound TCP session.",
        "Stage 3: Credential Dumping (14:40 UTC) — Windows workstation (WIN-ENG-07) compromise & Mimikatz execution (T1003).",
        "Stage 4: Lateral Movement & Staging (15:21 - 16:56 UTC) — SSH hop to Linux database (lin-db-03, T1021/T1078) and tar archive creation (T1560).",
        "Stage 5: Exfiltration (17:14 UTC) — AWS STS identity discovery and archive exfiltration via S3 PutObject (T1041).",
    ], ACCENT_CYAN)

    # =========================================================================
    # SLIDE 7: Live Ingestion (Part 2)
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7, DARK_BG)
    add_header(s7, "6. Real-Time Live Attack Ingestion (Part 2)", "Extending Post-Mortem Forensics into an Active Security Command Center")

    add_card(s7, 0.8, 1.8, 5.6, 5.0, "⚡ Live Sensor Architecture", [
        "Chronos Ingestion Hub running HTTP REST + Server-Sent Events (SSE) on port 8000.",
        "Windows OpenSSH Live Collector tails Windows Event Log (OpenSSH/Operational).",
        "Linux Shipper tails /var/log/auth.log and Suricata /var/log/suricata/eve.json.",
        "Instant sub-second normalization, ATT&CK mapping, and event broadcast.",
    ], ACCENT_CYAN)

    add_card(s7, 6.8, 1.8, 5.6, 5.0, "🎯 Live Attack Detection (Kali Linux)", [
        "Attacker on Kali WSL targets Windows OpenSSH with Hydra password spray.",
        "Windows Collector forwards authentication failures to Chronos.",
        "Chronos immediately tags events with MITRE ATT&CK T1110 (Brute Force).",
        "Live stats API (/api/live/stats) and SSE stream (/api/live/stream) update dashboard in real time.",
    ], ACCENT_GOLD)

    # =========================================================================
    # SLIDE 8: Summary & Business Impact
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8, DARK_BG)
    add_header(s8, "7. Summary & Real-World Impact", "Why Chronos is a Game-Changer for Incident Response Teams")

    add_card(s8, 0.8, 1.8, 5.6, 5.0, "🏆 Key Differentiators", [
        "Fixes physical clock skew (47s) and timezones before correlating.",
        "Reduces investigation time from 3-5 days to under 5 seconds.",
        "Eliminates analyst fatigue by isolating the exact 12-event attacker thread.",
        "Cryptographic chain-of-custody ensures court evidence admissibility.",
    ], ACCENT_GREEN)

    add_card(s8, 6.8, 1.8, 5.6, 5.0, "📊 Hackathon Deliverables Delivered", [
        "✓ Multi-Format Log Parsers (EVTX, Linux, Apache, Cisco, CloudTrail, Suricata).",
        "✓ Universal UTC & Blind Skew Inference Engine (28/28 Unit Tests Passing).",
        "✓ Interactive Visual Dashboard with Zoomable Timeline and Graph.",
        "✓ Single-Click Executive PDF & CSV Forensic Reports.",
        "✓ Real-Time Live Ingestion Hub & Windows OpenSSH Collector.",
    ], ACCENT_CYAN)

    prs.save(str(output_path))
    print(f"[+] Presentation saved: {output_path}")


if __name__ == "__main__":
    out_file = Path(__file__).resolve().parent.parent / "CHRONOS_INCIDENT_TIMELINE_RECONSTRUCTION.pptx"
    create_deck(out_file)
