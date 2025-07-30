"""
pdf_generator.py
Module to generate branded, watermarked PDF reports using fpdf.
"""

from fpdf import FPDF
from typing import Dict

def generate_pdf_report(scan_data: Dict, user_email: str, output_path: str) -> str:
    """
    Generate a PDF report from scan data, branded and watermarked with user email.
    Returns the path to the generated PDF.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="SCANNO Vulnerability Report", ln=True, align="C")
    pdf.cell(200, 10, txt=f"User: {user_email}", ln=True, align="C")
    pdf.cell(200, 10, txt=f"URL: {scan_data.get('url', '')}", ln=True, align="C")
    pdf.cell(200, 10, txt=f"Scan Type: {scan_data.get('scan_type', '')}", ln=True, align="C")
    pdf.cell(200, 10, txt="---", ln=True, align="C")
    pdf.cell(200, 10, txt="[Scan results go here]", ln=True, align="C")
    # Watermark
    pdf.set_text_color(200, 200, 200)
    pdf.set_xy(10, 250)
    pdf.cell(0, 10, f"Report generated for {user_email}")
    pdf.output(output_path)
    return output_path