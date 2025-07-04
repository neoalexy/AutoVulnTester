from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf(report_data, filename="report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Naslov
    title = Paragraph("AutoVulnTester Security Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))

    # Metadata: Target i vreme
    metadata = f"""
    <b>Target:</b> {report_data.get('target', 'N/A')}<br/>
    <b>Scan time:</b> {report_data.get('scan_time', 'N/A')}<br/><br/>
    """
    story.append(Paragraph(metadata, styles['Normal']))
    story.append(Spacer(1, 12))

    total_tests = 3  # ti testiraš 3 vrste ranjivosti
    found_count = len(report_data.get('vulnerabilities', []))

    # Broj pronadjenih ranjivosti
    vuln_summary = f"<b>Vulnerabilities found:</b> {found_count} / {total_tests}<br/><br/>"
    story.append(Paragraph(vuln_summary, styles['Heading2']))
    story.append(Spacer(1, 12))

    if found_count == 0:
        story.append(Paragraph("No vulnerabilities found.", styles['Normal']))
    else:
        red_style = ParagraphStyle(
            'RedStyle',
            parent=styles['Normal'],
            textColor=colors.red,
            fontSize=12,
            leading=14
        )

        for vuln in report_data['vulnerabilities']:
            vuln_text = f"""
            <b>Type:</b> {vuln['type']}<br/>
            <b>Confidence:</b> {vuln['confidence']}<br/>
            <b>Description:</b><br/>{vuln.get('ai_description', 'No description available')}<br/>
            <b>Payload:</b> {vuln['payload']}<br/>
            <b>URL:</b> {vuln['url']}<br/><br/>
            """
            story.append(Paragraph(vuln_text, red_style))
            story.append(Spacer(1, 12))

    doc.build(story)
