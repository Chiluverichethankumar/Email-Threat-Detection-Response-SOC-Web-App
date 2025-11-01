# detector/views.py
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, Http404
from django.conf import settings
from .models import EmailScan
from .utils import analyze_email_file
from weasyprint import HTML
import os
import uuid
import email
from email import policy


def upload_email(request):
    if request.method == 'POST' and request.FILES.get('eml_file'):
        uploaded_file = request.FILES['eml_file']
        temp_path = os.path.join('emails', f"{uuid.uuid4()}.eml")
        os.makedirs('emails', exist_ok=True)
        with open(temp_path, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        result = analyze_email_file(temp_path)

        scan = EmailScan.objects.create(
            file=f"emails/{os.path.basename(temp_path)}",
            classification=result['classification'],
            score=result['score'],
            issues=result['issues'],
            raw_email=result['raw_email']
        )
        return render(request, 'detector/result.html', {
            'scan': scan,
            'subject': result['subject'],
            'from_addr': result['from_addr']
        })
    return render(request, 'detector/upload.html')

def history(request):
    scans = EmailScan.objects.all()
    return render(request, 'detector/history.html', {'scans': scans})

def report_pdf(request, pk):
    scan = get_object_or_404(EmailScan, pk=pk)
    
    # FIXED: Use scan.file.name (stored relative path)
    file_path = os.path.join(settings.BASE_DIR, scan.file.name)
    
    if not os.path.exists(file_path):
        # If file is in quarantine, it was moved!
        raise Http404("Email file not found. It may have been quarantined or deleted.")

    with open(file_path, 'rb') as f:
        raw_email = f.read()
        msg = email.message_from_bytes(raw_email, policy=email.policy.default)

    from_addr = msg['From'] or "Unknown"
    subject = msg['Subject'] or "No Subject"

    html_string = render(request, 'detector/report_pdf.html', {
        'scan': scan,
        'from_addr': from_addr,
        'subject': subject
    }).content.decode()
    
    pdf = HTML(string=html_string, base_url=request.build_absolute_uri('/')).write_pdf()
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="scan_{pk}.pdf"'
    return response