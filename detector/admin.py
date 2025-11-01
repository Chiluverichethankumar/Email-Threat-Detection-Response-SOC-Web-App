from django.contrib import admin
from .models import EmailScan

@admin.register(EmailScan)
class EmailScanAdmin(admin.ModelAdmin):
    list_display = ('uploaded_at', 'classification', 'score')
    readonly_fields = ('uploaded_at', 'file', 'classification', 'score', 'issues')