from django.db import models
import uuid

class EmailScan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to='emails/')
    classification = models.CharField(max_length=20)
    score = models.IntegerField()
    issues = models.TextField()
    raw_email = models.TextField(blank=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.classification} - {self.uploaded_at.strftime('%Y-%m-%d %H:%M')}"