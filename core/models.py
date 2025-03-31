from django.db import models
from django.utils import timezone

class UsedPassword(models.Model):
    hashed_password = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.hashed_password[:10]}... at {self.created_at}"
