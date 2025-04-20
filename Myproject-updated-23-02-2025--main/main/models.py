from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator
from cryptography.fernet import Fernet
from django.conf import settings
import base64
from django.utils import timezone
import pyotp

# Create your models here.

class Article(models.Model):
    tile = models.CharField(max_length=100)
    description = models.CharField(max_length=255)
    def __str__(self):
        return self.title
    class Meta:
        db_table =''
        managed = True
        verbose_name ='Article'
        verbose_name_plural ='Articles'

class Password(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='stored_passwords')
    website = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    encrypted_password = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.website} - {self.username}"

    def set_password(self, raw_password):
        key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
        f = Fernet(key)
        self.encrypted_password = f.encrypt(raw_password.encode())

    def get_password(self):
        key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
        f = Fernet(key)
        return f.decrypt(self.encrypted_password).decode()

    class Meta:
        ordering = ['-created_at']

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    master_password = models.BinaryField()
    theme = models.CharField(max_length=10, default='light', choices=[('light', 'Light'), ('dark', 'Dark')])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, null=True, blank=True)
    last_password_change = models.DateTimeField(null=True, blank=True)
    recovery_phone = models.CharField(max_length=15, null=True, blank=True)

    def set_master_password(self, raw_password):
        key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
        f = Fernet(key)
        self.master_password = f.encrypt(raw_password.encode())
        self.last_password_change = timezone.now()

    def verify_master_password(self, raw_password):
        key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
        f = Fernet(key)
        try:
            stored_password = f.decrypt(self.master_password).decode()
            return stored_password == raw_password
        except:
            return False

    def generate_2fa_secret(self):
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
            self.save()
        return self.two_factor_secret

    def verify_2fa_code(self, code):
        if not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(code)

    def enable_2fa(self):
        self.two_factor_enabled = True
        self.save()

    def disable_2fa(self):
        self.two_factor_enabled = False
        self.two_factor_secret = None
        self.save()

    def update_recovery_options(self, email=None, phone=None):
        if email:
            self.user.email = email
            self.user.save()
        if phone:
            self.recovery_phone = phone
        self.save()