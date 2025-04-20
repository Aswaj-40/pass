# from django.shortcuts import render

# def login_view(request):
#     return render(request, 'main/login.html')
# #dashbaord redirection from Signin button
# from django.shortcuts import render, redirect

# def login_view(request):
#     if request.method == 'POST':
#         # Authenticate user logic here...
#         return redirect('dashboard')  # Redirect to dashboard after successful login
#     return render(request, 'main/login.html')
# def dashboard_view(request):
#     return render(request, 'main/dashboard.html')

# from django.shortcuts import render

# # Signup view
# from django.shortcuts import render

# def signup_view(request):
#     return render(request, "main/Signup.html")  # ✅ Ensure this is correct
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages  
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from .models import Password, UserProfile
from django.views.decorators.http import require_http_methods, require_POST
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.contrib.auth.forms import PasswordChangeForm
import json
import string
import random
import pyotp
import qrcode
from io import BytesIO
import base64

# ✅ Login View
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not email or not password:
            messages.error(request, "Please provide both email and password.")
            return render(request, 'main/login.html')

        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, "Login successful!")
                # Always redirect to master password verification
                return redirect('verify_master_password')
            else:
                messages.error(request, "Invalid email or password.")
        except User.DoesNotExist:
            messages.error(request, "User with this email does not exist.")

    return render(request, 'main/login.html')

# ✅ Logout View
@require_http_methods(["POST"])
def logout_view(request):
    logout(request)
    messages.success(request, "You have been successfully logged out.")
    return redirect('login')

# ✅ Dashboard View (Ensure User is Logged In)
@login_required
def dashboard_view(request):
    if not request.user.is_authenticated:
        messages.error(request, "You need to log in first.")
        return redirect('login')
    
    try:
        profile = request.user.profile
        # Check if master password is verified in session
        if not request.session.get('master_password_verified', False):
            return redirect('verify_master_password')
    except UserProfile.DoesNotExist:
        return redirect('set_master_password')
    
    passwords = Password.objects.filter(user=request.user)
    return render(request, 'main/dashboard.html', {'passwords': passwords})

# ✅ Signup View (Stores User Properly)
def signup_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # Validate email domain
        if not email.endswith("@gmail.com"):
            messages.error(request, "Only Gmail accounts are allowed.")
            return redirect("signup")

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists. Please log in.")
            return redirect("signup")

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken. Please choose a different username.")
            return redirect("signup")

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("signup")

        try:
            # Create and save the user properly
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
            messages.success(request, "Signup successful! You can now log in.")
            return redirect("login")
        except Exception as e:
            messages.error(request, f"An error occurred during signup: {str(e)}")
            return redirect("signup")

    return render(request, "main/Signup.html")

# ✅ Forgot Password View (Send Reset Link)
def forget_password(request):
    if request.method == "POST":
        email = request.POST.get("email")

        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "No account found with this email.")
            return redirect("forget_password")

        # Generate password reset link
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")

        # Send email
        subject = "Password Reset Request"
        message = render_to_string("main/password_reset_email.html", {
            "reset_link": reset_link,
            "user": user
        })
        plain_message = f"Hello {user.username},\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you didn't request this, please ignore this email.\n\nBest regards,\nPassword Manager Team"
        
        try:
            send_mail(
                subject,
                plain_message,
                settings.EMAIL_HOST_USER,
                [email],
                html_message=message,
                fail_silently=False,
            )
            messages.success(request, "A password reset link has been sent to your email.")
            return redirect("login")
        except Exception as e:
            print(f"Email sending error: {str(e)}")  # Log the error
            messages.error(request, f"Failed to send reset email. Error: {str(e)}")
            return redirect("forget_password")

    return render(request, 'main/Forgetpass.html')

# ✅ Reset Password View (Handles Password Change)
def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError):
        messages.error(request, "Invalid password reset link.")
        return redirect("login")

    if not default_token_generator.check_token(user, token):
        messages.error(request, "This link has expired or is invalid.")
        return redirect("login")

    if request.method == "POST":
        new_password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect(request.path)

        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)

        messages.success(request, "Your password has been reset successfully. You can now log in.")
        return redirect("login")

    return render(request, "main/reset_password.html", {"user": user})

@login_required
def password_manager(request):
    try:
        profile = request.user.profile
        if not request.session.get('master_password_verified', False):
            print(f"Master password not verified for user {request.user.username}, redirecting to verification")
            return redirect('verify_master_password')
        else:
            print(f"Master password verified for user {request.user.username}, showing password manager")
    except UserProfile.DoesNotExist:
        print(f"User profile not found for user {request.user.username}")
        return redirect('set_master_password')

    if request.method == 'POST':
        website = request.POST.get('website')
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if website and username and password:
            password_obj = Password.objects.create(
                user=request.user,
                website=website,
                username=username
            )
            password_obj.set_password(password)
            password_obj.save()
            messages.success(request, 'Password saved successfully!')
            return redirect('password_manager')
    
    passwords = Password.objects.filter(user=request.user)
    return render(request, 'main/password_manager.html', {'passwords': passwords})

@login_required
def edit_password(request, password_id):
    try:
        profile = request.user.profile
        if not request.session.get('master_password_verified', False):
            return redirect('verify_master_password')
    except UserProfile.DoesNotExist:
        return redirect('set_master_password')

    try:
        password = Password.objects.get(id=password_id, user=request.user)
        if request.method == 'POST':
            website = request.POST.get('website')
            username = request.POST.get('username')
            new_password = request.POST.get('password')
            
            if website and username and new_password:
                password.website = website
                password.username = username
                password.set_password(new_password)
                password.save()
                messages.success(request, 'Password updated successfully!')
                return redirect('password_manager')
        
        return render(request, 'main/edit_password.html', {'password': password})
    except Password.DoesNotExist:
        messages.error(request, 'Password not found or you do not have permission to edit it.')
        return redirect('password_manager')

@login_required
def delete_password(request, password_id):
    try:
        profile = request.user.profile
        master_password = request.POST.get('master_password')
        
        if not master_password:
            messages.error(request, 'Master password required')
            return redirect('password_manager')
            
        if not profile.verify_master_password(master_password):
            messages.error(request, 'Invalid master password')
            return redirect('password_manager')

        password = Password.objects.get(id=password_id, user=request.user)
        password.delete()
        messages.success(request, 'Password deleted successfully!')
    except UserProfile.DoesNotExist:
        messages.error(request, 'Master password not set')
        return redirect('set_master_password')
    except Password.DoesNotExist:
        messages.error(request, 'Password not found or you do not have permission to delete it.')
    return redirect('password_manager')

@login_required
def set_master_password(request):
    if request.method == 'POST':
        master_password = request.POST.get('master_password')
        confirm_master_password = request.POST.get('confirm_master_password')
        
        if master_password != confirm_master_password:
            messages.error(request, 'Master passwords do not match.')
            return redirect('set_master_password')
        
        try:
            profile = request.user.profile
        except UserProfile.DoesNotExist:
            profile = UserProfile(user=request.user)
        
        profile.set_master_password(master_password)
        profile.save()
        messages.success(request, 'Master password set successfully!')
        return redirect('dashboard')
    
    return render(request, 'main/set_master_password.html')

@login_required
def verify_master_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            master_password = data.get('master_password')
            
            if not master_password:
                return JsonResponse({'success': False, 'message': 'Master password is required'})
            
            # Get the user's profile
            profile = request.user.profile
            
            # Verify the master password using the model's method
            if profile.verify_master_password(master_password):
                # Set the session flag to indicate master password is verified
                request.session['master_password_verified'] = True
                # Set session expiry to 1 hour
                request.session.set_expiry(3600)
                print(f"Master password verified for user {request.user.username}")
                return JsonResponse({'success': True})
            else:
                print(f"Invalid master password attempt for user {request.user.username}")
                return JsonResponse({'success': False, 'message': 'Incorrect master password'})
                
        except UserProfile.DoesNotExist:
            print(f"User profile not found for user {request.user.username}")
            return JsonResponse({'success': False, 'message': 'Master password not set'})
        except Exception as e:
            print(f"Error verifying master password: {str(e)}")
            return JsonResponse({'success': False, 'message': str(e)})
    
    # Handle GET request - show verification page
    return render(request, 'main/verify_master_password.html')

@login_required
def get_password(request, password_id):
    try:
        profile = request.user.profile
        master_password = request.POST.get('master_password')
        
        if not master_password:
            return JsonResponse({'status': 'error', 'message': 'Master password required'})
            
        if not profile.verify_master_password(master_password):
            return JsonResponse({'status': 'error', 'message': 'Invalid master password'})

        password = Password.objects.get(id=password_id, user=request.user)
        return JsonResponse({
            'status': 'success',
            'password': password.get_password()
        })
    except UserProfile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Master password not set'})
    except Password.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Password not found'})

@login_required
def copy_password(request, password_id):
    try:
        profile = request.user.profile
        master_password = request.POST.get('master_password')
        
        if not master_password:
            return JsonResponse({'status': 'error', 'message': 'Master password required'})
            
        if not profile.verify_master_password(master_password):
            return JsonResponse({'status': 'error', 'message': 'Invalid master password'})

        password = Password.objects.get(id=password_id, user=request.user)
        return JsonResponse({
            'status': 'success',
            'password': password.get_password()
        })
    except UserProfile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Master password not set'})
    except Password.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Password not found'})

@login_required
def settings_view(request):
    if request.method == 'POST':
        if 'change_password' in request.POST:
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if not request.user.check_password(current_password):
                messages.error(request, 'Current password is incorrect')
            elif new_password != confirm_password:
                messages.error(request, 'New passwords do not match')
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request, 'Password changed successfully')
                return redirect('settings')
        
        elif 'change_theme' in request.POST:
            theme = request.POST.get('theme')
            try:
                profile = request.user.profile
            except UserProfile.DoesNotExist:
                profile = UserProfile(user=request.user)
            
            profile.theme = theme
            profile.save()
            messages.success(request, f'Theme changed to {theme} mode')
            return redirect('settings')
    
    try:
        profile = request.user.profile
        current_theme = profile.theme if hasattr(profile, 'theme') else 'light'
    except UserProfile.DoesNotExist:
        current_theme = 'light'
    
    return render(request, 'main/settings.html', {'current_theme': current_theme})

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('settings')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'main/settings.html', {'form': form})

def profile(request):
    if not request.user.is_authenticated:
        return redirect('login')
    
    # Get all passwords for the current user
    passwords = Password.objects.filter(user=request.user)
    total_passwords = passwords.count()
    
    # Calculate average age of passwords
    if total_passwords > 0:
        total_age = sum((timezone.now() - p.created_at).days for p in passwords)
        average_age = round(total_age / total_passwords, 1)
    else:
        average_age = 0
    
    # Calculate password strengths
    def calculate_strength(password):
        strength = 0
        # Length check
        if len(password) >= 12:
            strength += 30
        elif len(password) >= 8:
            strength += 20
        elif len(password) >= 6:
            strength += 10
        
        # Character type checks
        if any(c.isupper() for c in password):
            strength += 20
        if any(c.islower() for c in password):
            strength += 20
        if any(c.isdigit() for c in password):
            strength += 20
        if any(not c.isalnum() for c in password):
            strength += 20
        
        return min(strength, 100) / 100  # Normalize to 0-1 range
    
    # Calculate average strength
    if total_passwords > 0:
        total_strength = sum(calculate_strength(p.get_password()) for p in passwords)
        average_strength = round((total_strength / total_passwords) * 100, 1)
    else:
        average_strength = 0
    
    # Calculate age distribution
    age_distribution = {
        'Less than 30 days': 0,
        '30-90 days': 0,
        '90-180 days': 0,
        'More than 180 days': 0
    }
    
    for password in passwords:
        age = (timezone.now() - password.created_at).days
        if age < 30:
            age_distribution['Less than 30 days'] += 1
        elif age < 90:
            age_distribution['30-90 days'] += 1
        elif age < 180:
            age_distribution['90-180 days'] += 1
        else:
            age_distribution['More than 180 days'] += 1
    
    # Convert counts to percentages
    if total_passwords > 0:
        for key in age_distribution:
            age_distribution[key] = round((age_distribution[key] / total_passwords) * 100, 1)
    
    # Calculate strength distribution
    strength_distribution = {
        'Weak (0-40%)': 0,
        'Medium (40-70%)': 0,
        'Strong (70-90%)': 0,
        'Very Strong (90-100%)': 0
    }
    
    for password in passwords:
        strength = calculate_strength(password.get_password()) * 100
        if strength < 40:
            strength_distribution['Weak (0-40%)'] += 1
        elif strength < 70:
            strength_distribution['Medium (40-70%)'] += 1
        elif strength < 90:
            strength_distribution['Strong (70-90%)'] += 1
        else:
            strength_distribution['Very Strong (90-100%)'] += 1
    
    # Convert counts to percentages
    if total_passwords > 0:
        for key in strength_distribution:
            strength_distribution[key] = round((strength_distribution[key] / total_passwords) * 100, 1)
    
    # Get saved passwords with their strength
    saved_passwords = []
    for password in passwords:
        strength = calculate_strength(password.get_password()) * 100
        saved_passwords.append({
            'id': password.id,
            'website': password.website,
            'username': password.username,
            'created_at': password.created_at,
            'strength': round(strength, 1)
        })
    
    context = {
        'total_passwords': total_passwords,
        'average_age': average_age,
        'average_strength': average_strength,
        'age_distribution': age_distribution,
        'strength_distribution': strength_distribution,
        'saved_passwords': saved_passwords
    }
    
    return render(request, 'main/profile.html', context)

def test_email(request):
    try:
        send_mail(
            'Test Email',
            'This is a test email from your Password Manager application.',
            settings.EMAIL_HOST_USER,
            [settings.EMAIL_HOST_USER],  # Sending to yourself
            fail_silently=False,
        )
        return HttpResponse('Test email sent successfully! Check your inbox.')
    except Exception as e:
        return HttpResponse(f'Error sending email: {str(e)}')

@login_required
def home(request):
    # Get total number of passwords
    total_passwords = Password.objects.filter(user=request.user).count()
    
    # Get last login time
    last_login = request.user.last_login
    
    # Get recent activities
    recent_activities = [
        {
            'icon': 'key',
            'title': 'Password Added',
            'description': 'New password for Google account',
            'time': '2 hours ago'
        },
        {
            'icon': 'shield-alt',
            'title': 'Security Update',
            'description': 'Password strength improved',
            'time': '5 hours ago'
        },
        {
            'icon': 'sync',
            'title': 'Auto-sync',
            'description': 'Passwords synced across devices',
            'time': '1 day ago'
        }
    ]
    
    context = {
        'total_passwords': total_passwords,
        'last_login': last_login,
        'recent_activities': recent_activities
    }
    
    return render(request, 'main/home.html', context)

@login_required
def generate_password(request):
    if request.method == 'POST':
        length = int(request.POST.get('length', 12))
        include_uppercase = request.POST.get('uppercase') == 'on'
        include_numbers = request.POST.get('numbers') == 'on'
        include_special = request.POST.get('special') == 'on'
        
        characters = string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_special:
            characters += string.punctuation
            
        password = ''.join(random.choice(characters) for _ in range(length))
        return JsonResponse({'password': password})
    
    return render(request, 'main/generate_password.html')

@login_required
def security_settings(request):
    try:
        profile = request.user.profile
        if not request.session.get('master_password_verified', False):
            return redirect('verify_master_password')
    except UserProfile.DoesNotExist:
        return redirect('set_master_password')

    if request.method == 'POST':
        # Handle security settings updates
        if 'change_master_password' in request.POST:
            current_password = request.POST.get('current_master_password')
            new_password = request.POST.get('new_master_password')
            confirm_password = request.POST.get('confirm_master_password')
            
            if not profile.verify_master_password(current_password):
                messages.error(request, 'Current master password is incorrect')
            elif new_password != confirm_password:
                messages.error(request, 'New master passwords do not match')
            else:
                profile.set_master_password(new_password)
                profile.save()
                messages.success(request, 'Master password updated successfully')
                return redirect('security_settings')
        
        elif 'verify_2fa' in request.POST:
            verification_code = request.POST.get('verification_code')
            if not verification_code or len(verification_code) != 6:
                messages.error(request, 'Please enter a valid 6-digit code')
            elif profile.verify_2fa_code(verification_code):
                profile.enable_2fa()
                messages.success(request, 'Two-factor authentication enabled successfully')
                return redirect('security_settings')
            else:
                messages.error(request, 'Invalid verification code')
        
        elif 'disable_2fa' in request.POST:
            profile.disable_2fa()
            messages.success(request, 'Two-factor authentication disabled')
            return redirect('security_settings')
        
        elif 'change_email' in request.POST:
            new_email = request.POST.get('new_email')
            if not new_email:
                messages.error(request, 'Please provide a new email address')
            elif User.objects.filter(email=new_email).exclude(id=request.user.id).exists():
                messages.error(request, 'This email is already in use')
            else:
                profile.update_recovery_options(email=new_email)
                messages.success(request, 'Recovery email updated successfully')
                return redirect('security_settings')
        
        elif 'add_phone' in request.POST:
            phone = request.POST.get('phone')
            if not phone:
                messages.error(request, 'Please provide a phone number')
            else:
                profile.update_recovery_options(phone=phone)
                messages.success(request, 'Recovery phone number added successfully')
                return redirect('security_settings')

    # Generate QR code for 2FA setup if not enabled
    qr_code = None
    if not profile.two_factor_enabled:
        secret = profile.generate_2fa_secret()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=request.user.email,
            issuer_name='Password Manager'
        )
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    context = {
        'has_2fa': profile.two_factor_enabled,
        'last_password_change': profile.last_password_change,
        'qr_code': qr_code,
        'recovery_phone': profile.recovery_phone
    }
    
    return render(request, 'main/security_settings.html', context)

@login_required
def update_master_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            current_password = data.get('current_password')
            new_password = data.get('new_password')

            if not current_password or not new_password:
                return JsonResponse({
                    'success': False,
                    'message': 'Current password and new password are required.'
                })

            user_profile = UserProfile.objects.get(user=request.user)
            
            # Verify current password
            if not user_profile.verify_master_password(current_password):
                return JsonResponse({
                    'success': False,
                    'message': 'Current password is incorrect.'
                })

            # Update to new password
            user_profile.set_master_password(new_password)
            user_profile.save()

            # Update session
            request.session['master_password_verified'] = True
            request.session['master_password_verified_at'] = timezone.now().isoformat()

            return JsonResponse({
                'success': True,
                'message': 'Master password updated successfully.'
            })

        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid request data.'
            })
        except UserProfile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'User profile not found.'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            })

    return JsonResponse({
        'success': False,
        'message': 'Invalid request method.'
    })

@login_required
def password_health(request):
    if not request.session.get('master_password_verified', False):
        return redirect('verify_master_password')
    
    return render(request, 'main/health_dashboard.html')

@login_required
def get_password_health(request):
    if not request.session.get('master_password_verified', False):
        return JsonResponse({'error': 'Master password not verified'}, status=403)
    
    try:
        passwords = Password.objects.filter(user=request.user)
        total_passwords = passwords.count()
        
        # Calculate password strengths
        strong_passwords = 0
        medium_passwords = 0
        weak_passwords = 0
        
        # Calculate password ages
        now = timezone.now()
        passwords_less_than_30_days = 0
        passwords_30_to_90_days = 0
        passwords_90_to_180_days = 0
        passwords_more_than_180_days = 0
        
        weak_passwords_list = []
        
        for password in passwords:
            # Check password strength
            strength = calculate_password_strength(password.get_password())
            if strength >= 0.8:
                strong_passwords += 1
            elif strength >= 0.5:
                medium_passwords += 1
            else:
                weak_passwords += 1
                if strength < 0.5:
                    weak_passwords_list.append({
                        'id': password.id,
                        'website': password.website,
                        'username': password.username
                    })
            
            # Check password age
            age = (now - password.created_at).days
            if age < 30:
                passwords_less_than_30_days += 1
            elif age < 90:
                passwords_30_to_90_days += 1
            elif age < 180:
                passwords_90_to_180_days += 1
            else:
                passwords_more_than_180_days += 1
        
        # Calculate security score
        security_score = calculate_security_score(
            total_passwords,
            strong_passwords,
            medium_passwords,
            weak_passwords,
            passwords_more_than_180_days
        )
        
        # Generate recommendations
        recommendations = generate_recommendations(
            weak_passwords,
            passwords_more_than_180_days,
            total_passwords
        )
        
        return JsonResponse({
            'security_score': security_score,
            'weak_passwords_count': weak_passwords,
            'expired_passwords_count': passwords_more_than_180_days,
            'strong_passwords_count': strong_passwords,
            'medium_passwords_count': medium_passwords,
            'weak_passwords_count': weak_passwords,
            'passwords_less_than_30_days': passwords_less_than_30_days,
            'passwords_30_to_90_days': passwords_30_to_90_days,
            'passwords_90_to_180_days': passwords_90_to_180_days,
            'passwords_more_than_180_days': passwords_more_than_180_days,
            'weak_passwords': weak_passwords_list,
            'recommendations': recommendations
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def calculate_password_strength(password):
    strength = 0
    
    # Length check
    if len(password) >= 12:
        strength += 0.3
    elif len(password) >= 8:
        strength += 0.2
    elif len(password) >= 6:
        strength += 0.1
    
    # Character type checks
    if any(c.isupper() for c in password):
        strength += 0.2
    if any(c.islower() for c in password):
        strength += 0.2
    if any(c.isdigit() for c in password):
        strength += 0.2
    if any(not c.isalnum() for c in password):
        strength += 0.2
    
    return min(strength, 1.0)

def calculate_security_score(total_passwords, strong_passwords, medium_passwords, weak_passwords, expired_passwords):
    if total_passwords == 0:
        return 100
    
    # Calculate base score from password strength distribution
    strength_score = (strong_passwords * 1.0 + medium_passwords * 0.7 + weak_passwords * 0.3) / total_passwords
    
    # Penalize for expired passwords
    expired_penalty = expired_passwords / total_passwords
    
    # Calculate final score (0-100)
    final_score = (strength_score * (1 - expired_penalty)) * 100
    
    return round(final_score)

def generate_recommendations(weak_passwords, expired_passwords, total_passwords):
    recommendations = []
    
    if weak_passwords > 0:
        recommendations.append({
            'icon': 'exclamation-triangle',
            'message': f'You have {weak_passwords} weak passwords that need to be updated.',
            'action': 'showUpdateModal()',
            'action_text': 'Update Now'
        })
    
    if expired_passwords > 0:
        recommendations.append({
            'icon': 'clock',
            'message': f'You have {expired_passwords} passwords that are more than 180 days old.',
            'action': 'showUpdateModal()',
            'action_text': 'Update Now'
        })
    
    if total_passwords < 5:
        recommendations.append({
            'icon': 'plus-circle',
            'message': 'Consider adding more passwords to your vault for better security.',
            'action': 'window.location.href="/password-manager/"',
            'action_text': 'Add Passwords'
        })
    
    return recommendations
