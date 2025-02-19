from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings
from django.shortcuts import get_object_or_404

def index(request):
    return render(request, 'myapp/login.html')

# User login logic
def user_login(request):
    if request.method == 'POST':
        # Retrieve username and password from the form
        username = request.POST['username']
        password = request.POST['password']

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Log the user in if authentication is successful
            login(request, user)
            messages.success(request, "You have been logged in successfully.")
            return render(request, 'myapp/index.html')  # Redirect to the main page after login
        else:
            # Show error message if authentication fails
            messages.error(request, "Invalid username or password.")
            return redirect('login')  # Redirect back to the login page

    # Render the login page for GET requests
    return render(request, 'myapp/login.html')

# User logout logic
def user_logout(request):
    # Log the user out
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')  # Redirect to the login page after logout

# User signup logic
def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm-password']

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect('signup')

        # Create a new user but set is_active to False initially
        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = False
        user.save()

        # Generate a token for email verification
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Create the verification link
        verification_link = request.build_absolute_uri(
            reverse('verify_email', kwargs={'uidb64': uid, 'token': token})
        )

        # Send the verification email
        subject = "Verify your email address"
        message = f"Click the link below to verify your email address:\n\n{verification_link}"
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

        messages.success(request, "Account created successfully. Please check your email to verify your account.")
        return redirect('login')

    return render(request, 'myapp/signup.html')

# Email verification logic
def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User, pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your email has been verified. You can now login.")
        return redirect('index')  # Redirect to the index page after successful verification
    else:
        messages.error(request, "Invalid verification link.")
        return redirect('signup')