from django.urls import path  # Import Django's path function for URL routing
from . import views  # Import views from the current app

# Define URL patterns for the application
urlpatterns = [
    path('', views.index, name='index'),  # Home page route
    path('signup/', views.signup, name='signup'),  # User signup page
    path('login/', views.user_login, name='login'),  # User login page
    path('logout/', views.user_logout, name='logout'),  # User logout functionality
    path('verify-email/<uidb64>/<token>/', views.verify_email, name='verify_email'),  # Email verification route
]
