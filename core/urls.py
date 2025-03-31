from . import views
from django.urls import path
urlpatterns = [
    path('', views.home, name='home'),
    path("analyze-password/", views.analyze_password, name="analyze-password"),
    path("remember-phrase/", views.remember_phrase, name="remember_phrase"),
    path("make-unpredictable/", views.make_unpredictable_password, name="make_unpredictable"),
    path("save-password/", views.save_password, name="save-password"),
]
