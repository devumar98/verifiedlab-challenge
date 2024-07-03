from django.urls import path
from user.views import loginView, registerView, CookieTokenRefreshView, logoutView, user, home, get_ethereum_balance

app_name = "user"

urlpatterns = [
    path('login', loginView),
    path('register', registerView),
    path('refresh-token', CookieTokenRefreshView.as_view()),
    path('logout', logoutView),
    path('user', user),
    path('', home, name='home'),
    path('ethereum-balance', get_ethereum_balance, name='get_ethereum_balance'),
]
