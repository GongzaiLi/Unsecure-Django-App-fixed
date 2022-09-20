import logging

from cryptography.fernet import Fernet

from django.conf import settings
from django.core import mail, validators, serializers
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.http import HttpResponse

from apps.home.models import UserProfile

from .forms import LoginForm, SignUpForm, ResetForm, ResetPasswordForm

logger = logging.getLogger(__name__)


def login_user(request):
    form = LoginForm(request.POST or None)
    msg = None

    if request.method == "POST":

        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)
                response = HttpResponseRedirect("/")
                response.set_cookie(
                    "superuser", Fernet(settings.FERNET).encrypt(str(user.is_superuser).encode()).decode()  # FERNET key
                )
                return response
            else:
                logger.debug(form.data)
                msg = "Invalid credentials"

        else:
            msg = "Error in form"

    return render(request, "accounts/login.html", {"form": form, "msg": msg})


def register_user(request):
    msg = None
    success = False

    if request.method == "POST":
        form = SignUpForm(request.POST)

        if form.is_valid() and user_does_not_exist(form):
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            UserProfile(user_id=user.id).save()

            current_site = get_current_site(request)
            message = render_to_string('accounts/register_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            send_confirmation_email(form.cleaned_data["email"], message)
            success = True
            msg = "User created successfully, Please check your email to confirm"

        else:
            logger.debug(form.data)
            msg = "Error/s in form"

    else:
        form = SignUpForm()

    return render(request, "accounts/register.html", {"form": form, "msg": msg, "success": success})


def register_activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        # return redirect('home')
        return HttpResponse(
            'Thank you for your email confirmation. Now you can login your account.')  # todo make a nice html
    else:
        return HttpResponse('Activation link is invalid!')


def reset_password(request):
    msg = None
    success = False

    if request.method == "POST":
        form = ResetForm(request.POST)

        user = User.objects.filter(email=form.data["email"]).first()
        if form.is_valid() and user is not None:
            email = form.cleaned_data["email"]
            current_site = get_current_site(request)
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            send_reset_password_email(email, message)

            return redirect("/reset_password/sent/")
        else:
            logger.debug(form.data)
            msg = "Error/s in form"
    else:
        form = ResetForm()
    return render(request, "accounts/reset_password.html", {"form": form, "msg": msg, "success": success, "rest": True})


def reset_password_sent(request):
    return render(request, "accounts/reset_password_sent.html")


def reset_password_confirm(request, uidb64, token):
    msg = None
    success = False

    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):

        if request.method == "POST":
            form = ResetPasswordForm(request.POST)
            user = request.user
            if form.is_valid():
                if form.cleaned_data["password1"] == form.cleaned_data["password2"]:
                    user.set_password(form.cleaned_data["password1"])
                    user.save()
                    return redirect("/reset_password/done/")
                else:
                    form.add_error("password2", "Passwords don't match")
                    msg = "Error/s in form"
            else:
                logger.debug(form.data)
                msg = "Error/s in form"
        else:
            form = ResetPasswordForm()

        return render(request, "accounts/reset_password.html", {"form": form, "msg": msg, "success": success})
    else:
        return HttpResponse('Activation link is invalid!')


def reset_password_done(request):
    success = True
    msg = "Password reset successfully"
    return render(request, "accounts/reset_password.html", {"msg": msg, "success": success})


def logout_user(request):
    logout(request)
    response = redirect("/login/")
    for cookie in request.COOKIES:
        response.delete_cookie(cookie)
    return response

##
# Helper functions
##


def user_does_not_exist(form):
    rawsql = "select * from auth_user where email like '" + form.data["email"] + "'"
    logger.debug(rawsql)
    result = User.objects.raw(rawsql)
    logger.debug("query returned %s", serializers.serialize("json", result))
    if len(result) > 0:
        form.add_error("email", "email taken")

    return len(result) == 0


def email_is_valid(form):
    result = False
    try:
        validators.validate_email(form.data["email"])
        result = True
    except ValidationError as e:
        form.add_error("email", "email is invalid")
    return result


def send_confirmation_email(email, message):
    connection = mail.get_connection()
    connection.open
    to_send = mail.EmailMessage(
        "Welcome to SENG402 Unsecure App",
        message,
        "seng402@unsecure.app",
        [email],
        connection=connection,
    )
    to_send.send()
    connection.close()


def send_reset_password_email(email, message):
    connection = mail.get_connection()
    connection.open
    to_send = mail.EmailMessage(
        "A notification from SENG402 Unsecure App",
        message,
        "seng402@unsecure.app",
        [email],
        connection=connection,
    )
    to_send.send()
    connection.close()
