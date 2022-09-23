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
from django.contrib.auth.password_validation import validate_password

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
                logger.info("POST login user  %s", user.pk)
                return response
            else:
                logger.debug("Post Invalid credentials %s", form.errors)
                msg = "Invalid credentials"

        else:
            logger.debug(form.errors)
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
            logger.info("POST register user  %s", user.pk)

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
            logger.debug(form.errors)
            msg = "Error/s in form"

    else:
        logger.info("GET new user")
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
        logger.info("POST login user  %s", user.pk)
        # return redirect('home')
        return HttpResponse(
            'Thank you for your email confirmation. Now you can login your account.')  # todo make a nice html
    else:
        logger.info("Activation link is invalid")
        return HttpResponse('Activation link is invalid!')


def reset_password(request):
    msg = None
    success = False

    if request.method == "POST":
        form = ResetForm(request.POST)

        user = User.objects.filter(email=form.data["email"]).first()
        if form.is_valid() and user is not None:
            logger.info("POST reset password user  %s", user.pk)
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
            logger.debug(form.errors)
            msg = "Error/s in form"
    else:
        logger.info("GET reset password")
        form = ResetForm()
    return render(request, "accounts/reset_password.html", {"form": form, "msg": msg, "success": success, "rest": True})


def reset_password_sent(request):
    logger.info("GET reset password email end")
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

            if form.is_valid():
                password1 = form.cleaned_data.get("password1")
                password2 = form.cleaned_data.get("password2")
                try:
                    validate_password(password1, user)
                    validate_password(password2, user)
                except ValidationError as e:
                    form.add_error('password1', e)
                    logger.debug(form.errors)
                    msg = "Error/s in form"
                    return render(request, "accounts/reset_password.html",
                                  {"form": form, "msg": msg, "success": success})

                if form.cleaned_data["password1"] == form.cleaned_data["password2"]:
                    login(request, user)
                    user.set_password(form.cleaned_data["password1"])
                    user.save()
                    logger.info("POST reset password confirm user  %s", user.pk)
                    return redirect("/reset_password/done/")
                else:
                    form.add_error("password2", "Passwords don't match")
                    logger.debug(form.errors)
                    msg = "Error/s in form"
            else:
                logger.debug(form.errors)
                msg = "Error/s in form"
        else:
            logger.info("GET reset password confirm")
            form = ResetPasswordForm()

        return render(request, "accounts/reset_password.html", {"form": form, "msg": msg, "success": success})
    else:
        logger.info("Activation link is invalid")
        return HttpResponse('Activation link is invalid!')


def reset_password_done(request):
    success = True
    msg = "Password reset successfully"
    return render(request, "accounts/reset_password.html", {"msg": msg, "success": success})


def logout_user(request):
    logger.info("GET logout user %s", request.user.pk)
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
    # logger.debug(rawsql)
    result = User.objects.raw(rawsql)
    # logger.debug("query returned %s", serializers.serialize("json", result))
    if len(result) > 0:
        form.add_error("email", "email taken")
        logger.debug(form.errors)

    return len(result) == 0


def email_is_valid(form):
    result = False
    try:
        validators.validate_email(form.data["email"])
        result = True
    except ValidationError as e:
        form.add_error("email", "email is invalid")
        logger.debug("email is invalid is %s", e)
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
