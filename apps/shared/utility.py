import re
import threading

from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from rest_framework import exceptions


regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"


def check_emter_email(email):
    if re.fullmatch(regex, email):
        email = 'email'
    else:
        raise exceptions.ValidationError(
            {
                "access": False,
                "message": "email yaroqli emas"
            }
        )
    return email


class EamilThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == 'html':
            email.content_subtype = 'hthml'
        EamilThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {'code': code}
    )
    Email.send_email({
        "subject": "ro'yxatdam o'rish",
        "to_email": email,
        "body": html_content,
        "content_type": "html"
    })