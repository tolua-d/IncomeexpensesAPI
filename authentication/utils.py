from django.core.mail import EmailMessage

class Util:
    @staticmethod # helps you use the class without instanstiating it
    def send_email(data):
        
        email = EmailMessage(
            subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.send()