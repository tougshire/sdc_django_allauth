from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings

class SDCAccountAdapter(DefaultAccountAdapter):

    def is_open_for_signup(self, request):
        default = super().is_open_for_signup(request)
        return getattr(settings, 'ACCOUNT_IS_OPEN_FOR_SIGNUP', default)

    def allow_mfa_setup(self, request):
        return getattr(settings, 'ACCOUNT_ALLOW_MFA_SETUP', False)
