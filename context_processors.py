from .account.adapter import SDCAccountAdapter


def sdc_allauth(request):
    adapter = SDCAccountAdapter()
    return {'sdc_allauth_is_open_for_signup': adapter.is_open_for_signup(request)}
