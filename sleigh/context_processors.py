from decouple import config
import os

def export_vars(request):
    data = {}
    data['ORG_VAR'] = config('ORG', default=None)
    return data