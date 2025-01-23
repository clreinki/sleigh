from decouple import config
import os

def export_vars(request):
    data = {}
    data['ORG_VAR'] = config('ORG', default=None)
    data['ELASTIC_VAR'] = config('ELASTIC_URL', default=None)
    data['ELASTICLINK_VAR'] = config('ELASTIC_LINK', default=None)
    return data