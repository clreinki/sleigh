import requests
import toml
from django.core.management.base import BaseCommand
from sleigh.models import Rule
from django.utils import timezone

class Command(BaseCommand):
    help = 'Import rules from a TOML file located at a given URL'

    def add_arguments(self, parser):
        parser.add_argument('url', type=str, help='The URL of the TOML file to import')

    def handle(self, *args, **kwargs):
        url = kwargs['url']
        try:
            # Fetch the TOML file from the given URL
            response = requests.get(url)
            response.raise_for_status()
            toml_data = toml.loads(response.text)

            # Iterate over the rules and create Rule instances
            for rule_data in toml_data['rules']:
                Rule.objects.create(
                    description=rule_data.get('custom_msg', ''),
                    identifier=rule_data['identifier'],
                    policy=rule_data['policy'],
                    rule_type=rule_data['rule_type'],
                    custom_msg=rule_data.get('custom_msg', None),
                    custom_url=rule_data.get('custom_url', None),
                    date_created=timezone.now(),
                    profile=1
                )

            self.stdout.write(self.style.SUCCESS('Rules imported successfully!'))

        except requests.exceptions.RequestException as e:
            self.stderr.write(self.style.ERROR(f'Failed to fetch TOML file: {e}'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Error importing rules: {e}'))
