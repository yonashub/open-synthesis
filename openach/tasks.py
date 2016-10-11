"""Celery tasks.

For more information, please see:
- http://docs.celeryproject.org/en/latest/django/first-steps-with-django.html

"""

from datetime import timedelta
from django.utils import timezone
import itertools
import json
import logging
import re
import urllib.request

from celery import shared_task
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Q

from .models import EvidenceSource, EvidenceSourceScan


logger = logging.getLogger(__name__)

# max number of URLs to pass to Google's safe browsing API
SAFE_BROWSING_URL_MAX_BATCH = 500


def duration_to_delta(duration):
    """Convert a Google Safe Browsing API cache duration to a timedelta."""
    match = re.match('([\d\.]+)s', duration)
    if match:
        logger.debug('found duration in seconds: %s (as float: %s)', match.group(1), float(match.group(1)))
        return timedelta(seconds=float(match.group(1)))
    else:
        return ValueError('Unexpected cache duration {}'.format(duration))


def check_urls(urls, api_key, client_id, client_version):
    """Check one or more URLs against the Google Safe Browsing API.

    For more information, please see:
        https://developers.google.com/safe-browsing/v4/lookup-api

    :param urls: iterable of URLs to check
    :param api_key: the Google Safe Browsing API key
    :param client_id: a name that represents the true identity of the client, such as your company name, presented as
    all one word, in all-lowercase letters
    :param client_version: client version number
    :return mapping from unsafe URL to duration to catch
    """
    if not re.match('[a-z\-]+', client_id):
        raise ValueError('clientID should be one word, lowercase')
    api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}'.format(api_key)
    data = json.dumps({
        'client': {
            'clientId': client_id,
            'clientVersion': client_version,
        },
        'threatInfo': {
            'threatTypes': [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'THREAT_TYPE_UNSPECIFIED',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            "threatEntries": [{'url': url for url in urls}]
        },
    }).encode('utf-8')
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': len(data)
    }
    request = urllib.request.Request(api_url, data=data, headers=headers)
    with urllib.request.urlopen(request) as f:
        response = json.loads(f.read().decode(f.info().get_param('charset') or 'utf-8'))
        return {
            match['threat']['url']: duration_to_delta(match['cacheDuration'])
            for match in response['matches']
        }


def grouper(iterable, n, fillvalue=None):
    """Collect data into fixed-length chunks or blocks."""
    # copied from https://docs.python.org/3/library/itertools.html#itertools-recipes
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


@shared_task
def check_source_urls():
    """Check source URLs against the Google Safe Browsing API."""
    api_key = getattr(settings, 'GOOGLE_API_KEY')
    client_id = getattr(settings, 'GOOGLE_CLIENT_ID')
    client_version = getattr(settings, 'GOOGLE_CLIENT_VERSION')

    if api_key and client_id and client_version:
        query = Q(safescan__isnull=True) | Q(safescan__cache_deadline__lt=timezone.now())
        sources = list(EvidenceSource.objects.filter(query))
        logger.debug('Found %s source URLs to check', len(sources))
        for batch in grouper(sources, SAFE_BROWSING_URL_MAX_BATCH):
            batch_list = list(filter(None.__ne__, batch))
            timestamp = timezone.now()
            urls = [source.source_url for source in batch_list]
            logger.debug('Checking %s URLs vs. Google Safe Browsing API', len(urls))
            results = check_urls(urls, api_key=api_key, client_id=client_id, client_version=client_version)
            for source in batch_list:
                url = source.source_url
                EvidenceSourceScan.objects.update_or_create(source=source, defaults={
                    'last_scan': timestamp,
                    'unsafe': url in results,
                    'cache_deadline': timestamp + results[url] if url in results else None
                })
    else:
        raise ImproperlyConfigured('Google safe browsing variables not configured')


@shared_task
def example_task(x, y):  # pragma: no cover
    """Add two numbers together.

    An example for reference.
    """
    return x + y
