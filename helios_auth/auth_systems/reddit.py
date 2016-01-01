"""
Reddit Authentication

"""

from django.http import *
from django.core.mail import send_mail
from django.conf import settings

import httplib2,json

import sys, os, cgi, urllib, urllib2, re, random

from oauth2client.client import OAuth2WebServerFlow

# some parameters to indicate that status updating is not possible
STATUS_UPDATES = False

# display tweaks
LOGIN_MESSAGE = "Log in with my Reddit Account"

def get_flow(redirect_url=None, state=None):
  return OAuth2WebServerFlow(client_id=settings.REDDIT_CLIENT_ID,
            client_secret=settings.REDDIT_CLIENT_SECRET,
            auth_uri='https://www.reddit.com/api/v1/authorize',
            token_uri='https://www.reddit.com/api/v1/access_token',
            revoke_uri='https://www.reddit.com/api/v1/revoke_token',
            scope='identity',
            redirect_uri=redirect_url,
            duration='temporary',
            state=state)

def get_auth_url(request, redirect_url):
  request.session['reddit-state'] = random.randrange(0, 10000)

  flow = get_flow(redirect_url, request.session['reddit-state'])

  request.session['reddit-redirect-url'] = redirect_url
  
  return flow.step1_get_authorize_url()

def get_user_info_after_auth(request):
  flow = get_flow(request.session['reddit-redirect-url'])
  del request.session['reddit-redirect-url']
  
  state = request.session['reddit-state']
  del request.session['reddit-state']
  
  # Verify that the state matches
  if str(request.GET['state']) != str(state):
    raise FlowExchangeError('State does not match! Expected %s got %s' % (state, request.GET['state']))

  code = request.GET['code']
  credentials = step2_exchange(flow, code) # Needs to be modified for reddit OAuth

  # get the nice name
  http = httplib2.Http(".cache")
  http = credentials.authorize(http)
  (resp_headers, content) = http.request("https://oauth.reddit.com/api/v1/me", "GET")

  response = json.loads(content)

  name = response['name']
  
  return {'type': 'reddit', 'user_id': name, 'name': name, 'info': {'name': name}, 'token':{}}
    
def do_logout(user):
  """
  logout of Reddit
  """
  return None
  
def update_status(token, message):
  """
  simple update
  """
  pass

def send_message(user_id, name, user_info, subject, body):
  """
  send email to reddit users. user_id is the username for reddit.
  """
  pass
  
def check_constraint(constraint, user_info):
  """
  for eligibility
  """
  pass


#
# Election Creation
#

def can_create_election(user_id, user_info):
  return True


# OAUTH CODE, based on oauth2client code

from oauth2client.client import FlowExchangeError, OAuth2Credentials, _parse_exchange_token_response, _extract_id_token, logger
import datetime

def step2_exchange(self, code, http=None):
  """Exhanges a code for OAuth2Credentials.

  Args:
    code: string or dict, either the code as a string, or a dictionary
      of the query parameters to the redirect_uri, which contains
      the code.
    http: httplib2.Http, optional http instance to use to do the fetch

  Returns:
    An OAuth2Credentials object that can be used to authorize requests.

  Raises:
    FlowExchangeError if a problem occured exchanging the code for a
    refresh_token.
  """

  if not (isinstance(code, str) or isinstance(code, unicode)):
    if 'code' not in code:
      if 'error' in code:
        error_msg = code['error']
      else:
        error_msg = 'No code was supplied in the query parameters.'
      raise FlowExchangeError(error_msg)
    else:
      code = code['code']

  body = urllib.urlencode({
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': self.redirect_uri,
      })
  headers = {
      'content-type': 'application/x-www-form-urlencoded',
  }

  if self.user_agent is not None:
    headers['user-agent'] = self.user_agent

  if http is None:
    http = httplib2.Http()

  http.add_credentials(self.client_id, self.client_secret)

  resp, content = http.request(self.token_uri, method='POST', body=body,
                               headers=headers)
  d = _parse_exchange_token_response(content)
  if resp.status == 200 and 'access_token' in d:
    access_token = d['access_token']
    refresh_token = d.get('refresh_token', None)
    token_expiry = None
    if 'expires_in' in d:
      token_expiry = datetime.datetime.utcnow() + datetime.timedelta(
          seconds=int(d['expires_in']))

    if 'id_token' in d:
      d['id_token'] = _extract_id_token(d['id_token'])

    logger.info('Successfully retrieved access token')
    return OAuth2Credentials(access_token, self.client_id,
                             self.client_secret, refresh_token, token_expiry,
                             self.token_uri, self.user_agent,
                             revoke_uri=self.revoke_uri,
                             id_token=d.get('id_token', None),
                             token_response=d)
  else:
    logger.info('Failed to retrieve access token: %s' % content)
    if 'error' in d:
      # you never know what those providers got to say
      error_msg = unicode(d['error'])
    else:
      error_msg = 'Invalid response: %s.' % str(resp.status)
    raise FlowExchangeError(error_msg)
