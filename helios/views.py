# -*- coding: utf-8 -*-
"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.core.exceptions import PermissionDenied
from django.http import *
from django.db import transaction

from mimetypes import guess_type

from validate_email import validate_email

import csv, urllib, os, base64

from crypto import algs, electionalgs, elgamal
from crypto import utils as cryptoutils
from workflows import homomorphic
from workflows import mixnet
from helios import utils as helios_utils
from view_utils import *

from helios_auth.security import *
from helios_auth.auth_systems import AUTH_SYSTEMS, can_list_categories
from helios_auth.models import AuthenticationExpired

from helios import security
from helios_auth import views as auth_views

import tasks

from security import *
from helios_auth.security import get_user, save_in_session_across_logouts

import uuid, datetime

from models import *

import forms, signals

import json

# Parameters for everything
ELGAMAL_PARAMS = elgamal.Cryptosystem()

# 2048-bit MODP Group from RFC 3526
# I hope this is secure...
DEFAULT_CRYPTOSYSTEM = {'p': 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559L, 'q': 16158503035655503650169456963211914124408970620570119556421004875700370853317177111309844708681784673558950868954852095877302936604597514426879493092811076606087706257450887260135117898039118124442123094738793820552964323049705861622713311261096615270459518840262117759562839857935058500529027938825519430923640128988027451784866280763083540669680899770668238279580184158948364536589192294840319835950488601097084323612935515705668214659768096735818266604858538724113994294282684604322648318038625134477752964181375560587048486499034205277179792433291645821068109115539495499724326234131208486017955926253522680545279L, 'g': 2L}

DEFAULT_CRYPTOSYSTEM_PARAMS = getattr(settings, 'HELIOS_CRYPTOSYSTEM_PARAMS', DEFAULT_CRYPTOSYSTEM)

ELGAMAL_PARAMS.p = DEFAULT_CRYPTOSYSTEM_PARAMS['p']
ELGAMAL_PARAMS.q = DEFAULT_CRYPTOSYSTEM_PARAMS['q']
ELGAMAL_PARAMS.g = DEFAULT_CRYPTOSYSTEM_PARAMS['g']

# object ready for serialization
ELGAMAL_PARAMS_LD_OBJECT = datatypes.LDObject.instantiate(ELGAMAL_PARAMS, datatype='legacy/EGParams')

# single election server? Load the single electionfrom models import Election
from django.conf import settings

def get_election_url(election):
  return settings.URL_HOST + reverse(election_shortcut, args=[election.short_name])

def get_election_badge_url(election):
  return settings.URL_HOST + reverse(election_badge, args=[election.uuid])

def get_election_govote_url(election):
  return settings.URL_HOST + reverse(election_vote_shortcut, args=[election.short_name])

def get_castvote_url(cast_vote):
  return settings.URL_HOST + reverse(castvote_shortcut, args=[cast_vote.vote_tinyhash])


##
## remote auth utils

def user_reauth(request, user):
  # FIXME: should we be wary of infinite redirects here, and
  # add a parameter to prevent it? Maybe.
  login_url = "%s%s?%s" % (settings.SECURE_URL_HOST,
                           reverse(auth_views.start, args=[user.user_type]),
                           urllib.urlencode({'return_url':
                                               request.get_full_path()}))
  return HttpResponseRedirect(login_url)

##

# simple static views
def home(request):
  user = get_user(request)
  if user:
    elections = Election.get_by_user_as_admin(user, archived_p = False)
  else:
    elections = []

  return render_template(request, "index", {'elections' : elections})

def stats(request):
  user = get_user(request)
  if not user or not user.admin_p:
    raise PermissionDenied()

  page = int(request.GET.get('page', 1))
  limit = int(request.GET.get('limit', 25))

  elections = Election.objects.all().order_by('-created_at')
  elections_paginator = Paginator(elections, limit)
  elections_page = elections_paginator.page(page)

  return render_template(request, "stats", {'elections' : elections_page.object_list, 'elections_page': elections_page,
                                            'limit' : limit})


##
## simple admin for development
##
def admin_autologin(request):
  if "localhost" not in settings.URL_HOST and "127.0.0.1" not in settings.URL_HOST:
    raise Http404

  users = User.objects.filter(admin_p=True)
  if len(users) == 0:
    return HttpResponse("no admin users!")

  if len(users) == 0:
    return HttpResponse("no users!")

  user = users[0]
  request.session['user'] = {'type' : user.user_type, 'user_id' : user.user_id}
  return HttpResponseRedirect("/")

##
## General election features
##

@return_json
def election_params(request):
  return ELGAMAL_PARAMS_LD_OBJECT.toJSONDict()

def election_verifier(request):
  return render_template(request, "tally_verifier")

def election_single_ballot_verifier(request):
  return render_template(request, "ballot_verifier")

def election_shortcut(request, election_short_name):
  election = Election.get_by_short_name(election_short_name)
  if election:
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
  else:
    raise Http404

# a hidden view behind the shortcut that performs the actual perm check
@election_view()
def _election_vote_shortcut(request, election):
  vote_url = "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urllib.urlencode({'election_url' : reverse(one_election, args=[election.uuid])}))

  test_cookie_url = "%s?%s" % (reverse(test_cookie), urllib.urlencode({'continue_url' : vote_url}))

  return HttpResponseRedirect(test_cookie_url)

def election_vote_shortcut(request, election_short_name):
  election = Election.get_by_short_name(election_short_name)
  if election:
    return _election_vote_shortcut(request, election_uuid=election.uuid)
  else:
    raise Http404

@election_view()
def _castvote_shortcut_by_election(request, election, cast_vote):
  return render_template(request, 'castvote', {'cast_vote' : cast_vote, 'vote_content': cast_vote.vote.toJSON(), 'the_voter': cast_vote.voter, 'election': election})

def castvote_shortcut(request, vote_tinyhash):
  try:
    cast_vote = CastVote.objects.get(vote_tinyhash = vote_tinyhash)
  except CastVote.DoesNotExist:
    raise Http404

  return _castvote_shortcut_by_election(request, election_uuid = cast_vote.voter.election.uuid, cast_vote=cast_vote)

@trustee_check
def trustee_keygenerator(request, election, trustee):
  """
  A key generator with the current params, like the trustee home but without a specific election.
  """
  eg_params_json = utils.to_json(ELGAMAL_PARAMS_LD_OBJECT.toJSONDict())

  return render_template(request, "election_keygenerator", {'eg_params_json': eg_params_json, 'election': election, 'trustee': trustee})

@login_required
def elections_administered(request):
  if not can_create_election(request):
    return HttpResponseForbidden('only an administrator has elections to administer')

  user = get_user(request)
  elections = Election.get_by_user_as_admin(user)

  return render_template(request, "elections_administered", {'elections': elections})

@login_required
def elections_voted(request):
  user = get_user(request)
  elections = Election.get_by_user_as_voter(user)

  return render_template(request, "elections_voted", {'elections': elections})


@login_required
def election_new(request):
  if not can_create_election(request):
    return HttpResponseForbidden('only an administrator can create an election')

  error = None
  
  user = get_user(request)

  if request.method == "GET":
    election_form = forms.ElectionForm(initial={'private_p': settings.HELIOS_PRIVATE_DEFAULT,
                                                'help_email': user.info.get("email", '')})
  else:
    check_csrf(request)
    election_form = forms.ElectionForm(request.POST)

    if election_form.is_valid():
      # create the election obj
      election_params = dict(election_form.cleaned_data)

      # is the short name valid
      if helios_utils.urlencode(election_params['short_name']) == election_params['short_name']:
        election_params['uuid'] = str(uuid.uuid1())
        election_params['cast_url'] = settings.SECURE_URL_HOST + reverse(one_election_cast, args=[election_params['uuid']])

        # registration starts closed
        election_params['openreg'] = False

        user = get_user(request)
        election_params['admin'] = user

        election, created_p = Election.get_or_create(**election_params)

        if created_p:
          # add Helios as a trustee by default
          election.generate_trustee(ELGAMAL_PARAMS)
          if election.workflow_type == "mixnet":
              election.generate_helios_mixnet()

          return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
        else:
          error = "An election with short name %s already exists" % election_params['short_name']
      else:
        error = "No special characters allowed in the short name."

  return render_template(request, "election_new", {'election_form': election_form, 'error': error})

@election_admin(frozen=False)
def one_election_edit(request, election):

  error = None
  RELEVANT_FIELDS = ['short_name', 'name', 'description', 'use_voter_aliases',
      'election_type', 'private_p', 'help_email', 'randomize_answer_order',
      'workflow_type']
  # RELEVANT_FIELDS += ['use_advanced_audit_features']

  if settings.ALLOW_ELECTION_INFO_URL:
    RELEVANT_FIELDS += ['election_info_url']
  if request.method == "GET":
    values = {}
    for attr_name in RELEVANT_FIELDS:
      values[attr_name] = getattr(election, attr_name)
    election_form = forms.ElectionForm(values)
  else:
    check_csrf(request)
    election_form = forms.ElectionForm(request.POST)

    if election_form.is_valid():
      clean_data = election_form.cleaned_data
      for attr_name in RELEVANT_FIELDS:
        setattr(election, attr_name, clean_data[attr_name])

      election.save()
        
      return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
  
  return render_template(request, "election_edit", {'election_form' : election_form, 'election' : election, 'error': error})

@election_admin(frozen=False)
def one_election_schedule(request, election):
  return HttpResponse("foo")

@election_view()
@return_json
def one_election(request, election):
  if not election:
    raise Http404
  return election.toJSONDict(complete=True)

@election_view()
@return_json
def one_election_meta(request, election):
  if not election:
    raise Http404
  return election.metadata

@election_view()
def election_badge(request, election):
  election_url = get_election_url(election)
  params = {'election': election, 'election_url': election_url}
  for option_name in ['show_title', 'show_vote_link']:
    params[option_name] = (request.GET.get(option_name, '1') == '1')
  return render_template(request, "election_badge", params)

@election_view()
def one_election_view(request, election):
  user = get_user(request)
  admin_p = security.user_can_admin_election(user, election)
  can_feature_p = security.user_can_feature_election(user, election)

  notregistered = False
  eligible_p = True

  election_url = get_election_url(election)
  election_badge_url = get_election_badge_url(election)
  status_update_message = None

  vote_url = "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urllib.urlencode({'election_url' : reverse(one_election, args=[election.uuid])}))

  test_cookie_url = "%s?%s" % (reverse(test_cookie), urllib.urlencode({'continue_url' : vote_url}))

  if user:
    voter = Voter.get_by_election_and_user(election, user)

    if not voter:
      try:
        eligible_p = _check_eligibility(election, user)
      except AuthenticationExpired:
        return user_reauth(request, user)
      notregistered = True
  else:
    voter = get_voter(request, user, election)

  if voter:
    # cast any votes?
    votes = CastVote.get_by_voter(voter)
  else:
    votes = None

  # status update message?
  if election.openreg:
    if election.voting_has_started:
      status_update_message = u"Vote in %s" % election.name
    else:
      status_update_message = u"Register to vote in %s" % election.name

  # result!
  if election.result:
    status_update_message = u"Results are in for %s" % election.name

  trustees = Trustee.get_by_election(election)
  mixnets = election.mixnets.filter()

  # should we show the result?
  show_result = election.result_released_at or (election.result and admin_p)

  return render_template(request, 'election_view',
                         {'election' : election, 'trustees': trustees, 'admin_p': admin_p, 'user': user,
                          'voter': voter, 'votes': votes, 'notregistered': notregistered, 'eligible_p': eligible_p,
                          'can_feature_p': can_feature_p, 'election_url' : election_url,
                          'vote_url': vote_url, 'election_badge_url' : election_badge_url,
                          'show_result': show_result,
                          'test_cookie_url': test_cookie_url,
                          'mixnets': mixnets})

def test_cookie(request):
  continue_url = request.GET['continue_url']
  request.session.set_test_cookie()
  next_url = "%s?%s" % (reverse(test_cookie_2), urllib.urlencode({'continue_url': continue_url}))
  return HttpResponseRedirect(settings.SECURE_URL_HOST + next_url)  

def test_cookie_2(request):
  continue_url = request.GET['continue_url']

  if not request.session.test_cookie_worked():
    return HttpResponseRedirect(settings.SECURE_URL_HOST + ("%s?%s" % (reverse(nocookies), urllib.urlencode({'continue_url': continue_url}))))

  request.session.delete_test_cookie()
  return HttpResponseRedirect(continue_url)

def nocookies(request):
  retest_url = "%s?%s" % (reverse(test_cookie), urllib.urlencode({'continue_url' : request.GET['continue_url']}))
  return render_template(request, 'nocookies', {'retest_url': retest_url})

##
## Trustees and Public Key
##
## As of July 2009, there are always trustees for a Helios election: one trustee is acceptable, for simple elections.
##
@election_view()
@return_json
def list_trustees(request, election):
  trustees = Trustee.get_by_election(election)
  return [t.toJSONDict(complete=True) for t in trustees]

@election_view()
def list_trustees_view(request, election):
  trustees = Trustee.get_by_election(election)
  user = get_user(request)
  admin_p = security.user_can_admin_election(user, election)
  
  return render_template(request, 'list_trustees', {'election': election, 'trustees': trustees, 'admin_p':admin_p})

@election_admin(frozen=False)
def edit_trustee_threshold(request, election):
  check_csrf(request)
  election.trustee_threshold = int(request.POST['trustee_threshold'])
  election.save()
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_trustees_view, args=[election.uuid]))

@election_admin(frozen=False)
def new_trustee(request, election):
  if request.method == "GET":
    return render_template(request, 'new_trustee', {'election' : election})
  else:
    check_csrf(request)
    # get the public key and the hash, and add it
    name = request.POST['name']
    email = request.POST['email']

    trustee = Trustee(uuid = str(uuid.uuid1()), election = election, name=name, email=email)
    trustee.save()
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_trustees_view, args=[election.uuid]))

@election_admin(frozen=False)
def new_trustee_helios(request, election):
  """
  Make Helios a trustee of the election
  """
  election.generate_trustee(ELGAMAL_PARAMS)
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_trustees_view, args=[election.uuid]))
  
@election_admin(frozen=False)
def delete_trustee(request, election):
  trustee = Trustee.get_by_election_and_uuid(election, request.GET['uuid'])
  trustee.delete()
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_trustees_view, args=[election.uuid]))
  
def trustee_login(request, election_short_name, trustee_email, trustee_secret):
  election = Election.get_by_short_name(election_short_name)
  if election:
    trustee = Trustee.get_by_election_and_email(election, trustee_email)

    if trustee:
      if trustee.secret == trustee_secret:
        set_logged_in_trustee(request, trustee)
        return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(trustee_home, args=[election.uuid, trustee.uuid]))
      else:
        # bad secret, we'll let that redirect to the front page
        pass
    else:
      # no such trustee
      raise Http404

  return HttpResponseRedirect(settings.SECURE_URL_HOST + "/")

@election_admin()
def trustee_send_url(request, election, trustee_uuid):
  trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)

  url = settings.SECURE_URL_HOST + reverse(trustee_login, args=[election.short_name, trustee.email, trustee.secret])

  body = """

You are a trustee for %s.

Your trustee dashboard is at

  %s

--
Helios
""" % (election.name, url)

  helios_utils.send_email(settings.SERVER_EMAIL, ["%s <%s>" % (trustee.name, trustee.email)], 'your trustee homepage for %s' % election.name, body)

  logging.info("URL %s " % url)
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_trustees_view, args = [election.uuid]))

@trustee_check
def trustee_home(request, election, trustee):
  return render_template(request, 'trustee_home', {'election': election, 'trustee':trustee})

@trustee_check
def trustee_check_sk(request, election, trustee):
  return render_template(request, 'trustee_check_sk', {'election': election, 'trustee':trustee})

@trustee_check
def trustee_upload_pk(request, election, trustee):
  if request.method == "POST":
    # get the public key and the hash, and add it
    public_key_and_proof = utils.from_json(request.POST['public_key_json'])
    trustee.public_key = algs.EGPublicKey.fromJSONDict(public_key_and_proof['public_key'])
    trustee.pok = algs.DLogProof.fromJSONDict(public_key_and_proof['pok'])

    # verify the pok
    if not trustee.public_key.verify_sk_proof(trustee.pok, algs.DLog_challenge_generator):
      raise Exception("bad pok for this public key")

    trustee.public_key_hash = utils.hash_b64(utils.to_json(trustee.public_key.toJSONDict()))

    trustee.save()

    # send a note to admin
    try:
      election.admin.send_message("%s - trustee pk upload" % election.name, "trustee %s (%s) uploaded a pk." % (trustee.name, trustee.email))
    except:
      # oh well, no message sent
      pass
    
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(trustee_home, args=[election.uuid, trustee.uuid]))

##
## Ballot Management
##

@election_view()
@return_json
def get_randomness(request, election):
  """
  get some randomness to sprinkle into the sjcl entropy pool
  """
  return {
    # back to urandom, it's fine
    "randomness" : base64.b64encode(os.urandom(32))
    #"randomness" : base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes)
    }

@election_view(frozen=True)
@return_json
def encrypt_ballot(request, election):
  """
  perform the ballot encryption given answers_json, a JSON'ified list of list of answers
  (list of list because each question could have a list of answers if more than one.)
  """
  # FIXME: maybe make this just request.POST at some point?
  answers = utils.from_json(request.REQUEST['answers_json'])
  ev = mixnet.EncryptedVote.fromElectionAndAnswers(election, answers)
  return ev.ld_object.includeRandomness().toJSONDict()

@election_view(frozen=True)
def post_audited_ballot(request, election):
  if request.method == "POST":
    raw_vote = request.POST['audited_ballot']
    encrypted_vote = electionalgs.EncryptedVote.fromJSONDict(utils.from_json(raw_vote))
    vote_hash = encrypted_vote.get_hash()
    audited_ballot = AuditedBallot(raw_vote = raw_vote, vote_hash = vote_hash, election = election)
    audited_ballot.save()
    return SUCCESS

# we don't require frozen election to allow for ballot preview
@election_view()
def one_election_cast(request, election):
  """
  on a GET, this is a cancellation, on a POST it's a cast
  """
  if request.method == "GET":
    return HttpResponseRedirect("%s%s" % (settings.SECURE_URL_HOST, reverse(one_election_view, args = [election.uuid])))
    
  user = get_user(request)
  encrypted_vote = request.POST['encrypted_vote']

  save_in_session_across_logouts(request, 'encrypted_vote', encrypted_vote)

  return HttpResponseRedirect("%s%s" % (settings.SECURE_URL_HOST, reverse(one_election_cast_confirm, args=[election.uuid])))

@election_view(allow_logins=True)
def password_voter_login(request, election):
  """
  This is used to log in as a voter for a particular election
  """

  # the URL to send the user to after they've logged in
  bad_voter_login = (request.GET.get('bad_voter_login', "0") == "1")
  return_url = request.GET.get('return_url', None)

  if request.method == "GET":
    # if user logged in somehow in the interim, e.g. using the login link for administration,
    # then go!
    if user_can_see_election(request, election):
      return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args = [election.uuid]))

    password_login_form = forms.VoterPasswordForm()
    return render_template(request, 'password_voter_login',
                           {'election': election,
                            'return_url' : return_url,
                            'password_login_form': password_login_form,
                            'bad_voter_login' : bad_voter_login})

  login_url = request.REQUEST.get('login_url', None)

  if not login_url:
    # login depending on whether this is a private election
    # cause if it's private the login is happening on the front page
    if election.private_p:
      login_url = reverse(password_voter_login, args=[election.uuid])
    else:
      login_url = reverse(one_election_cast_confirm, args=[election.uuid])

  password_login_form = forms.VoterPasswordForm(request.POST)

  if password_login_form.is_valid():
    try:
      voter = election.voter_set.get(voter_login_id = password_login_form.cleaned_data['voter_id'].strip(),
                                     voter_password = password_login_form.cleaned_data['password'].strip())

      request.session['CURRENT_VOTER_ID'] = voter.id

      # if we're asked to cast, let's do it
      if request.POST.get('cast_ballot') == "1":
        return one_election_cast_confirm(request, election.uuid)
      
    except Voter.DoesNotExist:
      redirect_url = login_url + "?" + urllib.urlencode({
          'bad_voter_login' : '1',
          'return_url' : return_url
          })

      return HttpResponseRedirect(settings.SECURE_URL_HOST + redirect_url)
  
  return HttpResponseRedirect(settings.SECURE_URL_HOST + return_url)

@election_view()
def one_election_cast_confirm(request, election):
  user = get_user(request)

  # if no encrypted vote, the user is reloading this page or otherwise getting here in a bad way
  if (not request.session.has_key('encrypted_vote')) or request.session['encrypted_vote'] == None:
    return HttpResponseRedirect(settings.URL_HOST)

  # election not frozen or started
  if not election.voting_has_started():
    return render_template(request, 'election_not_started', {'election': election})

  voter = get_voter(request, user, election)

  # auto-register this person if the election is openreg
  if user and not voter and election.openreg:
    voter = _register_voter(election, user)

  # tallied election, no vote casting
  if election.tallied or election.result:
    return render_template(request, 'election_tallied', {'election': election})

  encrypted_vote = request.session['encrypted_vote']
  vote_fingerprint = cryptoutils.hash_b64(encrypted_vote)

  # if this user is a voter, prepare some stuff
  if voter:
    vote = datatypes.LDObject.fromDict(utils.from_json(encrypted_vote),
        type_hint='phoebus/EncryptedVote').wrapped_obj

    if 'HTTP_X_FORWARDED_FOR' in request.META:
      # HTTP_X_FORWARDED_FOR sometimes have a comma delimited list of IP addresses
      # Here we want the originating IP address
      # See http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html
      # and https://en.wikipedia.org/wiki/X-Forwarded-For
      #
      # Real client IP is apparently guaranteed by Heroku to be the *last* item in the header.
      cast_ip = request.META.get('HTTP_X_FORWARDED_FOR').split(',')[-1].strip() or None
    else:
      cast_ip = request.META.get('REMOTE_ADDR', None)

    # prepare the vote to cast
    cast_vote_params = {
      'vote' : vote,
      'voter' : voter,
      'vote_hash': vote_fingerprint,
      'cast_at': datetime.datetime.utcnow(),
      'cast_ip': cast_ip
    }

    cast_vote = CastVote(**cast_vote_params)
  else:
    cast_vote = None

  if request.method == "GET":
    if voter:
      past_votes = CastVote.get_by_voter(voter)
      if len(past_votes) == 0:
        past_votes = None
    else:
      past_votes = None

    if cast_vote:
      # check for issues
      issues = cast_vote.issues(election)
    else:
      issues = None

    bad_voter_login = (request.GET.get('bad_voter_login', "0") == "1")

    # status update this vote
    if voter and voter.user.can_update_status():
      status_update_label = voter.user.update_status_template() % "your smart ballot tracker"
      status_update_message = "I voted in %s - my smart tracker is %s.. #heliosvoting" % (get_election_url(election),cast_vote.vote_hash[:10])
    else:
      status_update_label = None
      status_update_message = None

    # do we need to constrain the auth_systems?
    if election.eligibility:
      auth_systems = [e['auth_system'] for e in election.eligibility]
    else:
      auth_systems = None

    password_only = False

    if auth_systems == None or 'password' in auth_systems:
      show_password = True
      password_login_form = forms.VoterPasswordForm()

      if auth_systems == ['password']:
        password_only = True
    else:
      show_password = False
      password_login_form = None

    return_url = reverse(one_election_cast_confirm, args=[election.uuid])
    login_box = auth_views.login_box_raw(request, return_url=return_url, auth_systems = auth_systems)

    return render_template(request, 'election_cast_confirm', {
        'login_box': login_box, 'election' : election, 'vote_fingerprint': vote_fingerprint,
        'past_votes': past_votes, 'issues': issues, 'voter' : voter,
        'return_url': return_url,
        'status_update_label': status_update_label, 'status_update_message': status_update_message,
        'show_password': show_password, 'password_only': password_only, 'password_login_form': password_login_form,
        'bad_voter_login': bad_voter_login})

  if request.method == "POST":
    check_csrf(request)

    # voting has not started or has ended
    if (not election.voting_has_started()) or election.voting_has_stopped():
      return HttpResponseRedirect(settings.URL_HOST)

    # if user is not logged in
    # bring back to the confirmation page to let him know
    if not voter:
      return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_cast_confirm, args=[election.uuid]))
    
    # don't store the vote in the voter's data structure until verification
    cast_vote.save()

    # status update?
    if request.POST.get('status_update', False):
      status_update_message = request.POST.get('status_update_message')
    else:
      status_update_message = None

    # launch the verification task
    tasks.cast_vote_verify_and_store.delay(
      cast_vote_id = cast_vote.id,
      status_update_message = status_update_message)

    # remove the vote from the store
    del request.session['encrypted_vote']

    return HttpResponseRedirect("%s%s" % (settings.URL_HOST, reverse(one_election_cast_done, args=[election.uuid])))

@election_view()
def one_election_cast_done(request, election):
  """
  This view needs to be loaded because of the IFRAME, but then this causes
  problems if someone clicks "reload". So we need a strategy.
  We store the ballot hash in the session
  """
  user = get_user(request)
  voter = get_voter(request, user, election)

  if voter:
    votes = CastVote.get_by_voter(voter)
    vote_hash = votes[0].vote_hash
    cv_url = get_castvote_url(votes[0])

    # only log out if the setting says so *and* we're dealing
    # with a site-wide voter. Definitely remove current_voter
    if voter.user == user:
      logout = settings.LOGOUT_ON_CONFIRMATION
    else:
      logout = False
      del request.session['CURRENT_VOTER_ID']

    save_in_session_across_logouts(request, 'last_vote_hash', vote_hash)
    save_in_session_across_logouts(request, 'last_vote_cv_url', cv_url)
  else:
    vote_hash = request.session['last_vote_hash']
    cv_url = request.session['last_vote_cv_url']
    logout = False

  # local logout ensures that there's no more
  # user locally
  # WHY DO WE COMMENT THIS OUT? because we want to force a full logout via the iframe, including
  # from remote systems, just in case, i.e. CAS
  # if logout:
  #   auth_views.do_local_logout(request)

  # remote logout is happening asynchronously in an iframe to be modular given the logout mechanism
  # include_user is set to False if logout is happening
  return render_template(request, 'cast_done', {'election': election,
                                                'vote_hash': vote_hash, 'logout': logout},
                         include_user=(not logout))

@election_view()
@return_json
def one_election_result(request, election):
  if not election.result_released_at:
    raise PermissionDenied
  return election.result

@election_view()
@return_json
def one_election_result_proof(request, election):
  if not election.result_released_at:
    raise PermissionDenied
  return election.result_proof

@election_view(frozen=True)
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  after = request.GET.get('after', None)
  offset= int(request.GET.get('offset', 0))
  limit = int(request.GET.get('limit', 50))

  order_by = 'voter_id'

  # unless it's by alias, in which case we better go by UUID
  if election.use_voter_aliases:
    order_by = 'alias'

  # if there's a specific voter
  if request.GET.has_key('q'):
    # FIXME: figure out the voter by voter_id
    voters = []
  else:
    # load a bunch of voters
    voters = Voter.get_by_election(election, after=after, limit=limit+1, order_by=order_by)

  more_p = len(voters) > limit
  if more_p:
    voters = voters[0:limit]
    next_after = getattr(voters[limit-1], order_by)
  else:
    next_after = None

  return render_template(request, 'election_bboard', {'election': election, 'voters': voters, 'next_after': next_after,
                'offset': offset, 'limit': limit, 'offset_plus_one': offset+1, 'offset_plus_limit': offset+limit,
                'voter_id': request.GET.get('voter_id', '')})

@election_view(frozen=True)
def one_election_audited_ballots(request, election):
  """
  UI to show election audited ballots
  """

  if request.GET.has_key('vote_hash'):
    b = AuditedBallot.get(election, request.GET['vote_hash'])
    return HttpResponse(b.raw_vote, content_type="text/plain")
    
  after = request.GET.get('after', None)
  offset= int(request.GET.get('offset', 0))
  limit = int(request.GET.get('limit', 50))

  audited_ballots = AuditedBallot.get_by_election(election, after=after, limit=limit+1)

  more_p = len(audited_ballots) > limit
  if more_p:
    audited_ballots = audited_ballots[0:limit]
    next_after = audited_ballots[limit-1].vote_hash
  else:
    next_after = None

  return render_template(request, 'election_audited_ballots', {'election': election, 'audited_ballots': audited_ballots, 'next_after': next_after,
                'offset': offset, 'limit': limit, 'offset_plus_one': offset+1, 'offset_plus_limit': offset+limit})

@election_admin()
def voter_delete(request, election, voter_uuid):
  """
  Two conditions under which a voter can be deleted:
  - election is not frozen or
  - election is open reg
  """
  ## FOR NOW we allow this to see if we can redefine the meaning of "closed reg" to be more flexible
  # if election is frozen and has closed registration
  #if election.frozen_at and (not election.openreg):
  #  raise PermissionDenied()

  if election.tallied:
    raise PermissionDenied()

  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  if voter:
    voter.delete()

  if election.frozen_at:
    # log it
    election.append_log("Voter %s/%s removed after election frozen" % (voter.voter_type,voter.voter_id))
    
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(voters_list_pretty, args=[election.uuid]))

@election_admin(frozen=False)
def one_election_set_reg(request, election):
  """
  Set whether this is open registration or not
  """
  # only allow this for public elections
  if not election.private_p:
    open_p = bool(int(request.GET['open_p']))
    election.openreg = open_p
    election.save()
  
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(voters_list_pretty, args=[election.uuid]))

@election_admin()
def one_election_set_featured(request, election):
  """
  Set whether this is a featured election or not
  """

  user = get_user(request)
  if not security.user_can_feature_election(user, election):
    raise PermissionDenied()

  featured_p = bool(int(request.GET['featured_p']))
  election.featured_p = featured_p
  election.save()
  
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))

@election_admin()
def one_election_archive(request, election):

  archive_p = request.GET.get('archive_p', True)

  if bool(int(archive_p)):
    election.archived_at = datetime.datetime.utcnow()
  else:
    election.archived_at = None

  election.save()

  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))

# changed from admin to view because
# anyone can see the questions, the administration aspect is now
# built into the page
@election_view()
def one_election_questions(request, election):
  questions_json = utils.to_json(election.questions)
  user = get_user(request)
  admin_p = security.user_can_admin_election(user, election)

  return render_template(request, 'election_questions', {'election': election, 'questions_json' : questions_json, 'admin_p': admin_p})

def _check_eligibility(election, user):
  # prevent password-users from signing up willy-nilly for other elections, doesn't make sense
  if user.user_type == 'password':
    return False

  return election.user_eligible_p(user)

def _register_voter(election, user):
  if not _check_eligibility(election, user):
    return None

  return Voter.register_user_in_election(user, election)

@election_view()
def one_election_register(request, election):
  if not election.openreg:
    return HttpResponseForbidden('registration is closed for this election')

  check_csrf(request)

  user = get_user(request)
  voter = Voter.get_by_election_and_user(election, user)

  if not voter:
    voter = _register_voter(election, user)
    
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))

@election_admin(frozen=False)
def one_election_save_questions(request, election):
  check_csrf(request)
  
  questions = utils.from_json(request.POST['questions_json'])
  questions_saved = election.save_questions_safely(questions)
  
  if questions_saved:
    election.save()
    return SUCCESS
  else:
    return FAILURE

@transaction.atomic
@election_admin(frozen=False)
def one_election_freeze(request, election):
  # figure out the number of questions and trustees
  issues = election.issues_before_freeze

  if request.method == "GET":
    return render_template(request, 'election_freeze', {'election': election, 'issues' : issues, 'issues_p' : len(issues) > 0})
  else:
    check_csrf(request)

    election.freeze()

    if get_user(request):
      return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
    else:
      return SUCCESS

def _check_election_tally_type(election):
  return election.workflow_type in ["homomorphic", "mixnet"]

@election_admin(frozen=True)
def one_election_close_poll(request, election):
  if not _check_election_tally_type(election):
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.election_id]))
  
  if request.method == "GET":
    return render_template(request, 'election_close_poll', {'election': election})
  
  check_csrf(request)
  
  if not election.voting_ended_at:
    election.voting_ended_at = datetime.datetime.utcnow()
    election.save()
  
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.uuid]))

@election_admin(frozen=True)
def one_election_compute_tally(request, election):
  """
  tallying is done all at a time now
  """
  if not _check_election_tally_type(election):
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.election_id]))

  if request.method == "GET":
    return render_template(request, 'election_compute_tally', {'election': election})

  check_csrf(request)

  if not election.voting_ended_at:
    election.voting_ended_at = datetime.datetime.utcnow()

  election.tallying_started_at = datetime.datetime.utcnow()
  election.save()

  tasks.election_compute_tally.delay(election_id = election.id)

  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.uuid]))

@trustee_check
def trustee_decrypt_and_prove(request, election, trustee):
  if not _check_election_tally_type(election) or election.encrypted_tally == None:
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.uuid]))
    
  return render_template(request, 'trustee_decrypt_and_prove', {'election': election, 'trustee': trustee})

@election_view(frozen=True)
def trustee_upload_decryption(request, election, trustee_uuid):
  if not _check_election_tally_type(election) or not election.tallied:
    return FAILURE

  trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)

  factors_and_proofs = utils.from_json(request.POST['factors_and_proofs'])

  # verify the decryption factors
  trustee.decryption_factors = [[datatypes.LDObject.fromDict(factor, type_hint='core/BigInteger').wrapped_obj for factor in one_q_factors] for one_q_factors in factors_and_proofs['decryption_factors']]

  # each proof needs to be deserialized
  trustee.decryption_proofs = [[datatypes.LDObject.fromDict(proof, type_hint='legacy/EGZKProof').wrapped_obj for proof in one_q_proofs] for one_q_proofs in factors_and_proofs['decryption_proofs']]

  if trustee.verify_decryption_proofs():
    trustee.save()

    try:
      # send a note to admin
      election.admin.send_message("%s - trustee partial decryption" % election.name, "trustee %s (%s) did their partial decryption." % (trustee.name, trustee.email))
    except:
      # ah well
      pass

    return SUCCESS
  else:
    return FAILURE

@election_admin(frozen=True)
def release_result(request, election):
  """
  result is computed and now it's time to release the result
  """
  election_url = get_election_url(election)

  if request.method == "POST":
    check_csrf(request)

    election.release_result()
    election.save()

    return HttpResponseRedirect("%s" % (settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid])))

  # if just viewing the form or the form is not valid
  return render_template(request, 'release_result', {'election': election})

@election_admin(frozen=True)
def combine_decryptions(request, election):
  """
  combine trustee decryptions
  """

  election_url = get_election_url(election)

  if request.method == "POST":
    check_csrf(request)

    election.combine_decryptions()
    election.save()

    return HttpResponseRedirect("%s" % (settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid])))

  # if just viewing the form or the form is not valid
  return render_template(request, 'combine_decryptions', {'election': election})

@election_admin(frozen=True)
def one_election_set_result_and_proof(request, election):
  if election.encrypted_tally == None:
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.election_id]))

  # FIXME: check csrf
  election.result = utils.from_json(request.POST['result'])
  election.result_proof = utils.from_json(request.POST['result_proof'])
  election.save()

  if get_user(request):
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
  else:
    return SUCCESS


@election_view()
def voters_list_pretty(request, election):
  """
  Show the list of voters
  now using Django pagination
  """

  # for django pagination support
  page = int(request.GET.get('page', 1))
  limit = int(request.GET.get('limit', 50))
  q = request.GET.get('q','')

  order_by = 'user__user_id'

  # unless it's by alias, in which case we better go by UUID
  if election.use_voter_aliases:
    order_by = 'alias'

  user = get_user(request)
  admin_p = security.user_can_admin_election(user, election)

  categories = None
  eligibility_category_id = None

  try:
    if admin_p and can_list_categories(user.user_type):
      categories = AUTH_SYSTEMS[user.user_type].list_categories(user)
      eligibility_category_id = election.eligibility_category_id(user.user_type)
  except AuthenticationExpired:
    return user_reauth(request, user)

  # files being processed
  voter_files = election.voterfile_set.all()

  # load a bunch of voters
  # voters = Voter.get_by_election(election, order_by=order_by)
  voters = Voter.objects.filter(election = election).order_by(order_by).defer('vote')

  if q != '':
    if election.use_voter_aliases:
      voters = voters.filter(alias__icontains = q)
    else:
      voters = voters.filter(voter_name__icontains = q)

  voter_paginator = Paginator(voters, limit)
  voters_page = voter_paginator.page(page)

  total_voters = voter_paginator.count

  return render_template(request, 'voters_list',
                         {'election': election, 'voters_page': voters_page,
                          'voters': voters_page.object_list, 'admin_p': admin_p,
                          'email_voters': helios.VOTERS_EMAIL,
                          'limit': limit, 'total_voters': total_voters,
                          'upload_p': helios.VOTERS_UPLOAD, 'q' : q,
                          'voter_files': voter_files,
                          'categories': categories,
                          'eligibility_category_id' : eligibility_category_id})

@election_admin()
def voters_eligibility(request, election):
  """
  set eligibility for voters
  """
  user = get_user(request)

  if request.method == "GET":
    # this shouldn't happen, only POSTs
    return HttpResponseRedirect("/")

  # for now, private elections cannot change eligibility
  if election.private_p:
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(voters_list_pretty, args=[election.uuid]))

  # eligibility
  eligibility = request.POST['eligibility']

  if eligibility in ['openreg', 'limitedreg']:
    election.openreg= True

  if eligibility == 'closedreg':
    election.openreg= False

  if eligibility == 'limitedreg':
    # now process the constraint
    category_id = request.POST['category_id']

    constraint = AUTH_SYSTEMS[user.user_type].generate_constraint(category_id, user)
    election.eligibility = [{'auth_system': user.user_type, 'constraint': [constraint]}]
  else:
    election.eligibility = None

  election.save()
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(voters_list_pretty, args=[election.uuid]))
  
@election_admin()
def voters_upload(request, election):
  """
  Upload a CSV of password-based voters with
  voter_id, email, name

  name and email are needed only if voter_type is static
  """

  ## TRYING this: allowing voters upload by admin when election is frozen
  #if election.frozen_at and not election.openreg:
  #  raise PermissionDenied()

  if request.method == "GET":
    return render_template(request, 'voters_upload', {'election': election, 'error': request.GET.get('e',None)})

  if request.method == "POST":
    if bool(request.POST.get('confirm_p', 0)):
      # launch the background task to parse that file
      tasks.voter_file_process.delay(voter_file_id = request.session['voter_file_id'])
      del request.session['voter_file_id']

      return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(voters_list_pretty, args=[election.uuid]))
    else:
      # we need to confirm
      if request.FILES.has_key('voters_file'):
        voters_file = request.FILES['voters_file']
        voter_file_obj = election.add_voters_file(voters_file)

        request.session['voter_file_id'] = voter_file_obj.id

        problems = []

        # import the first few lines to check
        try:
          voters = [v for v in voter_file_obj.itervoters()][:5]
        except:
          voters = []
          problems.append("your CSV file could not be processed. Please check that it is a proper CSV file.")

        # check if voter emails look like emails
        if False in [validate_email(v['email']) for v in voters]:
          problems.append("those don't look like correct email addresses. Are you sure you uploaded a file with email address as second field?")

        return render_template(request, 'voters_upload_confirm', {'election': election, 'voters': voters, 'problems': problems})
      else:
        return HttpResponseRedirect("%s?%s" % (settings.SECURE_URL_HOST + reverse(voters_upload, args=[election.uuid]), urllib.urlencode({'e':'no voter file specified, try again'})))

@election_admin()
def voters_upload_cancel(request, election):
  """
  cancel upload of CSV file
  """
  voter_file_id = request.session.get('voter_file_id', None)
  if voter_file_id:
    vf = VoterFile.objects.get(id = voter_file_id)
    vf.delete()
  del request.session['voter_file_id']

  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))

@election_admin(frozen=True)
def voters_email(request, election):
  if not helios.VOTERS_EMAIL:
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
  TEMPLATES = [
    ('vote', 'Time to Vote'),
    ('simple', 'Simple'),
    ('info', 'Additional Info'),
    ('result', 'Election Result')
    ]

  template = request.REQUEST.get('template', 'vote')
  if not template in [t[0] for t in TEMPLATES]:
    raise Exception("bad template")

  voter_id = request.REQUEST.get('voter_id', None)

  if voter_id:
    voter = Voter.get_by_election_and_voter_id(election, voter_id)
  else:
    voter = None

  election_url = get_election_url(election)
  election_vote_url = get_election_govote_url(election)

  default_subject = render_template_raw(None, 'email/%s_subject.txt' % template, {
      'custom_subject': "&lt;SUBJECT&gt;"
})
  default_body = render_template_raw(None, 'email/%s_body.txt' % template, {
      'election' : election,
      'election_url' : election_url,
      'election_vote_url' : election_vote_url,
      'custom_subject' : default_subject,
      'custom_message': '&lt;BODY&gt;',
      'voter': {'vote_hash' : '<SMART_TRACKER>',
                'name': '<VOTER_NAME>',
                'voter_login_id': '<VOTER_LOGIN_ID>',
                'voter_password': '<VOTER_PASSWORD>',
                'voter_type' : election.voter_set.all()[0].voter_type,
                'election' : election}
      })

  if request.method == "GET":
    email_form = forms.EmailVotersForm()
    if voter:
      email_form.fields['send_to'].widget = email_form.fields['send_to'].hidden_widget()
  else:
    email_form = forms.EmailVotersForm(request.POST)

    if email_form.is_valid():

      # the client knows to submit only once with a specific voter_id
      subject_template = 'email/%s_subject.txt' % template
      body_template = 'email/%s_body.txt' % template

      extra_vars = {
        'custom_subject' : email_form.cleaned_data['subject'],
        'custom_message' : email_form.cleaned_data['body'],
        'election_vote_url' : election_vote_url,
        'election_url' : election_url,
        'election' : election
        }

      voter_constraints_include = None
      voter_constraints_exclude = None

      if voter:
        tasks.single_voter_email.delay(voter_uuid = voter.uuid, subject_template = subject_template, body_template = body_template, extra_vars = extra_vars)
      else:
        # exclude those who have not voted
        if email_form.cleaned_data['send_to'] == 'voted':
          voter_constraints_exclude = {'vote_hash' : None}

        # include only those who have not voted
        if email_form.cleaned_data['send_to'] == 'not-voted':
          voter_constraints_include = {'vote_hash': None}

        tasks.voters_email.delay(election_id = election.id, subject_template = subject_template, body_template = body_template, extra_vars = extra_vars, voter_constraints_include = voter_constraints_include, voter_constraints_exclude = voter_constraints_exclude)

      # this batch process is all async, so we can return a nice note
      return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view, args=[election.uuid]))
    
  return render_template(request, "voters_email", {
      'email_form': email_form, 'election': election,
      'voter': voter,
      'default_subject': default_subject,
      'default_body' : default_body,
      'template' : template,
      'templates' : TEMPLATES})

# Individual Voters
@election_view()
@return_json
def voter_list(request, election):
  # normalize limit
  limit = int(request.GET.get('limit', 500))
  if limit > 500: limit = 500

  voters = Voter.get_by_election(election, order_by='uuid', after=request.GET.get('after',None), limit= limit)
  return [v.ld_object.toDict() for v in voters]

@election_view()
@return_json
def one_voter(request, election, voter_uuid):
  """
  View a single voter's info as JSON.
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  if not voter:
    raise Http404
  return voter.toJSONDict()

@election_view()
@return_json
def voter_votes(request, election, voter_uuid):
  """
  all cast votes by a voter
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  votes = CastVote.get_by_voter(voter)
  return [v.toJSONDict()  for v in votes]

@election_view()
@return_json
def voter_last_vote(request, election, voter_uuid):
  """
  all cast votes by a voter
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  return voter.last_cast_vote().toJSONDict()

##
## cast ballots
##

@election_view()
@return_json
def ballot_list(request, election):
  """
  this will order the ballots in voter order.
  and optionally take a after parameter.
  """
  limit = after = None
  if request.GET.has_key('limit'):
    limit = int(request.GET['limit'])
  if request.GET.has_key('after'):
    after = datetime.datetime.strptime(request.GET['after'], '%Y-%m-%d %H:%M:%S')

  voters = Voter.get_by_election(election, cast=True, limit=limit, after=after)

  # we explicitly cast this to a short cast vote
  return [v.last_cast_vote().ld_object.short.toDict(complete=True) for v in voters]

##
## mixnets & proofs
##
@election_view()
def list_mixnets_view(request, election):
  mixnets = election.mixnets.filter()
  user = get_user(request)
  admin_p = security.user_can_admin_election(user, election)

  return render_template(request, 'list_mixnets', {'election': election, 'mixnets': mixnets, 'admin_p': admin_p})

@election_admin(frozen=False)
def new_mixnet(request, election):
  if request.method == "GET":
    return render_template(request, 'new_mixnet', {'election' : election})
  else:
    check_csrf(request)
    params = {'election': election, 'mix_order': election.mixnets.count(),
              'name': request.POST['name'],
              'email': request.POST['email'],
              'mixnet_type': request.POST['mixnet_type'],
              'remote_protocol': request.POST['remote_protocol']}
    
    mixnet = ElectionMixnet(**params)
    mixnet.save()
    
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_mixnets_view, args=[election.uuid]))

@election_admin(frozen=False)
def new_mixnet_helios(request, election):
  election.generate_helios_mixnet()
  
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_mixnets_view, args=[election.uuid]))

@election_admin(frozen=False)
def delete_mixnet(request, election):
  pass

@election_admin(frozen=False)
def delete_mixnet(request, election):
  mixnet = election.mixnets.filter()[int(request.GET['index'])]
  mixnet.delete()
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_mixnets_view, args=[election.uuid]))

@election_admin()
def mixnet_send_url(request, election, mixnet_index):
  mixnet = election.mixnets.filter()[int(mixnet_index)]

  url = settings.SECURE_URL_HOST + reverse(mixnet_login, args=[election.short_name, mixnet_index, mixnet.secret])

  body = """

You are a mixnet for %s.

Your mixnet dashboard is at

  %s

--
Helios
""" % (election.name, url)

  helios_utils.send_email(settings.SERVER_EMAIL, ["%s <%s>" % (mixnet.name, mixnet.email)], 'your mixnet homepage for %s' % election.name, body)

  logging.info("URL %s " % url)
  return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(list_mixnets_view, args = [election.uuid]))

def mixnet_login(request, election_short_name, mixnet_index, mixnet_secret):
  election = Election.get_by_short_name(election_short_name)
  if election:
    mixnets = election.mixnets.filter()

    if mixnets.count() > int(mixnet_index):
      mixnet = mixnets[int(mixnet_index)]
      
      if mixnet.secret == mixnet_secret:
        set_logged_in_mixnet(request, election, mixnet_index)
        
        return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(mixnet_home, args=[election.uuid, mixnet_index]))
      else:
        # bad secret, we'll let that redirect to the front page
        pass
    else:
      # no such mixnet
      raise Http404

  return HttpResponseRedirect(settings.SECURE_URL_HOST + "/")


@mixnet_check
def mixnet_home(request, election, mixnet_index):
  mixnet = election.mixnets.filter()[int(mixnet_index)]
  return render_template(request, 'mixnet_home', {'election': election, 'mixnet_index': mixnet_index, 'mixnet': mixnet})

@mixnet_check
def mixnet_shuffle_and_prove(request, election, mixnet_index):
  mixnet = election.mixnets.filter()[int(mixnet_index)]
  if election.get_next_mixnet() != mixnet:
    return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(one_election_view,args=[election.uuid]))
  
  # :/
  pk = {'p': election.public_key.p, 'q': election.public_key.q, 'g': election.public_key.g, 'y': election.public_key.y}
  origDict = {'public_key': pk, 'answers': []}
  for answer in mixnet.get_original_answers():
    origDict['answers'].append(answer.toJSONDict())
  orig = json.dumps(origDict)
  
  return render_template(request, 'mixnet_shuffle_and_prove', {'election': election, 'mixnet_index': mixnet_index, 'mixnet': mixnet, 'orig': orig})

@transaction.atomic
@mixnet_check
def mixnet_upload_shuffle(request, election, mixnet_index):
  if 'shuffle_file' not in request.FILES or 'proof_file' not in request.FILES:
    return HttpResponseBadRequest(request.FILES)
  
  mixnet = election.mixnets.filter()[int(mixnet_index)]
  
  import phoebus.phoebus
  pk, nbits = phoebus.phoebus.mixnet_pk(election.public_key)
  
  from phoebus.mixnet.Ciphertext import Ciphertext
  from phoebus.mixnet.CiphertextCollection import CiphertextCollection
  from phoebus.mixnet.ShufflingProof import ShufflingProof
  
  # Read the uploaded shuffle and proof
  shuf = CiphertextCollection.from_dict(json.load(request.FILES['shuffle_file']), pk, nbits)
  proof = ShufflingProof.from_dict(json.load(request.FILES['proof_file']), pk, nbits)
  
  # Convert the ballots to ciphertexts
  orig = CiphertextCollection(pk)
  for ballot in mixnet.get_original_answers():
    ciphertext = Ciphertext(nbits, orig._pk_fingerprint)
    ciphertext.append(long(ballot.choice.alpha), long(ballot.choice.beta))
    orig.add_ciphertext(ciphertext)
  
  # Verify the proof
  if not proof.verify(orig, shuf):
    return HttpResponse(content="FAILURE")
  
  # Convert the mixnet results
  # TODO: Clean this the hell up
  new_answers = helios.workflows.mixnet.MixedAnswers([], question_num=0)
  for index, ct in enumerate(shuf):
    cipher = helios.crypto.elgamal.Ciphertext(alpha=ct.gamma[0], beta=ct.delta[0])
    new_answers.answers.append(helios.workflows.mixnet.MixedAnswer(choice=cipher, index=index))
  mixed_votes = helios.models.MixedAnswers(mixnet=mixnet)
  mixed_votes.mixed_answers = new_answers.ld_object
  mixed_votes.shuffling_proof = json_module.dumps(proof.to_dict())
  mixed_votes.save()
  
  mixnet.mixing_finished_at = datetime.datetime.now()
  mixnet.status = 'finished'
  mixnet.save()
  
  return HttpResponse(content="OK!")


@election_view()
@return_json
def mixnets_num(request, election):
  return election.mixnets.filter().count()

@election_view()
@return_json
def mixnets_answers(request, election, mixnet_index):
  mixnet = election.mixnets.filter()[int(mixnet_index)]
  answers = []
  for mixed_answer in mixnet.mixed_answers.filter():
    answers.append(mixed_answer.mixed_answers.toJSONDict())
  return answers

@election_view()
@return_json
def mixnets_proof(request, election, mixnet_index):
  mixnet = election.mixnets.filter()[int(mixnet_index)]
  proofs = []
  for mixed_answer in mixnet.mixed_answers.filter():
    proofs.append(json.loads(mixed_answer.shuffling_proof))
  return proofs


def debugger(request):
  import pdb
  pdb.set_trace()
