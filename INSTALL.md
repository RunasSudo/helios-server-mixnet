# Installation
* Install PostgreSQL 8.3+.
* Make sure you have virtualenv installed: http://www.virtualenv.org/en/latest/
* Download helios-server.
* cd into the helios-server directory.
* Create a virtualenv:
```
virtualenv venv
```
* Activate the virtual environment:
```
source venv/bin/activate
```
* Install the requirements:
```
pip install -r requirements.txt
```
* Reset the database:
```
./reset.sh
```

# Usage
* Ensure the virtual environment is activated, as above.
* Start the server:
```
python manage.py runserver
```
* Also start celeryd:
```
python manage.py celeryd -E -B --beat --concurrency=1
```
* The `run.sh` script will execute these automatically, and also launch a dummy SMTP server on port 2525 to log errors.

# Authentication methods

## Google auth
* Go to https://console.developers.google.com.
* Create an application.
* Set up oauth2 credentials as a web application, with your origin, e.g. https://myhelios.example.com, and your auth callback, which, based on our example, is https://myhelios.example.com/auth/after/.
* Still in the developer console, enable the Google+ API.
* Set the GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET configuration variables accordingly, and enable Google auth in AUTH_ENABLED_AUTH_SYSTEMS.

## Reddit auth
* Go to https://www.reddit.com/prefs/apps.
* Create an application.
* Set up oauth2 credentials as a web application, with your origin, e.g. https://myhelios.example.com, and your auth callback, which, based on our example, is https://myhelios.example.com/auth/after/.
* Set the REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET configuration variables accordingly, and enable Reddit auth in AUTH_ENABLED_AUTH_SYSTEMS.

## Password auth
* Enable password auth in AUTH_ENABLED_AUTH_SYSTEMS.
* Execute the following, or insert into reset.sh before resetting the database:
```
echo "from helios_auth.models import User; User.objects.create(user_type='password',user_id='YOUR_USERNAME_HERE', info={'name':'YOUR_NAME_HERE','password':'YOUR_PLAINTEXT_PASSWORD_HERE'})" | python manage.py shell
```
