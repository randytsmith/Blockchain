# ScalaMed Auth

Authentication Service for the ScalaMed Project.

## Running

```bash
# Install virtualenv and python3.X -- This is platform dependent.
$ ...

# Clone this repository
$ git clone git@bitbucket.org:GyrixSigma/auth.git scalamed-auth
$ cd scalamed-auth

# Set up virtualenv with python3, and activate
$ virtualenv --python=python3 venv
$ source venv/bin/activate

# Install dependencies
$ pip install -r requirements.txt

# Enter project
$ cd scalamed

# Migrate database and run
$ ./manage makemigrations
$ ./manage migrate
$ ./manage runserver

# Test the server
$ curl -v localhost:8000/auth/users
```

We will use docker in the near future to wrap this service. If it's too much
trouble install the above, we can get a dockerfile completed ASAP.

## API

This is the current state of the API.

| End Point                | Request Type | Parameters                               | Return                                    | Description                                        |
|:-------------------------|:------------:|:-----------------------------------------|:------------------------------------------|:---------------------------------------------------|
| /auth/login              |    `POST`    | ``{ email, password }``                  | ``{ token_level0, token_level1, uuid }``  | Login request - returns tokens                     |
| /auth/register           |     `PUT`    | ``{ email, password }``                  | ``{ email }``                             | Registration for a user to Auth service            |
| /auth/forgotpw           |    `POST`    | ``{ email } ``                           | ``{ token }``                             | Forgot password                                    |
| /auth/resetpw            |    `POST`    | ``{ email, token } ``                    | ``{ success }``                           | Reset password                                     |
| /auth/check              |    `POST`    | ``{ uuid, token_level0, token_level1 }`` | ``{ success, token_level1 }``             | Check if token is valid                            |
| /auth/check/prescription |    `POST`    | ``{ uuid, token_level0, token_level1 }`` | ``{ success, token_level1 }``             | Checks if the UUID is valid to sign a prescription |
| /auth/check/fulfil       |    `POST`    | ``{ uuid, token_level0, token_level1 }`` | ``{ success, token_level1 }``             | Checks if the UUID is valid to fulfil              |
| /auth/getsecret          |    `POST`    | ``{ uuid, token_level0, token_level1 }`` | ``{ token_level1, secret }``              | Get the secret for the row encryption              |

