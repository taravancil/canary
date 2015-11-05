# Contributing to Canary

## Setup
Clone the repository: `git clone https://github.com/taravancil/canary`

Navigate to the directory and activate the virtual environment.
    virtualenv venv
    . venv/bin/activate

The python dependencies are listed in `requirements.txt`. You can download them with Pip.

`pip install -r requirements.txt`

### Other Dependencies
Canary also uses[Sass](https://github.com/sass/sass)(LibSass and SassC more specifically) and [JSMin](https://github.com/douglascrockford/JSMin). Run `./manage.sh install_libs` to download the required libraries and build the binaries. The binaries will be in `venv/bin`.

### Configuration
Copy `config-sample.py` to `config.py` and fill in the required values.

#### Configure GPG 
`GPG_PATH` in `config.py` should point to the binary for a working GPG installation on your machine.

#### Set Up Celery
Canary uses Celery to queue and schedule periodic tasks, which also requires a message broker, like RabbitMQ or Redis. You can choose any broker you'd like. See the [Celery documentation](http://docs.celeryproject.org/en/latest/getting-started/brokers/) for information about setting up several different brokers.

Once your broker is running, update `BROKER_URL` in the `Celery` config object to the URL for your local broker set up.

##### Run Celery
To start the worker that handles Celery tasks, run `celery -A canary.tasks worker`. This is necessary for queuing and sending emails. If you don't want to receive emails while developing a feature, simply don't start the worker. Everything else will behave normally, but no emails will be sent.

Periodic tasks are handled by `celery.beat`. It's not necessary to run `celery.beat` for development, but if you want to hack on any of the periodic tasks or see how it works, run `celery -A canary.tasks beat`.

## Build the application
Build the entire application with `./manage.sh build`. This compiles the CSS and minifies the JavaScript.

### Compile CSS
To compile the `.scss` files in `canary/src/scss` run `./manage.sh build_css`. The compiled CSS will be in `canary/static/css`.

SassC does not have a `--watch` option like some other Sass implementations. It would be nice to be able to watch `src/scss` for changes and run `./manage.sh build_css every time there's a change. Contributions welcome :)

### Minify JavaScript
To minify the `.js` files in `src/js` run `./manage.sh minify_js`. The minified files will be in `canary/static/js`.

## Run the Application
You can run the application locally with `./manage.sh run`.

## Testing
Tests are in `canary/test/`. 

Run the entire test suite with `./manage.sh test`. To run the tests for an individual module or subset of modules, run `./manage.sh test module1 module2`.

### Writing Tests
Please run the test suite before submitting any changes to avoid introducing breaking changes. New features should be accompanied by corresponding tests.

If you submit a patch that fixes a bug, it would be very helpful if you also write a test to make sure that the bug is not reintroduced in the future.

#### Testing Email
When running tests, `MAIL_SUPPRESS_SEND` is set to True, so that no emails are actually sent. See [`mail_test.py`](https://github.com/taravancil/canary/blob/master/canary/test/mail_test.py) to see how to test features that involve sending mail.

It is not necessary to start the Celery worker to test email.

#### Testing GPG
The public and private keyrings used to run tests are in `canary/test/homedir`. The keyrings already include the public and private keys required to run the test, but ASCII-armored versions of the keys are also available in `canary/test/files` in case you accidentally delete the keyrings and need to reimport the keys. The passphrase for `test.sec` is `test`.

## Things to Work On
See the list of [TODOS](https://github.com/taravancil/canary/TODOS.md) or the [issue tracker](https://github.com/taravancil/canary/issues).

