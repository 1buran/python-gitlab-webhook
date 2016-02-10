## Example of GitLab Webhook receiver

The goal is to automate this routine: receive web hook request from GtLab, run project tests,
respond with comment of status (make a comment to discussion) and closing merge requests if tests failed.

Features:
-------------

On receive webhook from GitLab you can:

- validate messages of merge request commits
- run test commands

Installation:
-------------

__Requirements__:

- python 3.x (tested on 3.4)
- [falcon](http://falconframework.org/)
- [pyyaml](http://pyyaml.org/)
- [requests](http://docs.python-requests.org/en/master/)

__Setup virtual enviroment__:

```shell
$ sudo apt-get install python python3-dev python-virtualenv git
$ virtualenv ~/py3
$ . ~/py3/bin/activate
$ pip install -U setuptools pip
$ pip install -U cython
$ pip install -U falcon
$ pip install -U pyyaml requests
```

After setup virtual environment and install all requrements,
you should copy **config.yml.example** to **config.yml** and fill the settings!
The configuration file is well documented, I hope you will not have problems with setup!

__Run webhook receiver__:

You can place it behind Nginx/Apache or not - as you want,
but I would recommended set up https server and make the proxying requests from web server to it.

For example, simple Nginx configuration as frontend:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    access_log  /var/log/nginx/example_com_access.log;
    error_log   /var/log/nginx/example_com_error.log;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_trusted_certificate /path/to/fullchain.pem;

    client_max_body_size 2m;

    location / {
        proxy_redirect     off;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_pass http://localhost:5555;  # default listen address and port in config.yml
    }
}
```

and run the backend:

```shell
$ . ~/py3/bin/activate
$ python api.py
```

__Register in GitLab__

Login into your GitLab installation(or http://gitlab.com if you use it), does not matter.

Please go to the "Project Settings -> Web Hooks" and add new web hook which
will be point to your example.com, it will look like:

```
https://example.com/gitlab/webhook/?token=IifwRv0R0j7P25X0tXZzSUPaElintL2doDcZRVo2nd2DiFP5GRj7d4
```

For each projects, merge request of which you will receive,
you should add ssh key of user("Project Settings -> Deploy Keys") which runs the backend script.
This is needed for possibility apply merge requests changes on locally cloned copy of your repo and run test commands.

That's all, now you can play with it =)

If something does not work, please check logs!


__Developer/Sysadmin:__

2016, Andrew Burdyug


