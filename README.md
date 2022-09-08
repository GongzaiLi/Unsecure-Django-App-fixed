# SENG406 Unsecure (Django) App

This app has been develop in an unsecure way on purpose for SENG406 students to train themselves at identifying and fixing common vulnerabilities and design issues in software systems. 

Most of the vulnerabilities hidden in the app are instances of [OWASP Top 10 2021](https://owasp.org/Top10/).


## Initial app

This app has been built from the open-source **Django Dashboard** generated by `AppSeed` op top of a modern design. Designed for those who like bold elements and beautiful websites, **[Soft UI Dashboard](https://appseed.us/generator/soft-ui-dashboard/)** is ready to help you create stunning websites and webapps. **Soft UI Dashboard** is built with over 70 frontend individual elements, like buttons, inputs, navbars, nav tabs, cards, or alerts, giving you the freedom of choosing and combining.

<br />

![Soft UI Dashboard - Full-Stack Starter generated by AppSeed.](https://user-images.githubusercontent.com/51070104/175773323-3345d618-0e78-4c85-83fc-f495dc3f0bb0.png)

<br />


## ✨ How to use it

> Download the code 

```bash
$ git clone https://eng-git.canterbury.ac.nz/fgi18/seng402-asg2-22
```

<br />

### 👉 Set Up for `Unix`, `MacOS` and `Windows Linux Subsystem`

> Create a virtual environment

```bash
$ cd seng402-asg2-22
$ virtualenv -p python3 .venv
$ . .venv/bin/activate
$ pip3 install -r requirements.txt
```

<br />

> Set Up Database

```bash
$ python manage.py makemigrations
$ python manage.py migrate
```

<br />

> Run the console SMTP server (mock email)

```bash
$ python -m aiosmtpd -n -l localhost:8025
```

Emails will print to the console instead of being sent out. See bottom of `settings.py` for more details.

<br />



> Start the app

```bash
$ python manage.py runserver
```

At this point, the app runs at `http://127.0.0.1:8000/`. 

<br />