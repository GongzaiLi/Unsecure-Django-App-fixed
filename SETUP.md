# Started process

## Step 1:

#### SSH

```bash
git clone git@eng-git.canterbury.ac.nz:gli65/seng406-assignment-2.git
```

#### HTTP

```bash
git clone https://eng-git.canterbury.ac.nz/gli65/seng406-assignment-2.git
```

## Step 2:

```bash
python3 -m venv .venv-seng406_asg2_group9_src
. .venv-seng406_asg2_group9_src/bin/activate
pip3 install -r requirements.txt
python3 manage.py migrate
```

## Step 3:

### Run Server:

```bash
python3 manage.py runserver
```

### Run SMTP Server:

```bash
cd seng406_asg2_group9_src
. .venv-seng406_asg2_group9_src/bin/activate
python3 -m aiosmtpd -n -l localhost:8025
```

### Remove Debug:

```bash
python manage.py collectstatic
```

```python
# "urls.py"

from  django.conf.urls import url
from  django.views.static import serve
from  django.conf import settings

urlpatterns = [
    # ...
    url(r'^media/(?P<path>.*)$', serve,{'document_root': settings.MEDIA_ROOT}),
]
```

