# LinOTP in Docker

## Build Image

From the base directory run the following command
to build the image tagged as `linotp`:

```terminal
$ docker build -f docker_new/Dockerfile -t linotp .
```

## Run LinOTP Container

To run the previously build image as a container named `linotp` run
```terminal
$ docker run -p 5000:5000 --name linotp linotp
```

## Customization

### Translations
Custom translations can be mounted to `/custom-translations/{LANGUAGE_TAG}/LC_MESSAGES/linotp.po`.

### Mako Templates
Any number of custom mako templates can be mounted to `/custom-templates`.
Keep in mind to follow the directory structure of `linotp/templates`.
E.g. your custom `audit.mako` for `/manage` is to be mounted to `/templates/manage/audit.mako` via 
```terminal
$ docker run -p 5000:5000 --name linotp \
    -v ./audit.mako:/custom-assets/manage/audit.mako \
    linotp
```

### Other Files (images,css,js)
To customize other files overwrite them by mounting your custom file onto the original file.

Say, you want to change e.g. the looks of the SelfService:
Mount your `selfservice-style.css` to `/custom-assets/selfservice-style.css` via
```terminal
$ docker run -p 5000:5000 --name linotp \
    -v ./selfservice-style.css:/custom-assets/selfservice-style.css \
    linotp
```

## Persistence
To persist your linotp data (e.g. db, audit keys, logs...) mount a volume to `/linotp_data` via
```terminal
$ docker run -p 5000:5000 --name linotp \
    -v my_persistent_volume:/linotp_data \
    linotp
```