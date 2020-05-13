# shibboleth-idp-testbed

Fully working Shibboleth IDP and SP written in Python.

Project consists of the following modules:

- [ldap](./ldap) is a Dockerized version of [389 Directory Server](https://directory.fedoraproject.org/) based on [389ds](https://github.com/michel4j/389ds) GitHub project.
- [shibboleth-idp](./shibboleth-idp) is a Dockerized version of Shibboleth IdP based on [shibboleth-idp-dockerized](https://github.com/Unicon/shibboleth-idp-dockerized) and [dockerized-idp-testbed](https://github.com/UniconLabs/dockerized-idp-testbed) GitHub projects.
- [flask-sp](./flask-sp) is a Dockerized Python SP based on [OneLogin's python-saml library](https://github.com/onelogin/python-saml) and [lyrasis-saml-test](https://github.com/kristojorg/lyrasis-saml-test) GitHub projects.

## Usage

To run this project locally please do the following:

1. Add a new record idptestbed.com to `/etc/hosts`

```
127.0.0.1     idptestbed.com
```

It's required because Python SP assumes that Shibboleth IdP is accessible on `idptestbed.com`.

2. Run services using Docker Compose:

```
docker-compose up -d
```

3. After the services are up you can access http://localhost:8000 and test the authentication process using two users:

- login: `student1`, password: `password`
- login: `staff1`, password: `password`
