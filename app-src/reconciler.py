#!/usr/bin/env python

import base64
import itertools
import json
import logging
import os
import string
import sys
from collections import defaultdict
from random import SystemRandom as Random
from time import sleep
from uuid import uuid4

import bcrypt
import openshift as oc
import psycopg2
import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from quay import *

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logging.info("starting up")


def initialize_superuser(config):
    random = Random()

    DATABASE_SECRET_KEY = config.get("DATABASE_SECRET_KEY").encode("utf8")
    DB_URI = config.get("DB_URI")

    def convert_secret_key(secret_key):
        return b"".join(
            itertools.islice(itertools.cycle([bytes([b]) for b in secret_key]), 32)
        )

    def _encrypt_ccm(secret_key, value):
        aesccm = AESCCM(secret_key)
        nonce = os.urandom(13)
        ct = aesccm.encrypt(nonce, value.encode("utf-8"), None)
        encrypted = base64.b64encode(nonce + ct).decode("utf-8")
        return encrypted

    try:
        conn = psycopg2.connect(DB_URI)
    except Exception as dberr:
        logging.error(f"unable to connect to Database {dberr}")
        return False

    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO public.user "
            + "(uuid, username, email, verified, organization, robot, invoice_email, enabled, last_invalid_login) "
            + f"VALUES ('{str(uuid4())}', 'automation', '{str(uuid4())}', 'f', 't', 'f', 'f', 't', '1970-01-01 00:00:00.000');"
        )
        conn.commit()
    except Exception as dberr:
        logging.error(dberr)
        return False

    try:
        secsecret = "".join(
            [random.choice(string.ascii_uppercase + string.digits) for _ in range(40)]
        )
        esecsecret = (
            f"v0$${_encrypt_ccm(convert_secret_key(DATABASE_SECRET_KEY), secsecret)}"
        )
        cur.execute(
            "INSERT INTO public.oauthapplication "
            + "(client_id, redirect_uri, application_uri, organization_id, name, description, gravatar_email, secure_client_secret, fully_migrated) "
            + f"VALUES (1, '', '', 1, 'automation', '', '', '{esecsecret}', 't');"
        )
        conn.commit()
    except Exception as dberr:
        logging.error(dberr)
        return False

    try:
        token = "".join(
            [random.choice(string.ascii_uppercase + string.digits) for _ in range(40)]
        )
        etoken = bcrypt.hashpw(token[20:].encode("utf-8"), bcrypt.gensalt())
        ntoken = token[:20]
        cur.execute(
            "INSERT INTO public.oauthaccesstoken "
            + "(uuid, application_id, authorized_user_id, scope, token_type, expires_at, data, token_code, token_name) "
            + f"VALUES ('{str(uuid4())}', 1, 1, 'super:user org:admin user:admin user:read repo:create repo:admin repo:write repo:read', "
            + f"'Bearer', '2387-12-15 00:00:00.0', '', '{etoken.decode('utf8')}', '{ntoken}');"
        )
        conn.commit()
    except Exception as dberr:
        logging.error(dberr)
        return False

    try:
        store = getCryptStore(config)
        state = oc.apply(
            {
                "apiVersion": "v1",
                "data": {
                    "superusertoken": base64.b64encode(
                        store.encrypt(token.encode("utf8"))
                    ).decode("utf8")
                },
                "kind": "Secret",
                "metadata": {
                    "annotations": {"quay-automation": "v1"},
                    "name": "superusertoken",
                },
                "type": "Opaque",
            }
        )
    except Exception as ocerr:
        logging.error(ocerr)
        logging.error(f"Token will get lost if not capture from this line {token}")

    return token


def fetch_quay_config():
    try:
        configbundles = list(
            filter(
                lambda x: all(
                    [
                        x.model.metadata.get("annotations", {}).get(
                            "quay-registry-hostname", False
                        ),
                        x.model.get("data", {}).get("config.yaml", False),
                    ]
                ),
                oc.selector("secrets").objects(),
            )
        )
        current = sorted(
            configbundles,
            key=lambda x: x.model.metadata.creationTimestamp,
            reverse=True,
        )[0]
        config = yaml.safe_load(base64.b64decode(current.model.data.get("config.yaml")))
        api = current.model.metadata.annotations.get("quay-registry-hostname")
        logging.debug(f"Using API {api}")
        return (api, config)
    except Exception as ocerr:
        logging.error(f"cannot fetch config.yaml from API {ocerr}")
        return (None, {})


def fetch_quay_configurations():
    try:
        configmaps = list(
            filter(
                lambda x: all(
                    [
                        x.model.metadata.get("annotations", {}).get(
                            "quay-automation", False
                        ),
                        x.model.get("data", {}).get("config.json", False),
                    ]
                ),
                oc.selector("configMaps").objects(),
            )
        )
        for config in configmaps:
            try:
                yield json.loads(config.model.data.get("config.json"))
            except Exception as cfgerr:
                logging.error(f"cannot use config {config.name()} json error {cfgerr}")
    except Exception as ocerr:
        logging.error(f"cannot fetch configMaps from API {ocerr}")
        raise StopIteration()


def fetch_quay_token(config):
    try:
        store = getCryptStore(config)
        token = list(
            filter(
                lambda x: all(
                    [
                        x.model.metadata.get("annotations", {}).get(
                            "quay-automation", False
                        ),
                        x.model.get("data", {}).get("superusertoken", False),
                    ]
                ),
                oc.selector("secrets").objects(),
            )
        )[0]
        return store.decrypt(base64.b64decode(token.model.data.superusertoken)).decode(
            "utf8"
        )
    except Exception as ocerr:
        logging.error(f"cannot fetch token from API {ocerr}")
        return False


class CredentialStore(object):
    def __init__(self, config):
        self.config = config
        self.users = defaultdict(dict)
        self._uup = False
        self.robots = defaultdict(dict)
        self._rup = False

    @property
    def fetch_generated_creds(self):
        try:
            robots = oc.selector("configmap/generatedrobots").objects()[0].model
            self.robots = dict(robots.data)
            for k in self.robots:
                rdata = eval(self.robots[k].replace("\n", ","))
                if isinstance(rdata, tuple):
                    rdata = rdata[0]
                self.robots[k] = rdata
        except:
            self.robots = {}
        try:
            users = oc.selector("configmap/generatedusers").objects()[0].model
            self.users = dict(users.data)
            for k in self.users:
                rdata = eval(self.users[k].replace("\n", ","))
                if isinstance(rdata, tuple):
                    rdata = rdata[0]
                self.users[k] = rdata
        except:
            self.users = {}

    def robot_ee(self, organization={}, name={}, data=None):
        if self.robots.get(organization, {}) == {}:
            self.robots[organization] = {name: self.__ee__(data)}
        else:
            self.robots[organization][name] = self.__ee__(data)
        self._rup = True

    def user_ee(self, organization=None, name=None, data=None):
        if self.users.get(organization, {}) == {}:
            self.users[organization] = {name: self.__ee__(data)}
        else:
            self.users[organization][name] = self.__ee__(data)
        self._uup = True

    def __ee__(self, data):
        try:
            store = getCryptStore(self.config)
            return store.encrypt(data.encode("utf8")).decode("utf8")
        except Exception as eee:
            logging.error(f"cannot encode and encrypt data {data}")
            return ""

    def apply(self, who=None, oc=None):
        if oc == None:
            raise ValueError("cannot apply without oc")
        if who == "users":
            if self._uup:
                return oc.apply(self.users_to_dict)
        elif who == "robots":
            if self._rup:
                return oc.apply(self.robots_to_dict)
        return False

    @property
    def users_to_dict(self):
        if self._uup:
            data = self.__secret__("generatedusers")
            for org in self.users:
                rdata = []
                for u in self.users[org]:
                    rdata.append(
                        str({u: json.dumps(self.robots[org][u])}).replace('"', "")
                    )
                data["data"][org] = "\n".join(rdata)
            return data
        return ""

    @property
    def robots_to_dict(self):
        if self._rup:
            data = self.__secret__("generatedrobots")
            for org in self.robots:
                rdata = []
                for r in self.robots[org]:
                    rdata.append(
                        str({r: json.dumps(self.robots[org][r])}).replace('"', "")
                    )
                data["data"][org] = "\n".join(rdata)
            return data
        return ""

    def __secret__(self, name=None):
        return {
            "apiVersion": "v1",
            "data": {},
            "kind": "ConfigMap",
            "metadata": {
                "annotations": {"quay-automation-generated": "v1"},
                "name": name,
            },
        }


def reconcile_loop():
    while True:
        try:
            api, config = fetch_quay_config()
            registry = Registry(
                url=f"{config.get('PREFERRED_URL_SCHEME')}://{api}/api/v1/",
                ca=bool(int(os.environ.get("VERIFY_TLS", True))),
            )
            if not registry.health:
                raise AttributeError()
            token = fetch_quay_token(config)
            if token is False:
                token = initialize_superuser(config)
                if token is False:
                    logging.error(f"cannot retrieve superusertoken from API")
                    raise AttributeError("cannot retrieve superusertoken from API")
            registry.token = token
            logging.info(
                f"repositories: {' '.join(list(map(lambda x: x.name, registry.repositories)))}"
            )
            logging.info(
                f"organisation: {' '.join(list(map(lambda x: x.name, registry.organizations)))}"
            )
            credstore = CredentialStore(config)
            credstore.fetch_generated_creds

            for quaycfg in fetch_quay_configurations():
                for org in quaycfg.get("organizations", []):
                    o = Organization(name=org.get("name"), registry=registry)
                    logging.error(
                        f"organization check -{o.name}- -{registry.get(organization=o.name)}-"
                    )
                    if registry.get(organization=o.name) is None:
                        if not org.get("proxycache", None) is None:
                            logging.info(f"setting proxycache for {o.name}")
                            o._proxycache = ProxyCacheConfig(
                                from_json=org.get("proxycache"), parent=o
                            )
                        for permission in org.get("default_permissions", []):
                            logging.info(f"setting default permission for {o.name}")
                            o._default_permissions.append(DefaultPermissionConfig(from_json=permission, parent=o))

                        logging.info(f"creating Organization {o.name}")
                        o.addtoregistry
                        registry.add_orga(o)
                    for robot in org.get("robots", []):
                        ro = Robot(from_json=robot, parent=o)
                        oo = registry.get(organization=o.name)
                        if not oo == None:
                            roo = oo.get(robot=ro.name)
                            if roo == None:
                                logging.info(f"creating Robot {ro.name}")
                                credstore.robot_ee(
                                    o.name, ro.name, ro.addtoregistry.get("token")
                                )
                                oo.robots.append(ro)
                        else:
                            logging.info(f"creating Robot {ro.name}")
                            credstore.robot_ee(
                                o.name, ro.name, ro.addtoregistry.get("token")
                            )
                            oo.robots.append(ro)
                    for repo in org.get("repositories", []):
                        if repo.get("mirror", False):
                            repostate = "MIRROR"
                        else:
                            repostate = "NORMAL"
                        r = Repository(
                            namespace=o.name,
                            name=repo.get("name"),
                            is_public=repo.get("is_public"),
                            state=repostate,
                            registry=registry,
                        )
                        if repostate == "MIRROR":
                            r._json["mirror"] = repo.get("mirror")
                        if registry.get(repository=r.path) == None:
                            logging.info(f"creating Repository {r.path}")
                            r.addtoregistry
                            registry.add_repo(r)
                    for team in org.get("teams", []):
                        t = OrganizationTeam(from_json=team, organization=o)
                        oo = registry.get(organization=o.name)
                        if not oo == None:
                            roo = oo.get(team=t.name)
                            if roo == None:
                                logging.info(f"createing Team {t.name}")
                                t.addtoregistry
                                oo.teams.append(t)
                        else:
                            logging.info(f"createing Team {t.name}")
                            t.addtoregistry
                            oo.teams.append(t)
                    if org.get("owners", []) != []:
                        t = OrganizationTeam(
                            from_json={"name": "owners"},
                            role="Admin",
                            members=[],
                            organization=o,
                        )
                        for m in org.get("owners"):
                            oo = registry.get(organization=o.name)
                            try:
                                if oo.get(team=t.name).has_member(m):
                                    pass
                                else:
                                    t.members.add(m)
                            except AttributeError:
                                # we do not have teams with `owners` only
                                t.members.add(m)
                        if len(t) > 0:
                            t.updatemembers
                try:
                    credstore.apply("users", oc)
                except Exception as serr:
                    logging.error(f"cannot store generated users {serr}")
                try:
                    credstore.apply("robots", oc)
                except Exception as serr:
                    logging.error(f"cannot store generated robots {serr}")

            sleep(60)

        except AttributeError as err:
            logging.info(f"deployment not ready")
            logging.debug(f"exception {err}")
            sleep(60)
        except Exception as err:
            logging.error(f"unhandled exception {err}")
            break


if __name__ == "__main__":
    oc.context.default_token = open(
        "/run/secrets/kubernetes.io/serviceaccount/token"
    ).read()
    oc.set_default_project = open(
        "/run/secrets/kubernetes.io/serviceaccount/namespace"
    ).read()
    oc.set_default_api_server("https://kubernetes.default.svc.cluster.local:443")
    oc.context.default_skip_tls_verify = True
    try:
        reconcile_loop()
    except KeyboardInterrupt:
        logging.info("exiting on request")
