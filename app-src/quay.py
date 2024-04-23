#!/usr/bin/python3 -W ignore

import base64
import hashlib
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, wait
from copy import deepcopy
from datetime import datetime
from typing import List, Set
from uuid import uuid4

import requests
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from urllib3.util import parse_url

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
MAXTHREADS = int(os.environ.get("MAXTHREAD", 3))


def to_fkey(key):
    IKEYH = hashlib.md5(key)
    return base64.urlsafe_b64encode(IKEYH.hexdigest().encode())


def getCryptStore(config):
    if not isinstance(config.get("DATABASE_SECRET_KEY"), list):
        keys = list(config.get("DATABASE_SECRET_KEY"))
    else:
        keys = config.get("DATABASE_SECRET_KEY")
    CurrentStore = MultiFernet(
        list(map(lambda x: Fernet(x), map(lambda y: to_fkey(y.encode("utf8")), keys)))
    )
    return CurrentStore


class Registry(object):
    def __init__(self, url=None, token=None, ca=None):
        self.url = url
        self.token = token
        self.ca = ca
        self.orgas = set([])
        self.repos = set([])

    @property
    def hostname(self):
        return

    def __get_header__(self):
        return {"Authorization": f"Bearer {self.token}"}

    def __get(self, path=None):
        try:
            rsp = requests.get(
                f"{self.url}{path}",
                headers=self.__get_header__(),
                verify=self.ca,
                timeout=10,
            )
            if all([rsp.status_code >= 200, rsp.status_code < 300]):
                logging.debug(f"response for {self.url}{path} {rsp.status_code}")
            elif all([rsp.status_code >= 400, rsp.status_code < 500]):
                try:
                    return rsp.json()
                except:
                    return dict(
                        detail="Not Found",
                        error_message="Not Found",
                        error_type="not_found",
                        status=404,
                    )
            logging.debug(f"{rsp.status_code} {rsp.reason}")
        except Exception as apierr:
            logging.error(f"API error {apierr}")
            return dict()
        return rsp.json()

    def __post(self, path=None, data=None):
        try:
            rsp = requests.post(
                f"{self.url}{path}",
                json=data,
                headers=self.__get_header__(),
                verify=self.ca,
            )
            if all([rsp.status_code >= 200, rsp.status_code < 300]):
                logging.debug(f"response for {self.url}{path} {rsp.status_code}")
                if rsp.status_code == 204:
                    return {}
            elif all([rsp.status_code >= 400, rsp.status_code < 500]):
                try:
                    return rsp.json()
                except:
                    return dict(
                        detail="Not Found",
                        error_message="Not Found",
                        error_type="not_found",
                        status=404,
                    )
            elif rsp.status_code >= 500:
                logging.debug(f"API error {rsp}")
                logging.debug(f"API error {rsp.text}")
                return
            logging.debug(f"{rsp.status_code} {rsp.reason}")
        except Exception as apierr:
            logging.error(f"API error {apierr}")
            return dict()
        return rsp.json()

    def __put(self, path=None, data=None):
        try:
            rsp = requests.put(
                f"{self.url}{path}",
                json=data,
                headers=self.__get_header__(),
                verify=self.ca,
            )
            if all([rsp.status_code >= 200, rsp.status_code < 300]):
                logging.debug(f"response for {self.url}{path} {rsp.status_code}")
            elif all([rsp.status_code >= 400, rsp.status_code < 500]):
                try:
                    return rsp.json()
                except:
                    return dict(
                        detail="Not Found",
                        error_message="Not Found",
                        error_type="not_found",
                        status=404,
                    )
            elif rsp.status_code >= 500:
                logging.debug(f"API error {rsp}")
                logging.debug(f"API error {rsp.text}")
                return
            logging.debug(f"{rsp.status_code} {rsp.reason}")
        except Exception as apierr:
            logging.error(f"API error {apierr}")
            return dict()
        return rsp.json()

    def __delete(self, path=None, data=None):
        try:
            rsp = requests.delete(
                f"{self.url}{path}",
                json=data,
                headers=self.__get_header__(),
                verify=self.ca,
            )
            if all([rsp.status_code >= 200, rsp.status_code < 300]):
                if rsp.status_code == 204:
                    return dict(status=200)
                logging.debug(f"response for {self.url}{path} {rsp.status_code}")
            elif all([rsp.status_code >= 400, rsp.status_code < 500]):
                try:
                    return rsp.json()
                except:
                    return dict(
                        detail="Not Found",
                        error_message="Not Found",
                        error_type="not_found",
                        status=404,
                    )
            elif rsp.status_code >= 500:
                logging.debug(f"API error {rsp}")
                logging.debug(f"API error {rsp.text}")
                return
            logging.debug(f"{rsp.status_code} {rsp.reason}")
        except Exception as apierr:
            logging.error(f"API error {apierr}")
            return dict()
        return rsp.json()

    def __get_tags(self, repo):
        try:
            rsp = self.__get(path=f"repository/{repo.path}?includeTags=True")
            # repo.tags = list(map(lambda y: Tag(from_json=dict(y[1].items())), filter(lambda x: x[1].get('name') == 'latest', rsp.get('tags').items())))
            repo.tags = list(
                map(
                    lambda y: Tag(parent=repo, from_json=dict(y[1].items())),
                    rsp.get("tags").items(),
                )
            )
        except Exception as terr:
            logging.error(f"Generic gettags fetch error {terr}")
            logging.error(f"repository/{repo.path}?includeTags=True")
            logging.error(f"rsp = {rsp}")

    def __get_proxycacheconfig(self, orga):
        try:
            rsp = self.__get(path=f"organization/{orga.name}/proxycache")
            cache = ProxyCacheConfig(rsp)
            if cache.registry != "":
                orga._proxycache = cache
                orga._proxycache.parent = orga
        except Exception as terr:
            logging.error(f"Generic gettags fetch error {terr}")

    def __get_robots(self, user):
        try:
            rsp = self.__get(
                path=f"organization/{user.name}/robots?token=true&permissions=true"
            )
            logging.debug(f"Robots: {rsp}")
            user._robots = list(map(lambda x: Robot(from_json=x), rsp.get("robots")))
            user.parent = user
        except Exception as e:
            logging.error(f"Generic getrobot fetch error {e}")
            return False
        return True

    def __get_teams(self, orga):
        try:
            for team in orga._json.get("ordered_teams", []):
                rsp = self.__get(path=f"organization/{orga.name}/team/{team}/members")
                logging.debug(f"Team: {rsp}")
                if orga.get(team=rsp.get("name")) == None:
                    orga._teams.append(
                        OrganizationTeam(from_json=rsp, organization=orga)
                    )
                else:
                    for m in rsp.get("members"):
                        t = orga.get(team=rsp.get("name"))
                        t.members.add(m.get("name"))
        except Exception as e:
            logging.error(f"Generic getteam fetch error {e}")
            return False
        return True

    def __get_notifications(self, repo):
        try:
            rsp = self.__get(path=f"repository/{repo.path}/notification/")
            repo.notifications = list(
                map(
                    lambda y: Notification(parent=repo, from_json=dict(y[1].items())),
                    rsp.get("notification").items(),
                )
            )
        except Exception as terr:
            logging.error(f"Generic gettags fetch error {terr}")
            logging.error(f"repository/{repo.path}?includeTags=True")
            logging.error(f"rsp = {rsp}")

    def add_repo(self, repository, api=False):
        if all(
                [not isinstance(repository, Repository), not isinstance(repository, dict)]
        ):
            raise ValueError(
                f"need instance Repository or instance dict to add to Registry"
            )
        if isinstance(repository, dict):
            repository = Repository(from_json=repository)
        if repository.registry != None:
            # copy to be able to act on it
            repository = deepcopy(repository)
            repository.registry = self
        if api:
            repository.addtoregistry
        self.repos.add(repository)
        return repository

    def add_orga(self, organization, api=False):
        if all(
                [
                    not isinstance(organization, Organization),
                    not isinstance(organization, dict),
                ]
        ):
            raise ValueError(
                f"need instance Organization or instance dict to add to Registry"
            )
        if isinstance(organization, dict):
            organization = Organization(from_json=organization)
        if organization.registry != None:
            # copy to be able to act on it
            organization = deepcopy(organization)
            organization.registry = self
        if api:
            organization.addtoregistry
        self.orgas.add(organization)
        return organization

    def takeownership(self, organization):
        if all(
                [
                    not isinstance(organization, Organization),
                    not isinstance(organization, dict),
                ]
        ):
            raise ValueError(
                f"need instance Organization or instance dict to add to Registry"
            )
        if isinstance(organization, dict):
            organization = Organization(from_json=organization)
        rsp = self.__post(path=f"superuser/takeownership/{organization.name}")
        logging.debug(f"API takeownership organization {rsp}")
        return organization

    @property
    def repositories(self):
        if self.repos == set([]):
            try:
                logging.debug(f"requesting repositories for {self.url}")
                page = ""
                with ThreadPoolExecutor(max_workers=MAXTHREADS) as tpe:
                    while page != None:
                        if page != "":
                            page = f"&next_page={page}"
                        rsp = self.__get(path=f"repository?public=true{page}")
                        logging.debug(f"rsp {rsp}")
                        for repo in rsp.get("repositories", []):
                            repo = self.add_repo(
                                Repository(from_json=repo, registry=self)
                            )
                            tpe.submit(self.__get_tags, repo)
                        page = rsp.get("next_page")
            except Exception as e:
                logging.error(f"Generic repolist fetch error {e}")
                return []
        logging.debug(f"found {len(self.repos)}")
        return self.repos

    @property
    def organizations(self):
        if self.orgas == set([]):
            try:
                logging.debug(f"requesting organizations for {self.url}")
                with ThreadPoolExecutor(max_workers=MAXTHREADS) as tpe:
                    threads = []
                    for orga in set(
                            map(
                                lambda x: x.get("name"),
                                self._Registry__get(path=f"superuser/organizations/").get(
                                    "organizations"
                                ),
                            )
                    ):
                        threads.append(tpe.submit(self.__get, f"organization/{orga}"))
                    wait(threads)
                    for rsp in map(lambda x: x.result(), threads):
                        if rsp.get("status", 200) == 404:
                            continue
                        else:
                            orga = self.add_orga(
                                Organization(from_json=rsp, registry=self)
                            )
                            tpe.submit(self.__get_proxycacheconfig, orga)
                            tpe.submit(self.__get_robots, orga)
                            tpe.submit(self.__get_teams, orga)
            except Exception as e:
                logging.error(f"Generic orgalist fetch error {e}")
                return []
        logging.debug(f"found {len(self.orgas)}")
        return self.orgas

    def get(self, organization=None, repository=None):
        if repository != None:
            try:
                return list(
                    filter(
                        lambda x: any(
                            [
                                x.fullpath == repository,
                                x.path == repository,
                                x.name == repository,
                            ]
                        ),
                        self.repositories,
                    )
                )[0]
            except IndexError:
                return None
        elif organization != None:
            try:
                return list(
                    filter(lambda x: x.name == organization, self.organizations)
                )[0]
            except IndexError:
                return None

    def __iter__(self):
        for repo in list(self.repos):
            yield repo

    @property
    def health(self):
        try:
            rsp = requests.get(
                self.url.replace("/api/v1/", "/health"), verify=self.ca, timeout=10
            )
            if rsp.status_code == 200:
                return True
            else:
                return False
        except Exception as healtherr:
            logging.error(f"Health check Exception {healtherr}")
        return False


class Repository(object):
    def __init__(
            self,
            namespace=None,
            name=None,
            is_public=False,
            kind="image",
            state="NORMAL",
            quota_report=dict(quota_bytes=0, configured_quota=None),
            is_starred=False,
            from_json=None,
            registry=None,
    ):
        self.registry = registry
        self.tags = []
        self.notifications = []
        self._json = dict(
            namespace=namespace,
            name=name,
            is_public=is_public,
            kind=kind,
            state=state,
            quota_report=quota_report,
            is_starred=is_starred,
            description=None,
        )
        if from_json != None:
            self.__from_json__(from_json)

    @property
    def fetch(self):
        rsp = self.registry._Registry__post(path=f"repository/{self.path}")
        logging.debug(f"API fetching repository {rsp}")
        if rsp.status_code == 200:
            self.__from_json__(rsp.json())
        else:
            logging.error(f"cannot fetch repository {rsp.status} {rsp.reason}")
            return

    @property
    def namespace(self):
        return self._json.get("namespace")

    @property
    def name(self):
        return self._json.get("name")

    @property
    def is_public(self):
        return bool(self._json.get("is_public"))

    @property
    def path(self):
        return f"{self.namespace}/{self.name}"

    @property
    def fullpath(self):
        return f"{parse_url(self.registry.url).host}/{self.path}"

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    def __exists__(self):
        rsp = self.registry._Registry__get(path=f"repository/{self.path}")
        if rsp == {}:
            return False
        elif rsp.get("status", 404) >= 400:
            return False
        return True

    @property
    def addtoregistry(self):
        if self.__exists__():
            return
        rsp = self.registry._Registry__post(path="repository", data=self.to_dict)
        logging.debug(f"API create repository {rsp}")
        if not self._json.get("mirror", False) == False:
            self.setup_mirror

    def set_state(self, state="NORMAL"):
        if state.upper() not in ("NORMAL", "MIRROR", "READ_ONLY"):
            return False
        rsp = self.registry._Registry__put(
            path=f"repository/{self.path}/changestate", data={"state": state.upper()}
        )
        logging.debug(f"API change state {rsp}")

    @property
    def setup_mirror(self):
        if not self._json.get("mirror", False) == False:
            self.set_state(state="MIRROR")
            logging.debug(f"API create mirrorconfig")
            mc = MirrorConfig(from_json=self._json.get("mirror"), parent=self)
            mc.addtoregistry

    @property
    def delfromregistry(self):
        rsp = self.registry._Registry__delete(path=f"repository/{self.path}")
        logging.debug(f"API delete repository {rsp}")

    def visibility(self, visibility):
        if all([visibility == "public", self.is_public]):
            return True
        elif all([visibility == "private", not self.is_public]):
            return True
        rsp = self.registry._Registry__post(
            path=f"repository/{self.path}/changevisibility",
            data=dict(visibility=visibility),
        )
        return rsp

    def copy_from(self, other):
        if not isinstance(other, Repository):
            raise ValueError(f"need instance Repository to copy from {other}")
        return f"skopeo copy docker://{other.fullpath} docker://{self.fullpath}"

    @property
    def to_dict(self):
        # modify for API
        data = deepcopy(self._json)
        if data["description"] == None:
            data["description"] = ""
        if data["is_public"]:
            data["visibility"] = "public"
        else:
            data["visibility"] = "private"
        data["repository"] = data["name"]
        for k in ("is_public", "name", "quota_report"):
            try:
                del data[k]
            except:
                pass
        return data

    def __cmp__(self, other):
        if isinstance(other, Repository):
            return f"{self.path}" == f"{other.path}"
        return False


class Tag(object):
    def __init__(
            self,
            name=None,
            size=0,
            last_modified=None,
            manifest_digest=None,
            from_json=None,
            parent=None,
    ):
        self._json = dict(
            name=name,
            size=size,
            last_modified=last_modified,
            manifest_digest=manifest_digest,
        )
        self.parent = parent
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def name(self):
        return self._json.get("name")

    @property
    def digest(self):
        return self._json.get("manifest_digest")

    @property
    def manifest_digest(self):
        return self.digest

    @property
    def delfromregistry(self):
        rsp = self.registry._Registry__delete(
            path=f"repository/{self.path}/tag/{self.name}"
        )
        logging.debug(f"API delete tag {rsp}")

    def __cmp__(self, other):
        if isinstance(other, Tag):
            return self.digest == other.digest
        return False

    def __repr__(self):
        return f"{self.name} ({self.digest[:15]})"

    @property
    def to_dict(self):
        return self._json


class Organization(object):
    def __init__(self, name=None, from_json=None, registry=None):
        self._json = dict(name=name)
        self.registry = registry
        self._proxycache = None
        self._default_permissions: Set[DefaultPermissionConfig] = set()
        self._robots = []
        self._teams = []
        self._owners = []
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            if key == "teams":
                for t in value:
                    self._teams.append(
                        OrganizationTeam(from_json={"name": t}, organization=self)
                    )
                continue
            self._json[key] = value

    @property
    def name(self):
        return self._json.get("name")

    @property
    def email(self):
        return self._json.get("email", f"{str(uuid4())}")

    @property
    def is_proxy(self):
        if all(
                [self._proxycache != None, isinstance(self._proxycache, ProxyCacheConfig)]
        ):
            return True
        return False

    @property
    def has_default_permissions(self):
        if all(
                [self._default_permissions is not None, len(self._default_permissions) > 0]
        ):
            for permission in self._default_permissions:
                if not isinstance(permission, DefaultPermissionConfig):
                    logging.error("default permission config %s is invalid" % permission)
                    return False
            return True
        return False

    def __exists__(self):
        rsp = self.registry._Registry__get(path=f"organization/{self.name}")
        if rsp == {}:
            return False
        if rsp.get("status", 0) >= 400:
            return False
        return True

    def __exists_proxy__(self):
        rsp = self.registry._Registry__get(path=f"organization/{self.name}/proxycache")
        if rsp == {}:
            return False
        if rsp == {"upstream_registry": "", "expiration_s": "", "insecure": ""}:
            return False
        elif rsp.get("status", 404) >= 400:
            return False
        return True

    def __get_missing_default_permissions(self):
        rsp = self.registry._Registry__get(path=f"organization/{self.name}/prototypes")
        missing_permissions = []
        for wanted_permission in self._default_permissions:
            for existing_permission in rsp['prototypes']:
                if wanted_permission.delegate_name == existing_permission["delegate"]["name"] and \
                        wanted_permission.delegate_kind == existing_permission["delegate"]["kind"] and \
                        wanted_permission.role == existing_permission["role"]:
                    break
            missing_permissions.append(wanted_permission)
        return missing_permissions

    @property
    def addtoregistry(self):
        if self.__exists__():
            return
        rsp = self.registry._Registry__post(path="organization/", data=self.to_dict)
        logging.debug(f"API create organization {rsp}")
        if self.is_proxy:
            if self.__exists_proxy__():
                return
            rsp = self.registry._Registry__post(
                path=f"organization/{self.name}/proxycache", data=self.proxy.to_dict
            )
            logging.debug(f"API create proxy cache {rsp}")

    def add_permissions(self):
        if self.has_default_permissions:
            missing_permissions = self.__get_missing_default_permissions()
            if len(missing_permissions) > 0:
                for wanted_permission in missing_permissions:
                    rsp = self.registry._Registry__post(
                        path=f"organization/{self.name}/prototypes", data=wanted_permission.to_dict
                    )
                    logging.debug(
                        f"Default Permission of {wanted_permission.role} for {wanted_permission.delegate_kind} "
                        f"{wanted_permission.delegate_name} created: {rsp}")

    @property
    def proxy(self):
        return self._proxycache

    def get(self, team=None, robot=None, repository=None):
        if repository != None:
            try:
                return list(
                    filter(
                        lambda x: any(
                            [
                                x.fullpath == repository,
                                x.path == repository,
                                x.name == repository,
                            ]
                        ),
                        self.repositories,
                    )
                )[0]
            except IndexError:
                return None
        elif robot != None:
            try:
                return list(
                    filter(
                        lambda x: any(
                            [x.name == robot, x.name == f"{self.name}+{robot}"]
                        ),
                        self.robots,
                    )
                )[0]
            except IndexError:
                return None
        elif team != None:
            try:
                return list(filter(lambda x: x.name == team, self.teams))[0]
            except IndexError:
                return None

    @property
    def robots(self):
        return self._robots

    @property
    def teams(self):
        return self._teams

    @property
    def to_dict(self):
        if self.is_proxy:
            pcache = self._proxycache.to_dict
        else:
            pcache = {}
        return dict(
            name=self.name,
            email=self.email,
            proxycacheconfig=pcache,
        )

    def __cmp__(self, other):
        if isinstance(other, Organization):
            return self.name == other.name
        return self.name == other


class OrganizationTeam(object):
    def __init__(
            self, name=None, role="Member", members=[], from_json=None, organization=None
    ):
        self._json = dict(name=name)
        self.organization = organization
        self.role = role
        self.members = set([])
        for m in members:
            self.members.add(m)
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            if key == "members":
                try:
                    self.members = set(list(map(lambda x: x.get("name"), value)))
                except AttributeError:
                    self.members = value
                continue
            self._json[key] = value

    def __exists__(self):
        rsp = self.organization.registry._Registry__get(
            path=f"organization/{self.organization.name}/team/{self.name}/members"
        )
        if rsp == {}:
            return False
        if all([self._json.get("sync", False), rsp.get("synced", False) != False]):
            return True
        elif self._json.get("sync", False) != False:
            return False
        if all(
                [
                    self.members != [],
                    rsp.get("members", []) == [],
                    rsp.get("status", 0) != 404,
                ]
        ):
            return True
        if rsp.get("status", 0) >= 400:
            return False
        return True

    def sync(self, members=None):
        rsp = self.organization.registry._Registry__post(
            path=f"organization/{self.organization.name}/team/{self.name}/syncing",
            data={"group_dn": members},
        )
        logging.debug(f"API sync Team members {rsp}")

    @property
    def addtoregistry(self):
        if self.__exists__():
            return
        rsp = self.organization.registry._Registry__put(
            path=f"organization/{self.organization.name}/team/{self.name}",
            data=dict(name=self.name, role="member"),
        )
        logging.debug(f"API create Team {rsp}")
        if self._json.get("sync", False) != False:
            self.sync(members=self._json.get("sync"))
        elif len(self.members) > 0:
            self.updatemembers

    @property
    def updatemembers(self):
        if not self.__exists__():
            return
        for member in self.members:
            rsp = self.organization.registry._Registry__put(
                path=f"organization/{self.organization.name}/team/{self.name}/members/{member}",
                data=dict(name=self.name, role="admin"),
            )
        logging.debug(f"API updated Team {rsp}")

    @property
    def name(self):
        return self._json.get("name")

    def has_member(self, name):
        if name in list(self.members):
            return True
        return False

    @property
    def to_dict(self):
        return dict(
            name=self.name,
            role=self.role,
        )

    def __len__(self):
        return len(list(self.members))


class User(object):
    def __init__(self, name=None, from_json=None, registry=None):
        self._json = dict(username=name)
        self._robots = []
        self.registry = registry
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def name(self):
        return self._json.get("username")

    @property
    def robots(self):
        return self._robots

    def __exists__(self):
        rsp = self.registry._Registry__get(path=f"users/{self.name}")
        if rsp == 200:
            return True
        return False

    @property
    def addtoregistry(self):
        if self.__exists__():
            return
        rsp = self.registry._Registry__post(path="superuser/users", data=self.to_dict)
        logging.debug(f"API create user {rsp}")

    @property
    def to_dict(self):
        userdict = self._json
        userdict["robots"] = list(map(lambda x: x.to_dict, self._robots))
        return userdict


class ProxyCacheConfig(object):
    def __init__(self, from_json=None, parent=None):
        self._json = dict()
        self.parent = parent
        self._username = False
        self._password = False
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def registry(self):
        return self._json.get("upstream_registry")

    @property
    def expiration(self):
        return int(self._json.get("expiration_s", 86400))

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def hostname(self):
        return parse_url(self.registry).host

    @property
    def to_dict(self):
        if self.username:
            ret = dict(
                upstream_registry=self.registry,
                upstream_registry_username=self.username,
                upstream_registry_password=self.password,
                expiration_s=self.expiration,
                org_name=self.parent.name,
            )
        else:
            ret = dict(
                upstream_registry=self.registry,
                expiration_s=self.expiration,
                org_name=self.parent.name,
            )
        return ret


class DefaultPermissionConfig(object):
    def __init__(self, from_json, parent):
        self._json = dict()
        self.parent = parent
        self.__from_json__(from_json)

    def __eq__(self, other):
        if isinstance(other, DefaultPermissionConfig):
            return (self.delegate_name == other.delegate_name and self.delegate_kind == other.delegate_kind
                    and self.role == other.role)
        return False

    def __hash__(self):
        # Define a hash value based on the attributes that determine equality
        return hash(f"{self.delegate_kind}-{self.delegate_name}-{self.role}")

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def role(self):
        return self._json.get("role", "read")

    @property
    def delegate_name(self):
        return self._json.get("delegate_name")

    @property
    def delegate_kind(self):
        return self._json.get("delegate_kind")

    @property
    def to_dict(self):
        return {
            "role": self.role,
            "delegate": {
                "name": self.delegate_name,
                "kind": self.delegate_kind
            }
        }


class MirrorConfig(object):
    def __init__(self, from_json=None, parent=None):
        self._json = dict()
        self.parent = parent
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def reference(self):
        return self._json.get("external_reference")

    @property
    def sync_interval(self):
        return int(self._json.get("sync_interval", 86400))

    @property
    def username(self):
        return self._json.get("external_registry_username")

    @property
    def password(self):
        return self._json.get("external_registry_password")

    @property
    def sync_now(self):
        self.parent.registry._Registry__post(
            path=f"repository/{self.parent.path}/mirror/sync-now"
        )

    @property
    def robot(self):
        # if not self._json.get('robot', False):
        #    return f"{self.parent.path.split('/')[0]}+{self.parent.robots[0]}"
        return self._json.get("robot")

    @property
    def root_rule(self):
        return dict(rule_kind="tag_glob_csv", rule_value=self._json.get("tags", ["*"]))

    @property
    def sync_start_date(self):
        if not self._json.get("sync_start_date", False):
            return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            # parse handling ?
            return self._json.get("sync_start_date")

    @property
    def is_enabled(self):
        return bool(self._json.get("is_enabled", True))

    @property
    def reference(self):
        return self._json.get("external_reference")

    @property
    def addtoregistry(self):
        return self.parent.registry._Registry__post(
            path=f"repository/{self.parent.path}/mirror",
            data=dict(
                external_reference=self.reference,
                external_registry_username=self.username,
                external_registry_password=self.password,
                sync_start_date=self.sync_start_date,
                sync_interval=self.sync_interval,
                robot_username=self.robot,
                is_enabled=self.is_enabled,
                root_rule=self.root_rule,
            ),
        )

        # external_registry_config:
        # {verify_tls: true, unsigned_images: true, proxy: {http_proxy: null, https_proxy: null, no_proxy: null}}

    @property
    def to_dict(self):
        if self.robot:
            ret = dict(
                external_reference=self.reference,
                external_registry_username=self.username,
                external_registry_password=self.password,
                sync_start_date=self.sync_start_date,
                sync_interval=self.sync_interval,
                robot_username=self.robot,
                is_enabled=self.is_enabled,
                root_rule=self.root_rule,
                external_registry_config={},
            )
        else:
            ret = {}
        return ret


class Robot(object):
    def __init__(self, name=None, from_json=None, parent=None):
        self._json = dict(name=name)
        self.parent = parent
        if from_json != None:
            self.__from_json__(from_json)

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def name(self):
        return self._json.get("name")

    @property
    def token(self):
        return self._json.get("token")

    @property
    def permissions(self):
        return self._json.get("repositories", [])

    @property
    def description(self):
        return self._json.get("description", "")

    @property
    def to_dict(self):
        return self._json

    def __exists__(self):
        if isinstance(self.parent, Organization):
            rsp = self.parent.registry._Registry__get(
                path=f"organization/{self.parent.name}/robots/{self.name}"
            )
        else:
            rsp = self.parent.registry._Registry__get(path=f"user/robots/{self.name}")
        if rsp == {}:
            return False
        elif rsp.get("status", 404) >= 400:
            return False
        return True

    @property
    def addtoregistry(self):
        if self.__exists__():
            return
        if isinstance(self.parent, Organization):
            rsp = self.parent.registry._Registry__put(
                path=f"organization/{self.parent.name}/robots/{self.name}",
                data=dict(description=self.description),
            )
        else:
            rsp = self.parent.registry._Registry__put(
                path=f"user/robots/{self.name}", data=dict(description=self.description)
            )
        logging.debug(f"API create robot {rsp}")
        return rsp


class NotificationSeverity(object):
    Levels = {
        "Unknown": 5,
        "Negligible": 4,
        "Low": 3,
        "Medium": 2,
        "High": 1,
        "Critical": 0,
    }

    def __init__(self, level="Unknown"):
        if isinstance(level, int):
            self.level = level
        else:
            self.level = self.name_to_level(level)

    def name_to_level(self, name):
        return self.Levels.get(name.capitalize(), False)

    def level_to_name(self, level):
        try:
            return list(filter(lambda x: x[1] == level, self.Levels.items()))[0][0]
        except IndexError:
            return -1

    @property
    def to_dict(self):
        return {"eventConfig": {"level": self.level}}


class Notification(object):
    def __init__(
            self,
            from_json=None,
            parent=None,
            title=None,
            event=None,
            method=None,
            config=dict(),
            event_config=dict(),
    ):
        self._json = dict()
        self.parent = parent
        self.registry = self.parent.registry
        if from_json != None:
            self.__from_json__(from_json)
        else:
            self._json["title"] = title
            self._json["event"] = event
            self._json["method"] = method
            self._json["config"] = config
            self._json["event_config"] = event_config

    def __from_json__(self, from_json):
        for key, value in from_json.items():
            self._json[key] = value

    @property
    def uuid(self):
        return self._json.get("uuid", "")

    @property
    def addtorepository(self):
        rsp = self.registry._Registry__post(
            path=f"repository/{self.parent.path}/notification/", data=self.to_dict
        )
        logging.debug(f"API create repository notification {rsp}")
        return rsp.get("token")

    @property
    def delfromrepository(self):
        rsp = self.registry._Registry__delete(
            path=f"repository/{self.parent.path}/notification/{self.uuid}"
        )
        logging.debug(f"API removed repository notification {rsp}")

    @property
    def to_dict(self):
        return self._json
