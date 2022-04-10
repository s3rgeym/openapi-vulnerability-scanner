import cgi
import copy
import functools
import urllib.parse as urlparse
from logging import getLogger
from typing import Any, Optional

import requests
import yaml

from . import __package_name__
from .constants import USER_AGENT

logger = getLogger(__package_name__)


class Loader:
    YAML_MIMES: list[str] = [
        'text/vnd.yaml',
        'application/yaml',
        'application/x-yaml',
        'text/x-yaml',
    ]

    YAML_EXTS: tuple[str, ...] = ('.yml', '.yaml')

    def __init__(self, session: Optional[requests.Session] = None):
        self._session = session or self._create_session()
        self._cache = {}

    def _create_session(self) -> requests.Session:
        session = requests.session()
        session.headers.update({'User-Agent': USER_AGENT})
        return session

    def load(self, schema_url: str) -> dict[str, Any]:
        if schema_url not in self._cache:
            r = self._session.get(schema_url)
            ct, _ = cgi.parse_header(r.headers.get('content-type', ''))
            if ct in self.YAML_MIMES or schema_url.endswith(self.YAML_EXTS):
                schema = yaml.safe_load(r.text)
            else:
                schema = r.json()
            self._cache[schema_url] = schema
        return self._cache[schema_url]


class Dereferencer:
    def __init__(self, schema_url: str, loader: None | Loader = None):
        self._schema_url = schema_url
        self._loader = loader or Loader()

    # Эти методы должны принадлежать парсеру, но парсер мы выбираем исходя из структуры
    # документа

    def dereference(self) -> dict[str, Any]:
        return self._dereference(self._loader.load(self._schema_url))

    # Допустим, что $ref может быть в любом месте
    def _dereference(self, o: Any, backrefs: list[str] = []) -> Any:
        if isinstance(o, dict):
            rv = {}
            for k, v in o.items():
                if k == '$ref':
                    # Из-за наличия рекупсивных ссылок у пшеков, я думал, что я как-то
                    # направильно организовал обход, пришлось дебажить. Kurwa!!!111
                    if v in backrefs:
                        logger.debug('backrefs=%r', backrefs)
                        raise ValueError('Circular reference detected: %r', v)
                    backrefs.append(v)
                    rv.update(
                        self._dereference(self.resolve_reference(v), backrefs)
                    )
                    assert backrefs.pop() == v
                    # Все после $ref должно игнорироваться
                    break
                rv[k] = self._dereference(v, backrefs)
            return rv
        if isinstance(o, list):
            return [self._dereference(x, backrefs) for x in o]
        assert isinstance(o, (int, float, str, bool))
        return o

    def resolve_reference(self, ref: str) -> Any:
        url, path = ref.split('#', 2)
        # У локальных ссылок path = ''
        schema = self._loader.load(urlparse.urljoin(self._schema_url, url))
        rv = schema
        for key in path.split('/')[1:]:
            key = key.replace('~1', '/').replace('~0', '~')
            rv = rv[key]
        return rv


def dereference(schema_url: str) -> dict[str, Any]:
    return Dereferencer(schema_url=schema_url).dereference()


class BaseApi:
    pass


class SwaggerApi(BaseApi):
    ALLOWED_METHODS: set[str] = {
        'get',
        'head',
        'post',
        'put',
        'patch',
        'delete',
        'options',
        'trace',
    }

    def __init__(
        self,
        schema: dict[str, Any],
        schema_url: str,
    ):
        self._schema = schema
        self._schema_url = schema_url

    def get_server_urls(self) -> list[str]:
        base_path = self._schema.get('basePath', '/')
        if host := self._schema.get('host'):
            return [
                self.normalize_url(f'{scheme}://{host}{base_path}')
                for scheme in self._schema['schemes']
            ]
        return [self.normalize_url(base_path)]

    def normalize_url(self, url: str) -> str:
        return urlparse.urljoin(self._schema_url, url).rstrip('/')

    def get_paths(self) -> list[str]:
        return list(self._schema['paths'].keys())

    def get_operations(self, path: str) -> list[str]:
        return list(
            set(self._schema['paths'][path].keys()) & self.ALLOWED_METHODS
        )

    def get_parameters(self, path: str, operation: str) -> list[dict[str, Any]]:
        assert operation in self.ALLOWED_METHODS
        path_object = self._schema['paths'][path]
        defaults = path_object.get('parameters', {})
        path_item = path_object[operation]
        params = path_item.get('parameters', {})
        params = self._override_parameters(defaults, params)
        return copy.deepcopy(params)

    def filter_parameters(
        self, path: str, operation: str, location: str
    ) -> list[dict[str, Any]]:
        return list(
            filter(
                lambda x: x['in'] == location,
                self.get_parameters(path, operation),
            )
        )

    get_path_parameters = functools.partialmethod(
        filter_parameters, location='path'
    )
    get_query_parameters = functools.partialmethod(
        filter_parameters, location='query'
    )
    get_header_parameters = functools.partialmethod(
        filter_parameters, location='header'
    )
    get_body_parameters = functools.partialmethod(
        filter_parameters, location='body'
    )
    get_formdata_parameters = functools.partialmethod(
        filter_parameters, location='formData'
    )

    def has_payload(self, path: str, operation: str) -> bool:
        parameters = self.get_parameters(path, operation)
        return any(lambda x: x['in'] in ('body', 'formData'), parameters)

    def has_formdata(self, path: str, operation: str) -> bool:
        parameters = self.get_parameters(path, operation)
        return any(lambda x: x['in'] == 'formData', parameters)

    def get_payload_mimes(self, path: str, operation: str) -> list[str]:
        # Принимаемые типы можно объявить в корне и переопределить в Operation
        consumes = self._schema.get('consumes', [])
        # копируем объекты во избежание их модификации
        return list(
            self._schema['paths'][path][operation].get('consumes', consumes)
        )

    def _override_parameters(
        self, defaults: list[dict[str, Any]], overrides: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        make_key = lambda x: (x['name'], x['in'])
        tmp: list[tuple[str, str], Any] = {make_key(v): v for v in defaults}
        for v in overrides:
            tmp[make_key(v)] = v
        return list(tmp.values())


# https://api.data.amsterdam.nl/signals/swagger/openapi.yaml
class OpenApi(SwaggerApi):
    def get_server_urls(self) -> list[str]:
        servers = self._schema.get('servers', [])
        # Правильно ли?
        urls = [x['url'] for x in servers] if servers else ['/']
        return list(map(self.normalize_url, urls))

    get_cookie_parameters = functools.partialmethod(
        SwaggerApi.filter_parameters, location='cookie'
    )

    def get_request_body(
        self, path: str, operation: str, mime: None | str = None
    ) -> list[dict[str, Any]] | dict[str, Any] | None:
        rv = self._schema['paths'][path][operation].get('requestBody', {})
        if mime:
            rv = rv.get('content', {}).get(mime)
        return copy.deepcopy(rv)

    def get_payload_mimes(self, path: str, operation: str) -> list[str]:
        return list(
            self.get_request_body(path, operation).get('content', {}).keys()
        )

    def has_payload(self, path: str, operation: str) -> bool:
        return len(self.get_payload_mimes(path, operation)) > 0


# Примеры ссылок на спецификацию:
# - https://app.andfrankly.com/api/data/swagger.yml (2)
# - https://railgun.spatialcurrent.io/swagger.yml (2)
# - https://navigationservice.e-spirit.cloud/docs/api/swagger-files/swagger.yml (3)
# - https://api.weather.gov/openapi.json (3)
# - https://www.skylinesoft.com/KB_Resources/PM/WebHelp/API/openapi.json (3)
# - https://coda.io/apis/v1/openapi.json (3)
# - https://georg.nrm.se/api/swagger.json (2)
# - https://michael1011.at/git/michael1011/market-maker-bot/src/branch/feat/reserved-balance/src/proto/xudrpc.swagger.json (2)
def resolve(schema_url: str) -> BaseApi:
    schema = dereference(schema_url)
    if 'swagger' in schema:
        return SwaggerApi(schema=schema, schema_url=schema_url)
    if 'openapi' in schema:
        return OpenApi(schema=schema, schema_url=schema_url)
    raise ValueError()
