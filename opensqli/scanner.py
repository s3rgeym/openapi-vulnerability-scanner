import asyncio
import cgi
import json
import logging
import random
import urllib.parse as urlparse
import uuid
from typing import Any, Awaitable, Callable, Iterable, Optional

import aiohttp
import yaml
from aiohttp.typedefs import LooseHeaders
from aiolimiter import AsyncLimiter
from multidict import CIMultiDict
from packaging import version

from . import __package_name__, __version__
from .utils import random_datetime

logger = logging.getLogger(__package_name__)

# class ApiError(Exception):
#     message: str

#     def __init__(
#         self, response: aiohttp.ClientResponse, message: Optional[str] = None
#     ):
#         Exception.__init__(self, message)
#         self.response = response
#         self.message = self.message or message


# class ResponseError(ApiError):
#     pass


# navigationId:
#   name: navigationId
#   description: The id of the navigation.
#   in: path
#   required: true
#   schema:
#     $ref: '#/components/schemas/NavigationId'

# '#/components/schemas/NavigationId'.split('/')[1:]
# spec['components']['schemas']['NavigationId']

# components:
#   schemas:
#     NavigationId:
#       type: string
#       nullable: false


class OpenApiSqliScanner:
    # trace, options, head не используются на практике
    API_METHODS: list[str] = ['get', 'post', 'put', 'patch', 'delete']
    YAML_MIMES: list[str] = [
        'text/vnd.yaml',
        'application/yaml',
        'application/x-yaml',
        'text/x-yaml',
    ]

    def __init__(
        self,
        session: aiohttp.ClientSession,
        specification_url: str,
        *,
        headers: Optional[LooseHeaders] = None,
        rate_limit: Optional[float] = None,
    ):
        self._session = session
        self._specification_url = specification_url
        self._headers = CIMultiDict(headers or {})
        # self._headers.setdefault(
        #     'User-Agent',
        #     (
        #         f'Mozilla 5.0 ({__package_name__} v{__version__}'
        #         ' +https://github.com/tz4678/openapi-sqli-scanner)'
        #     ),
        # )
        # logger.debug('User-Agent = %r', self._headers['user-agent'])
        self._headers.setdefault(
            'User-Agent',
            'Mozilla/5.0 (X11; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0',
        )
        self._rate_limiter = AsyncLimiter(rate_limit or 100)

    # Примеры ссылок на спецификацию:
    # - https://app.andfrankly.com/api/data/swagger.yml (2)
    # - https://railgun.spatialcurrent.io/swagger.yml (2)
    # - https://navigationservice.e-spirit.cloud/docs/api/swagger-files/swagger.yml (3)
    # - https://api.weather.gov/openapi.json (3)
    # - https://www.skylinesoft.com/KB_Resources/PM/WebHelp/API/openapi.json (3)
    # - https://coda.io/apis/v1/openapi.json (3)
    # - https://georg.nrm.se/api/swagger.json (2)
    @classmethod
    async def run(
        cls,
        specification_url: str,
        *,
        timeout: int | float = 30,
        headers: dict[str, str] = {},
        rate_limit: Optional[float] = None,
    ) -> None:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            instance = cls(
                session,
                specification_url=specification_url,
                headers=headers,
                rate_limit=rate_limit,
            )
            await instance.parse_specification()
            await instance.scan()

    async def parse_specification(
        self,
    ) -> None:
        response = await self._request('GET', self._specification_url)
        # Расширения может и не быть типа <https://guarantee.money/api/test/swagger-json>
        content_type, _ = cgi.parse_header(response.headers['content-type'])
        # aiohttp.client_exceptions.ContentTypeError: 0, message='Attempt to decode JSON with unexpected mimetype: text/plain; charset=utf-8', url=URL('https://app.andfrankly.com/api/data/swagger.yml')
        if content_type in self.YAML_MIMES or self._specification_url.endswith(
            ('.yml', 'yaml')
        ):
            self._specification = yaml.safe_load(await response.text())
        else:
            # assert content_type == 'application/json'
            self._specification = await response.json()
        logger.info('specification parsed')

    async def _request(
        self,
        method: str,
        url: str,
        query: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        headers: Optional[LooseHeaders] = None,
    ) -> aiohttp.ClientResponse:
        method = method.upper()
        req_headers = self._headers.copy()
        req_headers.update(headers or {})
        async with self._rate_limiter:
            response = await self._session.request(
                method,
                url,
                params=self._normalize_query(query),
                json=data,
                headers=req_headers,
            )
            logger.debug('%s %s [%s]', method, response.url, response.status)
            return response

    def _normalize_query(self, query: dict[str, Any]) -> dict[str, Any]:
        # TypeError: Invalid variable type: value should be str, int or float, got True of type <class 'bool'>
        # https://github.com/aio-libs/yarl#why-isnt-boolean-supported-by-the-url-query-api
        # >>> [1, 2][True]
        # 2
        if query is None:
            return
        return {
            # k: ['false', 'true'][v] if isinstance(v, bool) else v
            k: int(v) if isinstance(v, bool) else v
            for k, v in query.items()
        }

    @property
    def api_version(self) -> version.Version:
        if not hasattr(self, '_api_version'):
            v = version.parse(self._specification['info']['version'])
            # Мне вом реализовывать 3-ью версию
            assert version.Version('3.0') > v >= version.Version('2.0')
            self._api_version = v
        return self._api_version

    @property
    def base_url(self) -> str:
        if not hasattr(self, '_base_url'):
            # TODO: В 3 версии нет `host``
            if 'host' in self._specification:
                server_url = (
                    'http'
                    + (
                        's'
                        if 'https' in self._specification.get('schemes', [])
                        else ''
                    )
                    + '://'
                    + self._specification['host']
                )
            else:
                server_url = self._specification_url
            base_path = self._specification.get('basePath', '/')
            self._base_url = urlparse.urljoin(server_url, base_path).rstrip('/')
        return self._base_url

    async def scan(self) -> None:
        logger.info('scanning started')
        await asyncio.gather(*self._generate_requests())
        logger.info('scanning finished')

    def _generate_requests(
        self,
    ) -> Iterable[
        Callable[
            [str, str, dict[str, Any], dict[str, Any], dict[str, Any]],
            Awaitable[None],
        ]
    ]:
        paths = self._specification.get('paths', {})
        logger.debug('paths len: %d', len(paths))
        for path, path_object in paths.items():
            logger.debug('parse %s', path)
            # assert path.startswith('/')
            default_params = path_object.get('parameters', {})
            for method in self.API_METHODS:
                if path_item := path_object.get(method):
                    params = self._override_params(
                        default_params, path_item.get('parameters', {})
                    )
                    params_ = {}
                    headers = {}
                    query = {}
                    data = {}
                    for param in params:
                        assert '$ref' not in param
                        name: str = param['name']
                        value: Any = self._get_param_value(param)
                        match param['in']:
                            case 'path':
                                params_[name] = value
                            case 'header':
                                headers[name] = value
                            case 'query':
                                query[name] = value
                            case 'body' | 'requestBody' | 'formData':
                                data[name] = value
                            case typ:
                                raise ValueError(
                                    f'unexpected param type: {typ}'
                                )

                    # TODO:
                    # ...
                    # "consumes": [
                    #     "application/json",
                    #     "text/json",
                    #     "application/x-www-form-urlencoded"
                    # ],
                    # "produces": [
                    #     "application/json",
                    #     "text/json"
                    # ],
                    # ...
                    # "responses": {
                    #     "200": {
                    #         "description": "OK",
                    #         "schema": {
                    #         "$ref": "#/definitions/ApiResult[RequestInfo]"
                    #         }
                    #     }
                    # }

                    # Проверяем каждый параметр по очереди
                    for k, v in params_.items():
                        params_copy = params_.copy()
                        params_copy[k] = self._add_quotes(v)
                        yield self._handle_request(
                            method, path, params_copy, query, data, headers
                        )
                    for k, v in headers.items():
                        headers_copy = params_.copy()
                        headers_copy[k] = self._add_quotes(v)
                        yield self._handle_request(
                            method, path, params_, query, data, headers_copy
                        )
                    for k, v in query.items():
                        query_copy = query.copy()
                        query_copy[k] = self._add_quotes(v)
                        yield self._handle_request(
                            method, path, params_, query_copy, data, headers
                        )
                    for k, v in data.items():
                        data_copy = data.copy()
                        data_copy[k] = self._add_quotes(v)
                        yield self._handle_request(
                            method, path, params_, query, data_copy, headers
                        )

    def _override_params(
        self, params: list[dict[str, Any]], overrides: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        # A list of parameters that are applicable for all the operations
        # described under this path. These parameters can be overridden at the
        # operation level, but cannot be removed there. The list MUST NOT
        # include duplicated parameters. A unique parameter is defined by a
        # combination of a name and location. The list can use the Reference
        # Object to link to parameters that are defined at the OpenAPI Object's
        # components/parameters.
        make_key = lambda x: (x.get('name'), x.get('in'))
        tmp = {make_key(v): v for v in params}
        for v in overrides:
            tmp[make_key(v)] = v
        return list(tmp.values())

    def _get_param_value(self, param: dict[str, Any]) -> Any:
        # Небольшой задел на будущее: поддержка 3 версии
        schema = param.get('schema', param)
        if 'default' in schema:
            return schema['default']
        if 'enum' in schema:
            return random.choice(schema['enum'])
        # Подставляем значения
        match schema.get('type'):
            case 'integer' | 'number':
                return random.randint(1, 100)
            case 'boolean':
                return bool(random.randbytes(1))
        match schema.get('format'):
            case 'date':
                return str(random_datetime().date())
            case 'date-time':
                return str(random_datetime())
            case 'password':
                return 'T0p$3cR3t'
            case 'email':
                return 'j.doe@example.com'
            case 'uuid':
                return str(uuid.uuid4())
        return random.choice(['foo', 'bar', 'baz', 'quix'])

    def _add_quotes(self, val: Any) -> str:
        return f"{val}'\""

    async def _handle_request(
        self,
        method: str,
        path: str,
        params: dict[str, Any],
        query: dict[str, Any],
        data: dict[str, Any],
        headers: dict[str, Any],
    ) -> None:
        try:
            endpoint_url: str = (
                f'{self.base_url}{self._replace_path_params(path, params)}'
            )
            response = await self._request(
                method, endpoint_url, query, data, headers
            )
            has_error = response.status >= 500
            try:
                parsed = await response.json()
            except:
                # Говно на PHP сгенерирует что-то типа:
                # <br />\n<b>Warning</b>: ...
                # Django же покажет стандартную html страницу, что тоже приведет к
                # ошибке парсинга.
                parsed = None
                has_error = True
            if not has_error:
                return
            print(
                json.dumps(
                    dict(
                        method=method,
                        url=endpoint_url,
                        query=query,
                        data=data,
                        headers=headers,
                        response={
                            'status_code': response.status,
                            'data': parsed,
                        },
                    )
                ),
                flush=True,
            )
        except Exception as ex:
            logger.exception(ex)

    def _replace_path_params(self, path: str, params: dict[str, Any]) -> str:
        for k, v in params.items():
            path = path.replace(f'{{{k}}}', urlparse.quote(str(v)))
        return path
