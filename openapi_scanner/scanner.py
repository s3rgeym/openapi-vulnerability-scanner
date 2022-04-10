import asyncio
import logging
import random
import urllib.parse as urlparse
import uuid
from json import dumps
from typing import Any, Awaitable, Callable, Iterable, Optional

import aiohttp
from aiohttp.typedefs import LooseHeaders
from aiolimiter import AsyncLimiter
from multidict import CIMultiDict

from . import __package_name__, __version__, api
from .constants import USER_AGENT
from .utils import random_datetime

# from copy import deepcopy

logger = logging.getLogger(__package_name__)


class OpenApiVulnScanner:
    def __init__(
        self,
        schema_url: str,
        session: aiohttp.ClientSession,
        *,
        headers: Optional[LooseHeaders] = None,
        rate_limit: Optional[float] = None,
    ):
        self._api = api.resolve(schema_url)
        self._schema_url = schema_url
        self._session = session
        self._headers = CIMultiDict(headers or {})
        self._headers.setdefault(
            'User-Agent',
            USER_AGENT,
        )
        self._rate_limiter = AsyncLimiter(rate_limit or 100)

    @classmethod
    async def run(
        cls,
        schema_url: str,
        *,
        timeout: int | float = 30,
        headers: dict[str, str] = {},
        rate_limit: Optional[float] = None,
    ) -> None:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            await cls(
                schema_url=schema_url,
                session=session,
                headers=headers,
                rate_limit=rate_limit,
            ).scan()

    async def _request(
        self,
        method: str,
        url: str,
        params: Any = None,
        *,
        data: Any = None,
        json: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> aiohttp.ClientResponse:
        method = method.upper()
        req_headers = self._headers.copy()
        req_headers.update(headers or {})
        async with self._rate_limiter:
            response = await self._session.request(
                method,
                url,
                params=self._normalize_query_params(params) if params else None,
                json=json,
                data=data,
                cookies=cookies,
                headers=req_headers,
            )
            logger.debug('%s %s [%s]', method, response.url, response.status)
            return response

    def _normalize_query_params(self, params: dict[str, Any]) -> dict[str, Any]:
        # TypeError: Invalid variable type: value should be str, int or float, got True of type <class 'bool'>
        # https://github.com/aio-libs/yarl#why-isnt-boolean-supported-by-the-url-query-api
        # >>> [1, 2][True]
        # 2
        return {
            # k: ['false', 'true'][v] if isinstance(v, bool) else v
            k: int(v) if isinstance(v, bool) else v
            for k, v in params.items()
        }

    @property
    def server_url(self) -> str:
        return self._api.get_server_urls()[0]

    async def scan(self) -> None:
        logger.info('scanning started')
        await asyncio.gather(*self._generate_tests())
        logger.info('scanning finished')

    def _generate_tests(
        self,
    ) -> Iterable[
        Callable[
            [str, str, dict[str, Any], dict[str, Any], dict[str, Any]],
            Awaitable[None],
        ]
    ]:
        for path in self._api.get_paths():
            for method in self._api.get_operations(path):
                params = self._api.get_path_parameters(path, method)
                query = self._api.get_query_parameters(path, method)
                headers = self._api.get_header_parameters(path, method)

                if isinstance(self._api, api.OpenApi):
                    json = self._api.get_request_body(
                        path, method, 'application/json'
                    )
                else:
                    try:
                        # only one body
                        json = self._api.get_body_parameters(path, method)[0]
                    except IndexError:
                        json = None

                # Проверяем каждый параметр по очереди
                params = self._fuzz_data(params)
                headers = self._fuzz_data(headers)
                query = self._fuzz_data(query)
                json = self._fuzz_data(json) or {}

                for k, v in params.items():
                    params_copy = params.copy()
                    params_copy[k] = self._inject(v)
                    yield self._test_sqli(
                        method, path, params_copy, query, json, headers
                    )

                for k, v in headers.items():
                    headers_copy = headers.copy()
                    headers_copy[k] = self._inject(v)
                    yield self._test_sqli(
                        method, path, params, query, json, headers_copy
                    )

                for k, v in query.items():
                    query_copy = query.copy()
                    query_copy[k] = self._inject(v)
                    yield self._test_sqli(
                        method, path, json, query_copy, json, headers
                    )

                # может иметь вложенные поля, так неправильно проверять
                for k, v in json.items():
                    json_copy = json.copy()
                    json_copy[k] = self._inject(v)
                    yield self._test_sqli(
                        method, path, params, query, json_copy, headers
                    )

    def _fuzz_data(self, data: Any) -> Any:
        if isinstance(data, list):
            return {x['name']: self._fuzz_data(x) for x in data}
        if isinstance(data, dict):
            if 'example' in data:
                return data['example']
            schema = data.get('schema', data)
            if 'default' in schema:
                return schema['default']
            if 'enum' in schema:
                return random.choice(schema['enum'])
            match schema.get('type'):
                case 'object':
                    return {
                        k: self._fuzz_data(v)
                        for k, v in schema.get('properties', {}).items()
                    }
                case 'array':
                    # minLength?
                    return [self._fuzz_data(data['items'])]
                case 'integer' | 'number':
                    return random.randint(1, 100)
                case 'boolean':
                    return bool(random.randbytes(1))
                case 'string':
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
                        case _:
                            return random.choice(['foo', 'bar', 'baz', 'quix'])

    def _inject(self, val: Any) -> str:
        return f"{val}'\""

    async def _test_sqli(
        self,
        method: str,
        path: str,
        params: dict[str, Any],
        query: dict[str, Any],
        json: dict[str, Any],
        headers: dict[str, Any],
    ) -> None:
        try:
            url: str = (
                f'{self.server_url}{self._replace_path_params(path, params)}'
            )
            response = await self._request(
                method, url, query, json=json, headers=headers
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
                dumps(
                    dict(
                        method=method,
                        url=url,
                        query=query,
                        data=json,
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
