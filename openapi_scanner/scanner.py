import asyncio
import logging
import random
import urllib.parse as urlparse
import uuid
from asyncio import Queue
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
        num_workers: int = 10,
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
        self._num_workers = num_workers

    @classmethod
    async def run(
        cls, schema_url: str, timeout: float = 60, **kwargs: dict[str, Any]
    ) -> None:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            await cls(schema_url=schema_url, session=session, **kwargs).scan()

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
        q = Queue()
        logger.info('scanning started')
        self._generate_tasks(q)
        logger.debug('queue size: %d', q.qsize())
        workers = [self._worker(q, i) for i in range(self._num_workers)]
        await asyncio.gather(*workers)
        await q.join()
        logger.info('scanning finished')

    async def _worker(self, q: Queue, index: int) -> None:
        logger.info('worker #%s started', index)
        while q.qsize():
            try:
                task = await q.get()
                logger.debug(task)
                await self._test_vuln(**task)
            except Exception as ex:
                logger.exception(ex)
            finally:
                q.task_done()
        logger.info('worker #%s finished', index)

    async def _test_vuln(
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

    def _generate_tasks(
        self,
        q: Queue,
    ) -> Iterable[
        Callable[
            [str, str, dict[str, Any], dict[str, Any], dict[str, Any]],
            Awaitable[None],
        ]
    ]:
        for path in self._api.get_paths():
            logger.debug(f'{path=}')
            for method in self._api.get_operations(path):
                params = self._api.get_path_parameters(path, method)
                query = self._api.get_query_parameters(path, method)
                headers = self._api.get_header_parameters(path, method)

                # Меня смущает, что в спецификации тело может быть одно, но на практике...
                # The POST, PUT and PATCH requests can have the request body (payload),
                # such as JSON or XML data. In Swagger terms, the request body is called a
                # body parameter. There can be only one body parameter, although the
                # operation may have other parameters (path, query, header). There can be
                # only one body parameter, although the operation may have other
                # parameters (path, query, header).
                json = None
                if method in ['patch', 'post', 'put']:
                    if isinstance(self._api, api.OpenApi):
                        json = self._api.get_request_body(
                            path, method, 'application/json'
                        )
                    else:
                        try:
                            # only one body
                            json = self._api.get_body_parameters(path, method)[
                                0
                            ]
                        except IndexError:
                            pass
                    # Лень обрабатывать formData
                    if not json:
                        logger.warning('%s: %s: no request body', path, method)
                        continue

                # Проверяем каждый параметр по очереди
                params = self._fuzz_data(params)
                headers = self._fuzz_data(headers)
                query = self._fuzz_data(query)
                json = self._fuzz_data(json) or {}

                for k, v in params.items():
                    params_copy = params.copy()
                    params_copy[k] = self._inject(v)
                    q.put_nowait(
                        {
                            'method': method,
                            'path': path,
                            'params': params_copy,
                            'query': query,
                            'json': json,
                            'headers': headers,
                        }
                    )

                for k, v in headers.items():
                    headers_copy = headers.copy()
                    headers_copy[k] = self._inject(v)
                    q.put_nowait(
                        {
                            'method': method,
                            'path': path,
                            'params': params,
                            'query': query,
                            'json': json,
                            'headers': headers_copy,
                        }
                    )

                for k, v in query.items():
                    query_copy = query.copy()
                    query_copy[k] = self._inject(v)
                    q.put_nowait(
                        {
                            'method': method,
                            'path': path,
                            'params': params,
                            'query': query_copy,
                            'json': json,
                            'headers': headers,
                        }
                    )

                # может иметь вложенные поля, так неправильно проверять
                for k, v in json.items():
                    json_copy = json.copy()
                    json_copy[k] = self._inject(v)
                    q.put_nowait(
                        {
                            'method': method,
                            'path': path,
                            'params': params,
                            'query': query,
                            'json': json_copy,
                            'headers': headers,
                        }
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

    def _replace_path_params(self, path: str, params: dict[str, Any]) -> str:
        for k, v in params.items():
            path = path.replace(f'{{{k}}}', urlparse.quote(str(v)))
        return path
