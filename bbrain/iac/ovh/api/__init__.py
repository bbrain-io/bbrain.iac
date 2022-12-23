import asyncio
from typing import Callable, Awaitable, Tuple


def wait_until(
    func: Callable[..., Awaitable],
    params: Tuple,
    expr: Callable[..., bool],
    timeout: int = 100,
    period: int = 2,
):
    """Run an asynchronous function until it succeeds.

    Args:
        func (Callable[..., Awaitable]): The function to run continuously
        params (Tuple): The parameters to pass to the function
        expr (Callable[..., bool]): An expression to determine if `func` succeeded.
            It should take a single parameter and return a bool.
            True to keep running, False to exit the loop.
        timeout (int, optional): The timeout in seconds. Defaults to 100.
        period (int, optional): How much time to wait between each iteration.
    """

    async def loop():
        while expr(await func(*params)):
            await asyncio.sleep(period)

    return asyncio.wait_for(loop(), timeout)
