from __future__ import annotations

import asyncio
import functools
from io import TextIOWrapper
from typing import TYPE_CHECKING
from bbrain.iac.ovh.api.dedicated import (
    post_dedicated_server_install,
    post_dedicated_server_reboot,
    put_dedicated_server,
)
from bbrain.iac.ovh.api.ip import get_ip_task, get_ip_tasks, post_ip_move
from bbrain.iac.ovh.client import Client
from bbrain.iac.ovh.manifests import UnknownManifest, manifest_factory

if TYPE_CHECKING:
    from bbrain.iac.ovh.manifests.base import BaseManifest

import click
from ruamel.yaml import YAML


yaml = YAML()


def sync(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))

    return wrapper


@click.group()
def ovh():
    pass


@ovh.command()
@click.option("-f", "--file", required=True, type=click.File())
@click.option("-o", "--overwrite", is_flag=True, show_default=True, default=False)
@click.option("-p", "--purge", is_flag=True, show_default=True, default=False)
@sync
async def apply(file: TextIOWrapper, overwrite: bool, purge: bool):
    raw_manifest: dict = yaml.load(file)
    try:
        manifest: BaseManifest = manifest_factory(raw_manifest)
    except UnknownManifest:
        print("Please provide a valid manifest")
    else:
        async with Client() as client:
            await manifest(**raw_manifest).apply(
                client, overwrite=overwrite, purge=purge
            )


@ovh.command()
@click.option("-s", "--server", required=True)
@sync
async def bootstrap(server: str):
    # async with Client() as client:
    #     await put_dedicated_server(client, server, 46371)
    #     await post_dedicated_server_reboot(client, server)

    from paramiko import SSHClient, AutoAddPolicy

    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    ssh_client.connect(
        hostname=server,
        username="root",
        timeout=600,
    )


@ovh.command()
@click.option("-s", "--server", required=True)
@click.option("-t", "--template", required=False, default="ubuntu2204-server_64")
@click.option("-n", "--hostname", required=False)
@click.option("-i", "--identity", required=False)
@sync
async def install(server: str, template: str, hostname: str, identity: str):
    async with Client() as client:
        res = await post_dedicated_server_install(
            client,
            server,
            template=template,
            hostname=hostname,
            sshKeyName=identity,
        )
        print(res)


@ovh.command()
@click.option("-s", "--service", required=True)
@click.option("-i", "--ip", required=True)
@sync
async def move_ip(service: str, ip: str):
    async with Client() as client:
        # await post_ip_move(client, ip, service)
        print(await get_ip_tasks(client, ip))
