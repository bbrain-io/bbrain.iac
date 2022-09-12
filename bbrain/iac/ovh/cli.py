import asyncio
import functools
from io import TextIOWrapper

import click
from ruamel.yaml import YAML

from bbrain.iac.ovh import BaseManifest
from bbrain.iac.ovh.client import Client
from bbrain.iac.ovh.manifests import UnknownManifest, manifest_factory

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
@sync
async def apply(file: TextIOWrapper):
    raw_manifest: dict = yaml.load(file)
    print(raw_manifest)
    try:
        manifest: BaseManifest = manifest_factory(raw_manifest)
    except UnknownManifest:
        print("Please provide a valid manifest")
    else:
        async with Client() as client:
            await manifest(**raw_manifest).apply(client)
